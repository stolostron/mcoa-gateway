package mcra

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	mcrav1beta1 "github.com/stolostron/multicluster-role-assignment/api/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clusterv1beta1 "open-cluster-management.io/api/cluster/v1beta1"
)

const (
	// listTimeout bounds one hub load. The caller's context is detached first,
	// so a disconnected caller does not cancel the load other waiters share.
	listTimeout = 10 * time.Second

	// pageSize is one list page. Continue is followed until it is empty.
	pageSize int64 = 500

	hubQPS   = 50
	hubBurst = 100

	hubUserAgent = "mcoa-gateway-mcra"
)

var (
	mcraGVR     = mcrav1beta1.GroupVersion.WithResource("multiclusterroleassignments")
	decisionGVR = schema.GroupVersionResource{
		Group:    clusterv1beta1.GroupName,
		Version:  clusterv1beta1.GroupVersion.Version,
		Resource: "placementdecisions",
	}

	// errHubDenied is a 401 or 403 from the apiserver.
	errHubDenied = errors.New("hub denied the multicluster role assignment list")
	// errHubUnavailable is a timeout, a transport error, or any other list failure.
	errHubUnavailable = errors.New("hub multicluster role assignment list failed")
)

// hubLoader lists MulticlusterRoleAssignment and PlacementDecision with the
// gateway's hub credentials. OpenShift cookie tokens are not hub tokens, and
// mTLS has a certificate subject and OU groups but no hub token.
type hubLoader struct {
	client dynamic.Interface
}

func newHubLoader(cfg *rest.Config) (hubLoader, error) {
	client, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return hubLoader{}, err
	}
	return hubLoader{client: client}, nil
}

func (h hubLoader) Load(ctx context.Context) (grantIndex, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), listTimeout)
	defer cancel()

	assignments, err := listTyped[mcrav1beta1.MulticlusterRoleAssignment](ctx, h.client, mcraGVR)
	if err != nil {
		return grantIndex{}, err
	}
	decisions, err := listTyped[clusterv1beta1.PlacementDecision](ctx, h.client, decisionGVR)
	if err != nil {
		return grantIndex{}, err
	}
	return grantIndexFrom(parsedAssignments(assignments), clustersByPlacement(decisions)), nil
}

func listTyped[T any](ctx context.Context, client dynamic.Interface, gvr schema.GroupVersionResource) ([]T, error) {
	var cont string
	var out []T
	for {
		page, err := client.Resource(gvr).List(ctx, metav1.ListOptions{Limit: pageSize, Continue: cont})
		if err != nil {
			return nil, hubErr(err)
		}
		items, err := decodeItems[T](page.Items)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
		cont = page.GetContinue()
		if cont == "" {
			return out, nil
		}
	}
}

func decodeItems[T any](items []unstructured.Unstructured) ([]T, error) {
	out := make([]T, 0, len(items))
	for i := range items {
		raw, err := items[i].MarshalJSON()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errHubUnavailable, err)
		}
		var item T
		if err := json.Unmarshal(raw, &item); err != nil {
			return nil, fmt.Errorf("%w: %v", errHubUnavailable, err)
		}
		out = append(out, item)
	}
	return out, nil
}

func hubErr(err error) error {
	if apierrors.IsUnauthorized(err) || apierrors.IsForbidden(err) {
		return fmt.Errorf("%w: %v", errHubDenied, err)
	}
	return fmt.Errorf("%w: %v", errHubUnavailable, err)
}

func parsedAssignments(items []mcrav1beta1.MulticlusterRoleAssignment) []parsedAssignment {
	out := make([]parsedAssignment, 0, len(items))
	for i := range items {
		var refs []placementRef
		for _, assignment := range items[i].Spec.RoleAssignments {
			if assignment.ClusterSelection.Type != clusterSelectionPlacements {
				continue
			}
			for _, placement := range assignment.ClusterSelection.Placements {
				if placement.Namespace == "" || placement.Name == "" {
					continue
				}
				refs = append(refs, placementRef{namespace: placement.Namespace, name: placement.Name})
			}
		}
		if len(refs) == 0 {
			continue
		}
		subject := items[i].Spec.Subject
		out = append(out, parsedAssignment{
			subject: subjectRef{
				kind:      subject.Kind,
				namespace: subject.Namespace,
				name:      subject.Name,
			},
			placements: refs,
		})
	}
	return out
}

func clustersByPlacement(items []clusterv1beta1.PlacementDecision) map[placementRef]clusterSet {
	names := map[placementRef][]string{}
	for i := range items {
		placementName := items[i].Labels[clusterv1beta1.PlacementLabel]
		if placementName == "" || items[i].Namespace == "" {
			continue
		}
		ref := placementRef{namespace: items[i].Namespace, name: placementName}
		for _, decision := range items[i].Status.Decisions {
			if decision.ClusterName == "" {
				continue
			}
			names[ref] = append(names[ref], decision.ClusterName)
		}
	}
	return setsByPlacement(names)
}

func setsByPlacement(in map[placementRef][]string) map[placementRef]clusterSet {
	out := make(map[placementRef]clusterSet, len(in))
	for ref, names := range in {
		set := newClusterSet(names)
		if set.len() == 0 {
			continue
		}
		out[ref] = set
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// loadHubConfig loads the gateway hub config.
// An empty path uses rest.InClusterConfig. Otherwise path is a kubeconfig file.
// Impersonation from the kubeconfig is cleared.
func loadHubConfig(path string) (*rest.Config, error) {
	var (
		cfg *rest.Config
		err error
	)
	if path == "" {
		cfg, err = rest.InClusterConfig()
	} else {
		cfg, err = clientcmd.BuildConfigFromFlags("", path)
	}
	if err != nil {
		return nil, err
	}
	cfg.QPS = hubQPS
	cfg.Burst = hubBurst
	cfg.UserAgent = hubUserAgent
	cfg.Impersonate = rest.ImpersonationConfig{}
	return cfg, nil
}
