package userperms

import (
	"context"
	"errors"
	"fmt"
	"time"

	clusterviewclientset "github.com/stolostron/cluster-lifecycle-api/client/clusterview/clientset/versioned"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// listTimeout bounds one hub List. The caller's context is detached first,
	// so a disconnected leader does not cancel the flight other waiters share.
	listTimeout = 10 * time.Second

	// pageSize is one UserPermissions page. Continue is followed until it is empty.
	pageSize = 500

	// Hub throttle on the shared base rest.Config. Each List copies that config.
	hubQPS   = 50
	hubBurst = 100

	userPermsUserAgent = "mcoa-gateway-userperms"
)

var (
	// errHubDenied is a 401 or 403 from the apiserver.
	errHubDenied = errors.New("hub denied userpermissions list")
	// errHubUnavailable is a timeout, a transport error, or any other list failure.
	errHubUnavailable = errors.New("hub userpermissions list failed")
)

// kubeLister lists as cred and returns every binding's cluster name.
// Any role, any scope. Binding.Cluster is the tenant id.
// base is the impersonation config. List copies it and never mutates it.
type kubeLister struct {
	base *rest.Config
}

func (k kubeLister) List(ctx context.Context, cred credential) (clusterSet, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), listTimeout)
	defer cancel()

	cfg := configFor(k.base, cred)
	cs, err := clusterviewclientset.NewForConfig(cfg)
	if err != nil {
		return clusterSet{}, fmt.Errorf("%w: %v", errHubUnavailable, err)
	}
	api := cs.ClusterviewV1alpha1().UserPermissions()

	var names []string
	var cont string
	for {
		list, err := api.List(ctx, metav1.ListOptions{Limit: pageSize, Continue: cont})
		if err != nil {
			if apierrors.IsUnauthorized(err) || apierrors.IsForbidden(err) {
				return clusterSet{}, fmt.Errorf("%w: %v", errHubDenied, err)
			}
			return clusterSet{}, fmt.Errorf("%w: %v", errHubUnavailable, err)
		}
		for i := range list.Items {
			for _, binding := range list.Items[i].Status.Bindings {
				if binding.Cluster == "" {
					continue
				}
				names = append(names, binding.Cluster)
			}
		}
		cont = list.Continue
		if cont == "" {
			break
		}
	}
	return newClusterSet(names), nil
}

// configFor copies base and binds the copy to cred. It never returns base.
//
// A bearer copy clears BearerTokenFile. If that file stays set, client-go
// refreshes it on each request and lists as the gateway service account.
func configFor(base *rest.Config, cred credential) *rest.Config {
	cfg := rest.CopyConfig(base)
	switch cred.kind {
	case credBearer:
		cfg.BearerToken = cred.token
		cfg.BearerTokenFile = ""
		cfg.Username = ""
		cfg.Password = ""
		cfg.CertFile = ""
		cfg.KeyFile = ""
		cfg.CertData = nil
		cfg.KeyData = nil
		cfg.AuthProvider = nil
		cfg.ExecProvider = nil
		cfg.Impersonate = rest.ImpersonationConfig{}
	case credImpersonate:
		cfg.Impersonate = rest.ImpersonationConfig{
			UserName: cred.user,
			Groups:   cloneGroups(cred.groups),
		}
	default:
		panic("userperms: credential has no kind")
	}
	return cfg
}

func cloneGroups(groups []string) []string {
	if len(groups) == 0 {
		return nil
	}
	out := make([]string, len(groups))
	copy(out, groups)
	return out
}

// loadHubConfig loads the impersonation base.
// An empty path uses rest.InClusterConfig. Otherwise path is a kubeconfig file.
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
	cfg.UserAgent = userPermsUserAgent
	cfg.Impersonate = rest.ImpersonationConfig{}
	return cfg, nil
}
