package mcra

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-kit/log"
	mcrav1beta1 "github.com/stolostron/multicluster-role-assignment/api/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/transport"
	clusterv1beta1 "open-cluster-management.io/api/cluster/v1beta1"
)

func TestHubList(t *testing.T) {
	t.Run("union", func(t *testing.T) {
		var rec hubLog
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !hubIdentity(t, w, r) {
				return
			}
			cont := r.URL.Query().Get("continue")
			rec.add(r.URL.Path, cont)
			switch {
			case strings.HasSuffix(r.URL.Path, "/multiclusterroleassignments"):
				writeMCRAPage(w, cont)
			case strings.HasSuffix(r.URL.Path, "/placementdecisions"):
				writeDecisionPage(w, cont)
			default:
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(srv.Close)

		path := writeHubKubeconfig(t, srv.URL)
		cfg, err := loadHubConfig(path)
		if err != nil {
			t.Fatal(err)
		}
		hub, err := newHubLoader(cfg)
		if err != nil {
			t.Fatal(err)
		}
		idx, err := hub.Load(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		assertClusters(t, idx, "alice", nil, "cluster-a", "cluster-b", "cluster-c")
		assertClusters(t, idx, "alice", []string{"sre"}, "cluster-a", "cluster-b", "cluster-c", "cluster-z")
		assertClusters(t, idx, "bob", nil)
		assertClusters(t, idx, "someone", []string{"sre"}, "cluster-z")
		assertClusters(t, idx, "system:serviceaccount:team:bot", nil, "cluster-a", "cluster-b")
		assertClusters(t, idx, "system:serviceaccount:other:bot", nil, "cluster-z")
		assertClusters(t, idx, "carol", []string{"system:serviceaccounts"})
		got := idx.clusters("alice", nil)
		for _, absent := range []string{"", "applied-only", "kube-system", "cluster-nope", "cluster-hidden", "cluster-unlabeled"} {
			if got.has(absent) {
				t.Fatalf("alice clusters = %#v, contains %q", got.names, absent)
			}
		}
		if !slices.Equal(rec.continues("/multiclusterroleassignments"), []string{"", "mcra-2"}) {
			t.Fatalf("mcra continues = %#v", rec.continues("/multiclusterroleassignments"))
		}
		if !slices.Equal(rec.continues("/placementdecisions"), []string{"", "pd-2"}) {
			t.Fatalf("decision continues = %#v", rec.continues("/placementdecisions"))
		}

		before := rec.len()
		long := NewMiddleware(Options{Kubeconfig: path, TTL: time.Hour, Logger: log.NewNopLogger()})
		alice := runMiddleware(t, long, "user-token", "THANOS-TENANT", "cluster-c|cluster-a|cluster-nope", "alice", nil)
		if alice.code != http.StatusNoContent || alice.tenant != "cluster-c|cluster-a" {
			t.Fatalf("alice = %+v", alice)
		}
		if rec.len() != before+4 {
			t.Fatalf("middleware loads = %d, want 4 more", rec.len()-before)
		}
		shared := NewMiddleware(Options{Kubeconfig: path, TTL: time.Hour, Logger: log.NewNopLogger()})
		group := runMiddleware(t, shared, "user-token", "THANOS-TENANT", "cluster-z|cluster-a", "someone", []string{"sre"})
		if group.code != http.StatusNoContent || group.tenant != "cluster-z" || rec.len() != before+4 {
			t.Fatalf("shared tenant=%q calls=%d body=%s", group.tenant, rec.len()-before, group.errMsg)
		}
		short := NewMiddleware(Options{Kubeconfig: path, TTL: time.Nanosecond, Logger: log.NewNopLogger()})
		again := runMiddleware(t, short, "user-token", "THANOS-TENANT", "cluster-a", "alice", nil)
		if again.tenant != "cluster-a" || rec.len() != before+8 {
			t.Fatalf("short tenant=%q calls=%d", again.tenant, rec.len()-before)
		}
		held := runMiddleware(t, long, "user-token", "THANOS-TENANT", "cluster-a", "alice", nil)
		if held.tenant != "cluster-a" || rec.len() != before+8 {
			t.Fatalf("long snapshot was dropped, calls=%d tenant=%q", rec.len()-before, held.tenant)
		}
	})

	t.Run("denied", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			code int
			path string
		}{
			{name: "forbidden decision list", code: http.StatusForbidden, path: "/placementdecisions"},
			{name: "unauthorized assignment list", code: http.StatusUnauthorized, path: "/multiclusterroleassignments"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.Contains(r.URL.Path, tc.path) {
						writeStatus(w, tc.code)
						return
					}
					writeEmptyList(w, r)
				}))
				t.Cleanup(srv.Close)
				_, err := loadFromServer(t, srv.URL, context.Background())
				if !errors.Is(err, errHubDenied) {
					t.Fatalf("err = %v, want hub denied", err)
				}
				if errors.Is(err, errHubUnavailable) {
					t.Fatal("denied list reported unavailable")
				}
			})
		}
	})

	t.Run("unavailable", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeStatus(w, http.StatusInternalServerError)
		}))
		t.Cleanup(srv.Close)
		_, err := loadFromServer(t, srv.URL, context.Background())
		if !errors.Is(err, errHubUnavailable) {
			t.Fatalf("err = %v, want hub unavailable", err)
		}
		if errors.Is(err, errHubDenied) {
			t.Fatal("server error reported as hub denied")
		}
	})

	t.Run("caller cancel", func(t *testing.T) {
		entered := make(chan struct{})
		release := make(chan struct{})
		var once sync.Once
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			once.Do(func() { close(entered) })
			<-release
			if strings.HasSuffix(r.URL.Path, "/multiclusterroleassignments") {
				writeMCRA(w, "", mcraSubject(
					mcrav1beta1.Subject{Kind: subjectKindUser, Name: "alice"},
					roleAssignment("view", clusterSelectionPlacements, place("sets", "app")),
				))
				return
			}
			writeDecisions(w, "", decision("sets", "app", "d", "cluster-a"))
		}))
		t.Cleanup(srv.Close)

		path := writeHubKubeconfig(t, srv.URL)
		cfg, err := loadHubConfig(path)
		if err != nil {
			t.Fatal(err)
		}
		hub, err := newHubLoader(cfg)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan loadResult, 1)
		go func() {
			idx, err := hub.Load(ctx)
			done <- loadResult{idx: idx, err: err}
		}()
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("list did not reach the hub")
		}
		cancel()
		close(release)
		select {
		case got := <-done:
			if got.err != nil {
				t.Fatalf("cancelled caller failed the list: %v", got.err)
			}
			assertClusters(t, got.idx, "alice", nil, "cluster-a")
		case <-time.After(5 * time.Second):
			t.Fatal("list did not finish after the caller cancelled")
		}
	})
}

func TestLoadHubConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "kubeconfig")
	body := []byte(`apiVersion: v1
kind: Config
clusters:
- name: hub
  cluster:
    server: https://hub.example
users:
- name: sa
  user:
    token: gateway-token
    as: somebody
    as-groups:
    - group-a
contexts:
- name: ctx
  context:
    cluster: hub
    user: sa
current-context: ctx
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		t.Fatal(err)
	}
	if raw.Impersonate.UserName != "somebody" || !slices.Equal(raw.Impersonate.Groups, []string{"group-a"}) {
		t.Fatalf("kubeconfig impersonation = %#v", raw.Impersonate)
	}
	cfg, err := loadHubConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "https://hub.example" || cfg.BearerToken != "gateway-token" {
		t.Fatalf("host=%q token=%q", cfg.Host, cfg.BearerToken)
	}
	if cfg.QPS != hubQPS || cfg.Burst != hubBurst || cfg.UserAgent != hubUserAgent {
		t.Fatalf("qps=%v burst=%d agent=%q", cfg.QPS, cfg.Burst, cfg.UserAgent)
	}
	if cfg.Impersonate.UserName != "" || cfg.Impersonate.UID != "" || len(cfg.Impersonate.Groups) != 0 || len(cfg.Impersonate.Extra) != 0 {
		t.Fatalf("impersonation = %#v", cfg.Impersonate)
	}
	if _, err := loadHubConfig(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing kubeconfig returned a config")
	}
	if os.Getenv("KUBERNETES_SERVICE_HOST") == "" {
		if _, err := loadHubConfig(""); err == nil {
			t.Fatal("empty path returned a config outside a cluster")
		}
	}
}

type loadResult struct {
	idx grantIndex
	err error
}

type hubLog struct {
	mu   sync.Mutex
	hits []hubHit
}

type hubHit struct {
	path string
	cont string
}

func (l *hubLog) add(path, cont string) {
	l.mu.Lock()
	l.hits = append(l.hits, hubHit{path: path, cont: cont})
	l.mu.Unlock()
}

func (l *hubLog) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.hits)
}

func (l *hubLog) continues(resource string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, hit := range l.hits {
		if strings.Contains(hit.path, resource) {
			out = append(out, hit.cont)
		}
	}
	return out
}

func hubIdentity(t *testing.T, w http.ResponseWriter, r *http.Request) bool {
	t.Helper()
	if strings.Contains(r.URL.Path, "/namespaces/") {
		http.Error(w, "namespaced list", http.StatusBadRequest)
		return false
	}
	if r.Header.Get("Authorization") != "Bearer gateway-token" {
		t.Logf("auth=%q ua=%q path=%s", r.Header.Get("Authorization"), r.Header.Get("User-Agent"), r.URL.RequestURI())
		http.Error(w, "auth", http.StatusUnauthorized)
		return false
	}
	if r.Header.Get(transport.ImpersonateUserHeader) != "" || len(r.Header.Values(transport.ImpersonateGroupHeader)) > 0 {
		http.Error(w, "impersonate", http.StatusBadRequest)
		return false
	}
	if r.URL.Query().Get("limit") != "500" {
		http.Error(w, "limit", http.StatusBadRequest)
		return false
	}
	if r.Header.Get("User-Agent") != hubUserAgent {
		http.Error(w, "user agent", http.StatusBadRequest)
		return false
	}
	return true
}

func loadFromServer(t *testing.T, server string, ctx context.Context) (grantIndex, error) {
	t.Helper()
	cfg, err := loadHubConfig(writeHubKubeconfig(t, server))
	if err != nil {
		t.Fatal(err)
	}
	hub, err := newHubLoader(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return hub.Load(ctx)
}

func writeHubKubeconfig(t *testing.T, server string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kubeconfig")
	body := []byte(`apiVersion: v1
kind: Config
clusters:
- name: hub
  cluster:
    server: ` + server + `
    insecure-skip-tls-verify: true
users:
- name: sa
  user:
    token: gateway-token
    as: somebody
contexts:
- name: ctx
  context:
    cluster: hub
    user: sa
current-context: ctx
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeMCRAPage(w http.ResponseWriter, cont string) {
	switch cont {
	case "":
		writeMCRA(w, "mcra-2",
			mcrav1beta1.MulticlusterRoleAssignment{
				ObjectMeta: metav1.ObjectMeta{Namespace: "assignments", Name: "alice-view"},
				Spec: mcrav1beta1.MulticlusterRoleAssignmentSpec{
					Subject: mcrav1beta1.Subject{Kind: subjectKindUser, Name: "alice"},
					RoleAssignments: []mcrav1beta1.RoleAssignment{
						{
							Name:             "view",
							ClusterRole:      "view",
							TargetNamespaces: []string{"kube-system"},
							ClusterSelection: mcrav1beta1.ClusterSelection{
								Type:       clusterSelectionPlacements,
								Placements: []mcrav1beta1.PlacementRef{place("sets", "app")},
							},
						},
						roleAssignment("edit", "manual", place("sets", "hidden")),
					},
				},
				Status: mcrav1beta1.MulticlusterRoleAssignmentStatus{AppliedClusters: []string{"applied-only"}},
			},
			mcraSubject(mcrav1beta1.Subject{Kind: subjectKindGroup, Name: "sre"},
				roleAssignment("view", clusterSelectionPlacements, place("sets", "plat")),
			),
			mcraSubject(mcrav1beta1.Subject{Kind: subjectKindUser, Name: "bob"},
				roleAssignment("view", clusterSelectionPlacements, place("sets", "missing")),
			),
			mcraSubject(mcrav1beta1.Subject{Kind: "Robot", Name: "alice"},
				roleAssignment("view", clusterSelectionPlacements, place("sets", "plat")),
			),
		)
	case "mcra-2":
		writeMCRA(w, "",
			mcraSubject(mcrav1beta1.Subject{Kind: subjectKindUser, Name: "alice"},
				roleAssignment("admin", clusterSelectionPlacements, place("other", "extra")),
			),
			mcraSubject(mcrav1beta1.Subject{Kind: subjectKindServiceAccount, Namespace: "team", Name: "bot"},
				roleAssignment("view", clusterSelectionPlacements, place("sets", "app")),
			),
			mcraSubject(mcrav1beta1.Subject{Kind: subjectKindServiceAccount, Namespace: "other", Name: "bot"},
				roleAssignment("view", clusterSelectionPlacements, place("sets", "plat")),
			),
		)
	default:
		http.Error(w, "continue", http.StatusBadRequest)
	}
}

func writeDecisionPage(w http.ResponseWriter, cont string) {
	switch cont {
	case "":
		writeDecisions(w, "pd-2",
			decision("sets", "app", "app-1", "", "cluster-a", "cluster-b"),
			decision("sets", "plat", "plat-1", "cluster-z"),
		)
	case "pd-2":
		writeDecisions(w, "",
			decision("other", "extra", "extra-1", "cluster-b", "cluster-c"),
			decision("elsewhere", "app", "else-1", "cluster-nope"),
			decision("sets", "hidden", "hidden-1", "cluster-hidden"),
			decision("sets", "", "unlabeled", "cluster-unlabeled"),
		)
	default:
		http.Error(w, "continue", http.StatusBadRequest)
	}
}

func decision(namespace, placement, name string, clusters ...string) clusterv1beta1.PlacementDecision {
	items := make([]clusterv1beta1.ClusterDecision, 0, len(clusters))
	for _, cluster := range clusters {
		items = append(items, clusterv1beta1.ClusterDecision{ClusterName: cluster, Reason: "Selected"})
	}
	labels := map[string]string{}
	if placement != "" {
		labels[clusterv1beta1.PlacementLabel] = placement
	}
	return clusterv1beta1.PlacementDecision{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, Labels: labels},
		Status:     clusterv1beta1.PlacementDecisionStatus{Decisions: items},
	}
}

func writeMCRA(w http.ResponseWriter, cont string, items ...mcrav1beta1.MulticlusterRoleAssignment) {
	if items == nil {
		items = []mcrav1beta1.MulticlusterRoleAssignment{}
	}
	writeJSON(w, mcrav1beta1.MulticlusterRoleAssignmentList{
		TypeMeta: metav1.TypeMeta{
			Kind:       "MulticlusterRoleAssignmentList",
			APIVersion: mcrav1beta1.GroupVersion.String(),
		},
		ListMeta: metav1.ListMeta{Continue: cont},
		Items:    items,
	})
}

func writeDecisions(w http.ResponseWriter, cont string, items ...clusterv1beta1.PlacementDecision) {
	if items == nil {
		items = []clusterv1beta1.PlacementDecision{}
	}
	writeJSON(w, clusterv1beta1.PlacementDecisionList{
		TypeMeta: metav1.TypeMeta{
			Kind:       "PlacementDecisionList",
			APIVersion: clusterv1beta1.GroupVersion.String(),
		},
		ListMeta: metav1.ListMeta{Continue: cont},
		Items:    items,
	})
}

func writeEmptyList(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/placementdecisions") {
		writeDecisions(w, "")
		return
	}
	writeMCRA(w, "")
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeStatus(w http.ResponseWriter, code int) {
	reason := metav1.StatusReasonUnknown
	switch code {
	case http.StatusUnauthorized:
		reason = metav1.StatusReasonUnauthorized
	case http.StatusForbidden:
		reason = metav1.StatusReasonForbidden
	case http.StatusInternalServerError:
		reason = metav1.StatusReasonInternalError
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(&metav1.Status{
		TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"},
		Status:   metav1.StatusFailure,
		Message:  http.StatusText(code),
		Reason:   reason,
		Code:     int32(code),
	})
}
