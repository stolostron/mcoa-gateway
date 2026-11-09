package userperms

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

	clusterviewv1alpha1 "github.com/stolostron/cluster-lifecycle-api/clusterview/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/transport"
)

func TestConfigForBearerClearsGatewayCredentials(t *testing.T) {
	t.Parallel()

	base := gatewayBase("https://hub.example", "/var/run/sa-token")
	cfg := configFor(base, credential{kind: credBearer, token: "user-token"})
	if cfg == base {
		t.Fatal("configFor returned the base config")
	}
	if cfg.BearerToken != "user-token" || cfg.BearerTokenFile != "" {
		t.Fatalf("bearer config token=%q file=%q", cfg.BearerToken, cfg.BearerTokenFile)
	}
	if cfg.Username != "" || cfg.Password != "" || cfg.CertFile != "" || cfg.KeyFile != "" {
		t.Fatalf("basic auth or client certs survived: %#v", cfg)
	}
	if cfg.CertData != nil || cfg.KeyData != nil || cfg.AuthProvider != nil || cfg.ExecProvider != nil {
		t.Fatal("client identity from the base config survived on the bearer copy")
	}
	if cfg.Impersonate.UserName != "" || cfg.Impersonate.Groups != nil {
		t.Fatalf("impersonation survived on the bearer copy: %#v", cfg.Impersonate)
	}
	if base.BearerTokenFile != "/var/run/sa-token" || base.Username != "basic-user" || string(base.CertData) != "cert" {
		t.Fatal("configFor mutated the base config")
	}
	if base.AuthProvider == nil || base.AuthProvider.Name != "oidc" || base.ExecProvider == nil {
		t.Fatal("configFor cleared credentials on the base config")
	}
}

func TestConfigForImpersonateKeepsServiceAccount(t *testing.T) {
	t.Parallel()

	base := gatewayBase("https://hub.example", "/var/run/sa-token")
	groups := []string{"b", "a"}
	cfg := configFor(base, credential{
		kind:   credImpersonate,
		token:  "should-not-send",
		user:   "alice",
		groups: groups,
	})
	if cfg == base {
		t.Fatal("configFor returned the base config")
	}
	if cfg.BearerToken != base.BearerToken || cfg.BearerTokenFile != base.BearerTokenFile {
		t.Fatalf("impersonation config token=%q file=%q", cfg.BearerToken, cfg.BearerTokenFile)
	}
	if cfg.Impersonate.UserName != "alice" || !slices.Equal(cfg.Impersonate.Groups, groups) {
		t.Fatalf("impersonation = %#v", cfg.Impersonate)
	}
	cfg.Impersonate.Groups[0] = "changed"
	if groups[0] != "b" {
		t.Fatal("impersonation groups alias the credential slice")
	}
	if base.Impersonate.UserName != "gateway-sa" {
		t.Fatal("configFor mutated base impersonation")
	}

	empty := configFor(base, credential{kind: credImpersonate, user: "alice"})
	if empty.Impersonate.Groups != nil {
		t.Fatalf("empty groups = %#v, want nil", empty.Impersonate.Groups)
	}
}

func TestConfigForRejectsZeroCredential(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Fatal("zero credential did not panic")
		}
	}()
	configFor(gatewayBase("https://hub.example", "tok"), credential{})
}

func TestKubeListerBearerSendsSubjectToken(t *testing.T) {
	t.Parallel()

	tokenFile := writeTokenFile(t, "sa-token\n")
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		writePermissionList(w, "", permission("view", binding("cluster-a", clusterviewv1alpha1.BindingScopeCluster)))
	}))
	t.Cleanup(srv.Close)

	base := gatewayBase(srv.URL, tokenFile)
	set, err := (kubeLister{base: base}).List(context.Background(), credential{kind: credBearer, token: "user-token"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got.Get("Authorization") != "Bearer user-token" {
		t.Fatalf("Authorization = %q, want the subject token", got.Get("Authorization"))
	}
	if got.Get(transport.ImpersonateUserHeader) != "" {
		t.Fatalf("bearer request impersonated %q", got.Get(transport.ImpersonateUserHeader))
	}
	if !set.has("cluster-a") || set.len() != 1 {
		t.Fatalf("set = %#v", set.names)
	}
	if base.BearerTokenFile != tokenFile {
		t.Fatal("List mutated the base token file")
	}
}

func TestKubeListerImpersonatesSubject(t *testing.T) {
	t.Parallel()

	tokenFile := writeTokenFile(t, "sa-token\n")
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		writePermissionList(w, "", permission("view", binding("cluster-a", clusterviewv1alpha1.BindingScopeNamespace)))
	}))
	t.Cleanup(srv.Close)

	base := &rest.Config{
		Host:            srv.URL,
		BearerToken:     "config-token",
		BearerTokenFile: tokenFile,
	}
	_, err := (kubeLister{base: base}).List(context.Background(), credential{
		kind:   credImpersonate,
		token:  "should-not-send",
		user:   "alice",
		groups: []string{"g-b", "g-a"},
	})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got.Get("Authorization") != "Bearer sa-token" {
		t.Fatalf("Authorization = %q, want the service account token", got.Get("Authorization"))
	}
	if got.Get(transport.ImpersonateUserHeader) != "alice" {
		t.Fatalf("Impersonate-User = %q", got.Get(transport.ImpersonateUserHeader))
	}
	if !slices.Equal(got.Values(transport.ImpersonateGroupHeader), []string{"g-b", "g-a"}) {
		t.Fatalf("groups = %#v", got.Values(transport.ImpersonateGroupHeader))
	}
}

func TestKubeListerFollowsContinue(t *testing.T) {
	t.Parallel()

	var (
		mu    sync.Mutex
		calls []string
		paths []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.URL.Query().Get("continue"))
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if r.URL.Query().Get("limit") != "500" {
			http.Error(w, "limit", http.StatusBadRequest)
			return
		}
		switch r.URL.Query().Get("continue") {
		case "":
			writePermissionList(w, "page-2", permission("view",
				binding("cluster-a", clusterviewv1alpha1.BindingScopeCluster),
				binding("", clusterviewv1alpha1.BindingScopeNamespace),
				binding("cluster-b", clusterviewv1alpha1.BindingScopeNamespace),
			))
		case "page-2":
			writePermissionList(w, "", permission("admin",
				binding("cluster-a", clusterviewv1alpha1.BindingScopeCluster),
				binding("cluster-c", clusterviewv1alpha1.BindingScopeCluster),
				binding("*", clusterviewv1alpha1.BindingScopeCluster),
			))
		default:
			http.Error(w, "continue", http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)

	set, err := (kubeLister{base: &rest.Config{Host: srv.URL, BearerToken: "user-token"}}).List(
		context.Background(),
		credential{kind: credBearer, token: "user-token"},
	)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if !slices.Equal(calls, []string{"", "page-2"}) {
		t.Fatalf("continue tokens = %#v", calls)
	}
	for _, path := range paths {
		if !strings.HasSuffix(path, "/userpermissions") {
			t.Fatalf("path = %s", path)
		}
	}
	want := []string{"*", "cluster-a", "cluster-b", "cluster-c"}
	if !slices.Equal(set.names, want) {
		t.Fatalf("clusters = %#v, want %#v", set.names, want)
	}
}

func TestKubeListerHubDenied(t *testing.T) {
	t.Parallel()

	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeStatus(w, code)
			}))
			t.Cleanup(srv.Close)
			set, err := (kubeLister{base: &rest.Config{Host: srv.URL}}).List(
				context.Background(),
				credential{kind: credBearer, token: "user-token"},
			)
			if !errors.Is(err, errHubDenied) {
				t.Fatalf("err = %v, want hub denied", err)
			}
			if errors.Is(err, errHubUnavailable) {
				t.Fatal("denied list reported unavailable")
			}
			if set.len() != 0 {
				t.Fatalf("denied list returned %#v", set.names)
			}
		})
	}
}

func TestKubeListerHubUnavailable(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()
	_, err := (kubeLister{base: &rest.Config{Host: srv.URL, BearerToken: "user-token"}}).List(
		context.Background(),
		credential{kind: credBearer, token: "user-token"},
	)
	if !errors.Is(err, errHubUnavailable) {
		t.Fatalf("err = %v, want hub unavailable", err)
	}
	if errors.Is(err, errHubDenied) {
		t.Fatal("transport failure reported as hub denied")
	}
}

func TestKubeListerIgnoresCallerCancel(t *testing.T) {
	t.Parallel()

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(entered) })
		<-release
		writePermissionList(w, "", permission("view", binding("cluster-a", clusterviewv1alpha1.BindingScopeCluster)))
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := (kubeLister{base: &rest.Config{Host: srv.URL, BearerToken: "user-token"}}).List(
			ctx,
			credential{kind: credBearer, token: "user-token"},
		)
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("list did not reach the hub")
	}
	cancel()
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("cancelled caller failed the list: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("list did not finish after the caller cancelled")
	}
}

func TestLoadHubConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	tokenFile := writeTokenFile(t, "sa-token\n")
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
    tokenFile: ` + tokenFile + `
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
		t.Fatalf("kubeconfig: %v", err)
	}
	if raw.Impersonate.UserName != "somebody" || !slices.Equal(raw.Impersonate.Groups, []string{"group-a"}) {
		t.Fatalf("kubeconfig impersonation = %#v", raw.Impersonate)
	}
	cfg, err := loadHubConfig(path)
	if err != nil {
		t.Fatalf("loadHubConfig: %v", err)
	}
	if cfg.Host != "https://hub.example" {
		t.Fatalf("host = %q", cfg.Host)
	}
	if cfg.BearerTokenFile != tokenFile {
		t.Fatalf("token file = %q", cfg.BearerTokenFile)
	}
	if cfg.QPS != hubQPS || cfg.Burst != hubBurst || cfg.UserAgent != userPermsUserAgent {
		t.Fatalf("qps=%v burst=%d agent=%q", cfg.QPS, cfg.Burst, cfg.UserAgent)
	}
	if cfg.Impersonate.UserName != "" || cfg.Impersonate.Groups != nil {
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

func gatewayBase(host, tokenFile string) *rest.Config {
	return &rest.Config{
		Host:            host,
		BearerToken:     "config-token",
		BearerTokenFile: tokenFile,
		Username:        "basic-user",
		Password:        "basic-pass",
		TLSClientConfig: rest.TLSClientConfig{
			CertFile: "missing.crt",
			KeyFile:  "missing.key",
			CertData: []byte("cert"),
			KeyData:  []byte("key"),
		},
		AuthProvider: &clientcmdapi.AuthProviderConfig{Name: "oidc"},
		ExecProvider: &clientcmdapi.ExecConfig{Command: "echo"},
		Impersonate: rest.ImpersonationConfig{
			UserName: "gateway-sa",
			Groups:   []string{"system:serviceaccounts"},
		},
	}
}

func writeTokenFile(t *testing.T, token string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func permission(name string, bindings ...clusterviewv1alpha1.ClusterBinding) clusterviewv1alpha1.UserPermission {
	return clusterviewv1alpha1.UserPermission{
		TypeMeta: metav1.TypeMeta{
			Kind:       "UserPermission",
			APIVersion: clusterviewv1alpha1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status:     clusterviewv1alpha1.UserPermissionStatus{Bindings: bindings},
	}
}

func binding(cluster string, scope clusterviewv1alpha1.BindingScope) clusterviewv1alpha1.ClusterBinding {
	return clusterviewv1alpha1.ClusterBinding{
		Cluster:    cluster,
		Scope:      scope,
		Namespaces: []string{"ns"},
	}
}

func writePermissionList(w http.ResponseWriter, cont string, items ...clusterviewv1alpha1.UserPermission) {
	list := clusterviewv1alpha1.UserPermissionList{
		TypeMeta: metav1.TypeMeta{
			Kind:       "UserPermissionList",
			APIVersion: clusterviewv1alpha1.SchemeGroupVersion.String(),
		},
		ListMeta: metav1.ListMeta{Continue: cont},
		Items:    items,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(&list)
}

func writeStatus(w http.ResponseWriter, code int) {
	reason := metav1.StatusReasonUnknown
	switch code {
	case http.StatusUnauthorized:
		reason = metav1.StatusReasonUnauthorized
	case http.StatusForbidden:
		reason = metav1.StatusReasonForbidden
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
