package authentication

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-kit/log"
	"k8s.io/apiserver/pkg/authentication/authenticator"
)

func TestWithDefaultTenantMiddlewares(t *testing.T) {
	t.Parallel()

	pm := NewProviderManager(log.NewNopLogger(), nil)
	mw := WithDefaultTenantMiddlewares(pm)

	rec := httptest.NewRecorder()
	called := false
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})).ServeHTTP(rec, req)
	if called || rec.Code != http.StatusUnauthorized {
		t.Fatalf("unregistered called=%t status=%d body=%s", called, rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "default tenant authenticator is not registered") {
		t.Fatalf("body = %s", rec.Body.String())
	}

	pm.middlewares[DefaultTenantName] = func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := GetTenant(r.Context()); ok {
				t.Fatal("default authenticator saw a client tenant")
			}
			next.ServeHTTP(w, r)
		})
	}
	rec = httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("registered status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestWithDefaultTenantMiddlewaresRejectsNil(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Fatal("nil provider manager did not panic")
		}
	}()
	WithDefaultTenantMiddlewares(nil)
}

func TestProviderLoginPath(t *testing.T) {
	t.Parallel()

	if got := providerLoginPath("openshift", "prod.cluster"); got != "/openshift/prod.cluster/login" {
		t.Fatalf("path = %q", got)
	}
	if got := providerLoginPath("oidc", DefaultTenantName); got != "/oidc/__mcoa_default__/login" {
		t.Fatalf("path = %q", got)
	}

	defer func() {
		if recover() == nil {
			t.Fatal("empty provider tenant did not panic")
		}
	}()
	providerLoginPath("oidc", "")
}

type denyRequestAuth struct{}

func (denyRequestAuth) AuthenticateRequest(*http.Request) (*authenticator.Response, bool, error) {
	return nil, false, nil
}

func TestOpenShiftCookieMissUsesRegisteredTenant(t *testing.T) {
	t.Parallel()

	a := OpenShiftAuthenticator{
		tenant:        "prod.cluster",
		logger:        log.NewNopLogger(),
		authenticator: denyRequestAuth{},
		cookieName:    "mcoa",
		oauthEnabled:  true,
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/my%20query", nil)
	req = req.WithContext(context.WithValue(req.Context(), tenantKey, "evil"))
	rec := httptest.NewRecorder()
	a.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("cookie miss called next")
	})).ServeHTTP(rec, req)

	const want = "/openshift/prod.cluster/login?route=%2Fapi%2Fv1%2Fmy+query"
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != want {
		t.Fatalf("status=%d location=%q body=%s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "failed to find token") {
		t.Fatalf("body = %s", rec.Body.String())
	}
}

func TestOIDCCookieMissUsesRegisteredTenant(t *testing.T) {
	t.Parallel()

	a := oidcAuthenticator{
		tenant:     "prod.cluster",
		logger:     log.NewNopLogger(),
		cookieName: "sid",
	}
	req := httptest.NewRequest(http.MethodGet, "/api/logs/v1/query", nil)
	req = req.WithContext(context.WithValue(req.Context(), tenantKey, "evil"))
	rec := httptest.NewRecorder()
	a.Middleware()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("cookie miss called next")
	})).ServeHTTP(rec, req)

	const want = "/oidc/prod.cluster/login"
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != want {
		t.Fatalf("status=%d location=%q body=%s", rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
}

func TestPatternHandlerUsesURLTenant(t *testing.T) {
	t.Parallel()

	pm := NewProviderManager(log.NewNopLogger(), nil)
	const pattern = "/openshift/{tenant}"
	var got string
	pm.patternHandlers[pattern] = tenantHandlers{
		"prod.cluster": http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = chi.URLParam(r, "tenant")
			w.WriteHeader(http.StatusNoContent)
		}),
	}
	r := chi.NewRouter()
	r.Mount(pattern, pm.PatternHandler(pattern))

	req := httptest.NewRequest(http.MethodGet, "/openshift/prod.cluster/login", nil)
	req = req.WithContext(context.WithValue(req.Context(), tenantKey, "evil"))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || got != "prod.cluster" {
		t.Fatalf("status=%d tenant=%q body=%s", rec.Code, got, rec.Body.String())
	}

	unknown := httptest.NewRequest(http.MethodGet, "/openshift/missing/login", nil)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, unknown)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "error finding tenant") {
		t.Fatalf("unknown status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	pm.PatternHandler(pattern)(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "error finding tenant") {
		t.Fatalf("direct status=%d body=%s", rec.Code, rec.Body.String())
	}
}
