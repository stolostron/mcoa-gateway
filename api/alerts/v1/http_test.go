package v1

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stolostron/mcoa-gateway/authentication"
)

const testTenantHeader = "X-Test-Tenant"

func seedTenant(next http.Handler) http.Handler {
	// Seed context the same way write-path mTLS extraction does, without needing TLS.
	return authentication.WithTenantFromHeader(testTenantHeader)(next)
}

func requestWithTenant(method, path, tenant string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set(testTenantHeader, tenant)
	return req
}

func TestWithTenantHeaderMapsNameToID(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Scope-OrgID"); got != "tenant-uuid" {
			t.Fatalf("header = %q, want tenant-uuid", got)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	var cfg handlerConfiguration
	WithTenantHeader("X-Scope-OrgID", map[string]string{"test-oidc": "tenant-uuid"})(&cfg)
	if len(cfg.writeMiddlewares) != 1 {
		t.Fatalf("expected 1 middleware, got %d", len(cfg.writeMiddlewares))
	}

	rr := httptest.NewRecorder()
	seedTenant(cfg.writeMiddlewares[0](next)).ServeHTTP(rr, requestWithTenant(http.MethodPost, "/api/v2/alerts", "test-oidc"))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusNoContent, rr.Body.String())
	}
}

func TestWithTenantHeaderFallsBackToTenantName(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Scope-OrgID"); got != "unknown-tenant" {
			t.Fatalf("header = %q, want unknown-tenant", got)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	var cfg handlerConfiguration
	WithTenantHeader("X-Scope-OrgID", map[string]string{"test-oidc": "tenant-uuid"})(&cfg)

	rr := httptest.NewRecorder()
	seedTenant(cfg.writeMiddlewares[0](next)).ServeHTTP(rr, requestWithTenant(http.MethodPost, "/api/v2/alerts", "unknown-tenant"))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusNoContent, rr.Body.String())
	}
}

func TestWithTenantHeaderRequiresTenant(t *testing.T) {
	var cfg handlerConfiguration
	WithTenantHeader("X-Scope-OrgID", nil)(&cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/v2/alerts", nil)
	rr := httptest.NewRecorder()
	cfg.writeMiddlewares[0](http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next should not be called")
	})).ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestWithAccessorTokenSetsBearer(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer secret-token" {
			t.Fatalf("Authorization = %q, want Bearer secret-token", got)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	var cfg handlerConfiguration
	WithAccessorToken("secret-token")(&cfg)
	if len(cfg.writeMiddlewares) != 1 {
		t.Fatalf("expected 1 middleware, got %d", len(cfg.writeMiddlewares))
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v2/alerts", nil)
	rr := httptest.NewRecorder()
	cfg.writeMiddlewares[0](next).ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusNoContent)
	}
}

func TestWithAccessorTokenNoopWhenEmpty(t *testing.T) {
	var cfg handlerConfiguration
	WithAccessorToken("")(&cfg)
	if len(cfg.writeMiddlewares) != 0 {
		t.Fatalf("expected no middleware for empty token, got %d", len(cfg.writeMiddlewares))
	}
}

func TestNewHandlerFansOutWithTenantAndToken(t *testing.T) {
	var gotAuth, gotTenant string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotTenant = r.Header.Get("X-Scope-OrgID")
		if r.URL.Path != "/api/v2/alerts" {
			t.Errorf("path = %q, want /api/v2/alerts", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	ep, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}

	h := NewHandler(
		[]*url.URL{ep},
		"",
		"",
		// Order matches main.go: extract tenant, map to ID header, then accessor token.
		WriteMiddleware(seedTenant),
		WithTenantHeader("X-Scope-OrgID", map[string]string{"test-oidc": "tenant-uuid"}),
		WithAccessorToken("accessor"),
	)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, requestWithTenant(http.MethodPost, "/api/v2/alerts", "test-oidc"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if gotAuth != "Bearer accessor" {
		t.Fatalf("Authorization = %q, want Bearer accessor", gotAuth)
	}
	if gotTenant != "tenant-uuid" {
		t.Fatalf("X-Scope-OrgID = %q, want tenant-uuid", gotTenant)
	}
}
