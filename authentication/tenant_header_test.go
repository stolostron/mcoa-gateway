package authentication

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWithTenantFromHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		tenantHeader   string
		requestHeaders map[string]string   // single header values
		multiHeaders   map[string][]string // multiple header values
		wantTenant     string
		wantStatus     int
	}{
		{
			name:         "valid single tenant from X-Scope-OrgID",
			tenantHeader: "X-Scope-OrgID",
			requestHeaders: map[string]string{
				"X-Scope-OrgID": "team-alpha",
			},
			wantTenant: "team-alpha",
			wantStatus: http.StatusOK,
		},
		{
			name:         "valid single tenant from THANOS-TENANT",
			tenantHeader: "THANOS-TENANT",
			requestHeaders: map[string]string{
				"THANOS-TENANT": "tenant-123",
			},
			wantTenant: "tenant-123",
			wantStatus: http.StatusOK,
		},
		{
			name:         "valid tenant with underscore",
			tenantHeader: "X-Tenant",
			requestHeaders: map[string]string{
				"X-Tenant": "tenant_prod_us",
			},
			wantTenant: "tenant_prod_us",
			wantStatus: http.StatusOK,
		},
		{
			name:         "missing tenant header",
			tenantHeader: "X-Scope-OrgID",
			requestHeaders: map[string]string{
				"Other-Header": "value",
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:         "empty tenant header",
			tenantHeader: "X-Scope-OrgID",
			requestHeaders: map[string]string{
				"X-Scope-OrgID": "",
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:         "whitespace-only tenant",
			tenantHeader: "X-Scope-OrgID",
			requestHeaders: map[string]string{
				"X-Scope-OrgID": "   ",
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:         "multiple tenants via multiple headers (new feature)",
			tenantHeader: "X-Scope-OrgID",
			multiHeaders: map[string][]string{
				"X-Scope-OrgID": {"team-a", "team-b", "team-c"},
			},
			wantTenant: "team-a|team-b|team-c",
			wantStatus: http.StatusOK,
		},
		{
			name:         "multiple tenants via pipe separator (legacy)",
			tenantHeader: "X-Scope-OrgID",
			requestHeaders: map[string]string{
				"X-Scope-OrgID": "team-a|team-b|team-c",
			},
			wantTenant: "team-a|team-b|team-c",
			wantStatus: http.StatusOK,
		},
		{
			name:         "mixed: multiple headers with pipe separators",
			tenantHeader: "X-Scope-OrgID",
			multiHeaders: map[string][]string{
				"X-Scope-OrgID": {"team-a|team-b", "team-c"},
			},
			wantTenant: "team-a|team-b|team-c",
			wantStatus: http.StatusOK,
		},
		{
			name:         "invalid tenant name with special characters",
			tenantHeader: "X-Scope-OrgID",
			requestHeaders: map[string]string{
				"X-Scope-OrgID": "team@invalid",
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:         "invalid tenant name with spaces",
			tenantHeader: "X-Scope-OrgID",
			requestHeaders: map[string]string{
				"X-Scope-OrgID": "team alpha",
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:         "invalid tenant name with dots",
			tenantHeader: "X-Scope-OrgID",
			requestHeaders: map[string]string{
				"X-Scope-OrgID": "team.alpha",
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:         "tenant name too long",
			tenantHeader: "X-Scope-OrgID",
			requestHeaders: map[string]string{
				"X-Scope-OrgID": strings.Repeat("a", 257),
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:         "tenant name at max length (256 chars)",
			tenantHeader: "X-Scope-OrgID",
			requestHeaders: map[string]string{
				"X-Scope-OrgID": strings.Repeat("a", 256),
			},
			wantTenant: strings.Repeat("a", 256),
			wantStatus: http.StatusOK,
		},
		{
			name:         "duplicate tenants in multiple headers",
			tenantHeader: "X-Scope-OrgID",
			multiHeaders: map[string][]string{
				"X-Scope-OrgID": {"team-a", "team-b", "team-a"},
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:         "duplicate tenants in pipe-separated string",
			tenantHeader: "X-Scope-OrgID",
			requestHeaders: map[string]string{
				"X-Scope-OrgID": "team-a|team-b|team-a",
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:         "empty tenant in multi-tenant list",
			tenantHeader: "X-Scope-OrgID",
			requestHeaders: map[string]string{
				"X-Scope-OrgID": "team-a||team-b",
			},
			wantTenant: "team-a|team-b",
			wantStatus: http.StatusOK, // Empty parts are filtered out
		},
		{
			name:         "whitespace trimmed from tenants",
			tenantHeader: "X-Scope-OrgID",
			requestHeaders: map[string]string{
				"X-Scope-OrgID": " team-a | team-b ",
			},
			wantTenant: "team-a|team-b",
			wantStatus: http.StatusOK,
		},
		{
			name:         "custom tenant header name",
			tenantHeader: "X-Custom-Tenant",
			requestHeaders: map[string]string{
				"X-Custom-Tenant": "my-tenant",
			},
			wantTenant: "my-tenant",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create test handler that captures the tenant from context
			var capturedTenant string
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tenant, ok := GetTenant(r.Context())
				if ok {
					capturedTenant = tenant
				}
				w.WriteHeader(http.StatusOK)
			})

			// Wrap with middleware
			handler := WithTenantFromHeader(tt.tenantHeader)(testHandler)

			// Create request
			req := httptest.NewRequest(http.MethodGet, "/test", nil)

			// Set headers
			if tt.multiHeaders != nil {
				for name, values := range tt.multiHeaders {
					for _, value := range values {
						req.Header.Add(name, value)
					}
				}
			} else {
				for name, value := range tt.requestHeaders {
					req.Header.Set(name, value)
				}
			}

			// Execute request
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			// Check status code
			if rec.Code != tt.wantStatus {
				t.Errorf("status code = %d, want %d, body = %s",					rec.Code, tt.wantStatus, rec.Body.String())
			}

			// Check tenant value if status is OK
			if tt.wantStatus == http.StatusOK {
				if capturedTenant != tt.wantTenant {
					t.Errorf("tenant = %q, want %q", capturedTenant, tt.wantTenant)
				}
			}
		})
	}
}

func TestWithOptionalTenantFromHeader(t *testing.T) {
	tenantHeader := "X-Scope-OrgID"

	t.Run("extracts tenant from header when present", func(t *testing.T) {
		middleware := WithOptionalTenantFromHeader(tenantHeader)

		req := httptest.NewRequest(http.MethodGet, "/api/logs/v1/loki/api/v1/query", nil)
		req.Header.Set(tenantHeader, "team-alpha")

		var capturedTenant string
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant, ok := GetTenant(r.Context())
			if ok {
				capturedTenant = tenant
			}
			w.WriteHeader(http.StatusOK)
		})

		rr := httptest.NewRecorder()
		middleware(handler).ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rr.Code)
		}

		if capturedTenant != "team-alpha" {
			t.Errorf("expected tenant 'team-alpha', got '%s'", capturedTenant)
		}
	})

	t.Run("continues without error when header missing", func(t *testing.T) {
		middleware := WithOptionalTenantFromHeader(tenantHeader)

		req := httptest.NewRequest(http.MethodGet, "/api/logs/v1/loki/api/v1/query", nil)
		// No header set

		var handlerCalled bool
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			_, ok := GetTenant(r.Context())
			if ok {
				t.Error("expected no tenant in context")
			}
			w.WriteHeader(http.StatusOK)
		})

		rr := httptest.NewRecorder()
		middleware(handler).ServeHTTP(rr, req)

		if !handlerCalled {
			t.Error("handler should have been called")
		}

		if rr.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rr.Code)
		}
	})

	t.Run("continues without error when header empty", func(t *testing.T) {
		middleware := WithOptionalTenantFromHeader(tenantHeader)

		req := httptest.NewRequest(http.MethodGet, "/api/logs/v1/loki/api/v1/query", nil)
		req.Header.Set(tenantHeader, "")

		var handlerCalled bool
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			_, ok := GetTenant(r.Context())
			if ok {
				t.Error("expected no tenant in context")
			}
			w.WriteHeader(http.StatusOK)
		})

		rr := httptest.NewRecorder()
		middleware(handler).ServeHTTP(rr, req)

		if !handlerCalled {
			t.Error("handler should have been called")
		}

		if rr.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rr.Code)
		}
	})
}
