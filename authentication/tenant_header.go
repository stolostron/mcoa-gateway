package authentication

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/observatorium/api/httperr"
)

var (
	// tenantNameRegex restricts tenant names to alphanumeric, underscore, and dash
	tenantNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

	// maxTenantNameLength prevents abuse with very long tenant names
	maxTenantNameLength = 256

	// maxTenants limits the number of tenants that can be queried simultaneously
	maxTenants = 100
)

// WithTenantFromHeader extracts tenant(s) from the specified HTTP header and adds them to the request context.
// This is designed for read-path authentication where clients (like Grafana) specify the tenant via headers.
//
// Supports multiple tenants in two ways:
//   1. Multiple header values (recommended):
//        X-Scope-OrgID: team-a
//        X-Scope-OrgID: team-b
//        X-Scope-OrgID: team-c
//   2. Pipe-separated string (legacy, for backwards compatibility):
//        X-Scope-OrgID: team-a|team-b|team-c
//
// For example:
//   - Loki uses "X-Scope-OrgID"
//   - Thanos/Prometheus uses "THANOS-TENANT"
//   - Jaeger uses "X-Tenant"
func WithTenantFromHeader(tenantHeader string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get all header values (supports multiple headers with same name)
			tenantValues := r.Header.Values(tenantHeader)

			if len(tenantValues) == 0 {
				httperr.PrometheusAPIError(w,
					fmt.Sprintf("tenant header '%s' is required", tenantHeader),
					http.StatusBadRequest)
				return
			}

			// Collect all tenants (flatten if using pipe-separated format)
			var tenants []string
			for _, value := range tenantValues {
				// Support both multiple headers and pipe-separated format
				parts := strings.Split(value, "|")
				for _, part := range parts {
					tenant := strings.TrimSpace(part)
					if tenant != "" {
						tenants = append(tenants, tenant)
					}
				}
			}

			// Validate we have at least one tenant
			if len(tenants) == 0 {
				httperr.PrometheusAPIError(w, "empty tenant name not allowed", http.StatusBadRequest)
				return
			}

			// Validate number of tenants
			if len(tenants) > maxTenants {
				httperr.PrometheusAPIError(w,
					fmt.Sprintf("too many tenants (max %d)", maxTenants),
					http.StatusBadRequest)
				return
			}

			// Validate each tenant name
			seen := make(map[string]bool, len(tenants))
			for _, tenant := range tenants {
				// Check length
				if len(tenant) > maxTenantNameLength {
					httperr.PrometheusAPIError(w,
						fmt.Sprintf("tenant name too long (max %d characters): %s", maxTenantNameLength, tenant),
						http.StatusBadRequest)
					return
				}

				// Check format (alphanumeric, underscore, dash only)
				if !tenantNameRegex.MatchString(tenant) {
					httperr.PrometheusAPIError(w,
						fmt.Sprintf("invalid tenant name '%s' (allowed: a-z, A-Z, 0-9, _, -)", tenant),
						http.StatusBadRequest)
					return
				}

				// Check for duplicates
				if seen[tenant] {
					httperr.PrometheusAPIError(w,
						fmt.Sprintf("duplicate tenant name: %s", tenant),
						http.StatusBadRequest)
					return
				}
				seen[tenant] = true
			}

			// Join tenants with pipe separator for internal representation
			// This maintains compatibility with existing authorization middleware
			tenantString := strings.Join(tenants, "|")

			// Set tenant in request context for downstream middleware
			ctx := context.WithValue(r.Context(), tenantKey, tenantString)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// WithOptionalTenantFromHeader extracts the tenant from the header if present, otherwise continues without error.
// This is useful for endpoints that can work with or without a tenant specified.
func WithOptionalTenantFromHeader(tenantHeader string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant := r.Header.Get(tenantHeader)
			if tenant != "" {
				ctx := context.WithValue(r.Context(), tenantKey, tenant)
				r = r.WithContext(ctx)
			}

			next.ServeHTTP(w, r)
		})
	}
}
