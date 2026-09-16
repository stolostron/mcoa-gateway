package authorization

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/prometheus/prometheus/model/labels"

	"github.com/stolostron/mcoa-gateway/authentication"
	"github.com/stolostron/mcoa-gateway/httperr"
)

// WithTenantLabel returns a middleware that converts tenant(s) from the request context
// into label matchers for enforcement by label enforcer middlewares.
// Supports single tenant or multiple tenants separated by |.
func WithTenantLabel(tenantLabelName string) func(http.Handler) http.Handler {
	// Validate configuration at middleware creation time
	if tenantLabelName == "" {
		panic("tenantLabelName cannot be empty - check metrics.tenant-label or logs.tenant-label configuration")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant, ok := authentication.GetTenant(r.Context())
			if !ok {
				httperr.PrometheusAPIError(w, "error finding tenant in request context", http.StatusBadRequest)
				return
			}

			// Support multiple tenants separated by |
			// e.g., "tenant-a|tenant-b|tenant-c"
			tenants := strings.Split(tenant, "|")

			// Validate and escape each tenant name to prevent regex injection
			for i, t := range tenants {
				t = strings.TrimSpace(t)
				if t == "" {
					httperr.PrometheusAPIError(w, "empty tenant name not allowed", http.StatusBadRequest)
					return
				}
				// Escape regex metacharacters for multi-tenant queries
				// This prevents injection attacks like ".*" matching all tenants
				tenants[i] = regexp.QuoteMeta(t)
			}

			var matchers []*labels.Matcher
			if len(tenants) == 1 {
				// Single tenant: exact match
				// Use original unescaped value for exact match (no regex needed)
				originalTenant := strings.TrimSpace(strings.Split(tenant, "|")[0])
				matchers = []*labels.Matcher{
					{
						Type:  labels.MatchEqual,
						Name:  tenantLabelName,
						Value: originalTenant,
					},
				}
			} else {
				// Multiple tenants: regex match with OR
				// Creates: tenant_id=~"tenant-a|tenant-b|tenant-c"
				// Note: tenant names are already escaped with regexp.QuoteMeta above
				matchers = []*labels.Matcher{
					{
						Type:  labels.MatchRegexp,
						Name:  tenantLabelName,
						Value: strings.Join(tenants, "|"),
					},
				}
			}

			// Serialize matchers to JSON for label enforcers
			matchersJSON, err := json.Marshal(matchers)
			if err != nil {
				httperr.PrometheusAPIError(w, "error encoding tenant matchers", http.StatusInternalServerError)
				return
			}

			// Set in authorization context for label enforcers to use
			ctx := WithData(r.Context(), string(matchersJSON))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
