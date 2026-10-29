package legacy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"

	metricsv1 "github.com/stolostron/mcoa-gateway/api/metrics/v1"
	"github.com/stolostron/mcoa-gateway/authentication"
	"github.com/stolostron/mcoa-gateway/authorization"
	"github.com/stolostron/mcoa-gateway/tls"
)

func TestLegacyQueryRoutesEnforceTenant(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{name: "query", path: "/api/v1/api/v1/query"},
		{name: "query_range", path: "/api/v1/api/v1/query_range"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.URL.Query().Get("query")
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(srv.Close)

			upstream, err := url.Parse(srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			handler := NewHandler(
				upstream,
				&tls.UpstreamOptions{},
				WithGlobalMiddleware(authentication.WithTenantFromHeader("THANOS-TENANT")),
				WithGlobalMiddleware(authorization.WithTenantLabel("tenant_id")),
				WithGlobalMiddleware(metricsv1.WithEnforceAuthorizationLabels()),
			)
			parent := chi.NewRouter()
			parent.Mount("/api/v1", handler)

			q := url.Values{}
			q.Set("query", "up")
			req := httptest.NewRequest(http.MethodGet, tc.path+"?"+q.Encode(), nil)
			req.Header.Set("THANOS-TENANT", "team-alpha")
			rr := httptest.NewRecorder()
			parent.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("status %d body %s query %q", rr.Code, rr.Body.String(), got)
			}

			expr, err := parser.NewParser(parser.Options{}).ParseExpr(got)
			if err != nil {
				t.Fatalf("parse %q: %v", got, err)
			}
			vs, ok := expr.(*parser.VectorSelector)
			if !ok {
				t.Fatalf("%q parsed as %T", got, expr)
			}
			found := false
			for _, m := range vs.LabelMatchers {
				if m.Name == "tenant_id" && m.Type == labels.MatchEqual && m.Value == "team-alpha" {
					found = true
				}
			}
			if !found {
				t.Fatalf("query %q missing tenant matcher", got)
			}
		})
	}
}
