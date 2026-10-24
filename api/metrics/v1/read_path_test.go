package v1

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-kit/log"

	"github.com/stolostron/mcoa-gateway/authentication"
	"github.com/stolostron/mcoa-gateway/tls"
)

func TestAlertmanagerGetEnforcesTenantFilter(t *testing.T) {
	const (
		label  = "tenant_id"
		tenant = "team-alpha"
	)

	tests := []struct {
		name   string
		path   string
		filter string
	}{
		{
			name: "alerts",
			path: "/api/metrics/v1/am/api/v2/alerts",
		},
		{
			name:   "silences",
			path:   "/api/metrics/v1/am/api/v2/silences",
			filter: `alertname="Watchdog"`,
		},
		{
			name:   "alerts replace caller tenant filter",
			path:   "/api/metrics/v1/am/api/v2/alerts",
			filter: `tenant_id="other"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var filters []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				filters = r.URL.Query()["filter"]
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(srv.Close)

			parent := mountMetrics(t, srv.URL, label)
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			if tc.filter != "" {
				q := url.Values{}
				q.Add("filter", tc.filter)
				req.URL.RawQuery = q.Encode()
			}
			req.Header.Set("THANOS-TENANT", tenant)
			rr := httptest.NewRecorder()
			parent.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
			}

			want := label + `="` + tenant + `"`
			if !containsString(filters, want) {
				t.Fatalf("filters %v missing %s", filters, want)
			}
			if strings.Contains(tc.filter, `tenant_id="other"`) && containsString(filters, `tenant_id="other"`) {
				t.Fatalf("filters %v kept caller tenant matcher", filters)
			}
		})
	}
}

func TestSilenceByIDSeesTenant(t *testing.T) {
	const (
		label  = "tenant_id"
		tenant = "team-alpha"
		silID  = "802146e0-1f7a-42a6-ab0e-1e631479970b"
	)
	silenceJSON := `{
  "id": "` + silID + `",
  "status": {"state": "active"},
  "updatedAt": "2020-01-15T09:06:23.419Z",
  "comment": "comment",
  "createdBy": "author",
  "endsAt": "2020-02-13T13:00:02.084Z",
  "matchers": [{"isRegex": false, "name": "` + label + `", "value": "` + tenant + `"}],
  "startsAt": "2020-02-13T12:02:01.000Z"
}`

	var proxied bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, silID) {
			http.NotFound(w, r)
			return
		}
		proxied = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(silenceJSON))
	}))
	t.Cleanup(srv.Close)

	parent := mountMetrics(t, srv.URL, label)
	req := httptest.NewRequest(http.MethodGet, "/api/metrics/v1/am/api/v2/silence/"+silID, nil)
	req.Header.Set("THANOS-TENANT", tenant)
	rr := httptest.NewRecorder()
	parent.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	if !proxied {
		t.Fatal("silence request did not reach upstream")
	}
}

func mountMetrics(t *testing.T, upstreamRaw, label string) http.Handler {
	t.Helper()

	upstream, err := url.Parse(upstreamRaw)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(
		Endpoints{AlertmanagerEndpoint: upstream},
		&tls.UpstreamOptions{},
		WithLogger(log.NewNopLogger()),
		WithTenantLabel(label),
		WithGlobalMiddleware(authentication.WithTenantFromHeader("THANOS-TENANT")),
	)
	parent := chi.NewRouter()
	parent.Mount("/api/metrics/v1", handler)
	return parent
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
