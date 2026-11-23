package v1

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-kit/log"

	"github.com/stolostron/mcoa-gateway/tls"
)

func TestQueryReadUIMiddlewareSkipsAlertmanager(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	endpoint, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}

	var deriveHits, amHits []string
	mark := func(dst *[]string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				*dst = append(*dst, r.URL.Path)
				next.ServeHTTP(w, r)
			})
		}
	}
	inner := NewHandler(
		Endpoints{
			ReadEndpoint:         endpoint,
			WriteEndpoint:        endpoint,
			RulesEndpoint:        endpoint,
			AlertmanagerEndpoint: endpoint,
		},
		&tls.UpstreamOptions{},
		WithLogger(log.NewNopLogger()),
		WithTenantLabel("tenant_id"),
		WithQueryReadUIMiddleware(mark(&deriveHits)),
		WithAlertmanagerMiddleware(mark(&amHits)),
	)
	const prefix = "/api/metrics/v1"
	handler := chi.NewRouter()
	handler.Mount(prefix, inner)

	derivePaths := []string{
		prefix + "/api/v1/query",
		prefix + "/api/v1/series",
		prefix + "/api/v1/rules",
		prefix + "/graph",
		prefix + "/api/v1/rules/raw",
	}
	amPaths := []struct {
		method string
		path   string
	}{
		{http.MethodGet, prefix + "/am/api/v2/alerts"},
		{http.MethodGet, prefix + "/am/api/v2/silences"},
		{http.MethodPost, prefix + "/am/api/v2/silences"},
		{http.MethodGet, prefix + "/am/api/v2/silence/abc"},
		{http.MethodDelete, prefix + "/am/api/v2/silence/abc"},
	}
	neither := []struct {
		method string
		path   string
	}{
		{http.MethodPost, prefix + "/api/v1/receive"},
		{http.MethodPut, prefix + "/api/v1/rules/raw"},
	}

	for _, path := range derivePaths {
		deriveHits, amHits = nil, nil
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if !hasPath(deriveHits, path) || hasPath(amHits, path) {
			t.Fatalf("%s derive=%v am=%v status=%d body=%s", path, deriveHits, amHits, rec.Code, rec.Body.String())
		}
	}
	for _, tc := range amPaths {
		deriveHits, amHits = nil, nil
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if hasPath(deriveHits, tc.path) || !hasPath(amHits, tc.path) {
			t.Fatalf("%s %s derive=%v am=%v status=%d", tc.method, tc.path, deriveHits, amHits, rec.Code)
		}
	}
	for _, tc := range neither {
		deriveHits, amHits = nil, nil
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code == http.StatusNotFound || hasPath(deriveHits, tc.path) || hasPath(amHits, tc.path) {
			t.Fatalf("%s %s derive=%v am=%v status=%d", tc.method, tc.path, deriveHits, amHits, rec.Code)
		}
	}
}

func hasPath(paths []string, want string) bool {
	for _, path := range paths {
		if path == want {
			return true
		}
	}
	return false
}
