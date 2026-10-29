package v1

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"

	"github.com/stolostron/mcoa-gateway/authentication"
	"github.com/stolostron/mcoa-gateway/authorization"
)

func TestMetricsEnforcerUsesRouteParam(t *testing.T) {
	tests := []struct {
		name      string
		tenant    string
		path      string
		params    url.Values
		param     string
		wantType  labels.MatchType
		wantValue string
		keepName  string
		keepValue string
	}{
		{
			name:      "series single tenant",
			tenant:    "team-alpha",
			path:      "/api/metrics/v1/api/v1/series",
			params:    url.Values{"match[]": {`{__name__="up"}`}},
			param:     "match[]",
			wantType:  labels.MatchEqual,
			wantValue: "team-alpha",
			keepName:  "__name__",
			keepValue: "up",
		},
		{
			name:      "series multiple tenants",
			tenant:    "team-alpha|team-beta",
			path:      "/api/metrics/v1/api/v1/series",
			params:    url.Values{"match[]": {`{__name__="up"}`}},
			param:     "match[]",
			wantType:  labels.MatchRegexp,
			wantValue: "team-alpha|team-beta",
			keepName:  "__name__",
			keepValue: "up",
		},
		{
			name:      "label names",
			tenant:    "team-alpha",
			path:      "/api/metrics/v1/api/v1/labels",
			param:     "match[]",
			wantType:  labels.MatchEqual,
			wantValue: "team-alpha",
		},
		{
			name:      "label values",
			tenant:    "team-alpha|team-beta",
			path:      "/api/metrics/v1/api/v1/label/job/values",
			param:     "match[]",
			wantType:  labels.MatchRegexp,
			wantValue: "team-alpha|team-beta",
		},
		{
			name:      "rules",
			tenant:    "team-alpha",
			path:      "/api/metrics/v1/api/v1/rules",
			param:     "match[]",
			wantType:  labels.MatchEqual,
			wantValue: "team-alpha",
		},
		{
			name:      "federate",
			tenant:    "team-alpha",
			path:      "/api/metrics/v1/federate",
			param:     "match[]",
			wantType:  labels.MatchEqual,
			wantValue: "team-alpha",
		},
		{
			name:      "instant query",
			tenant:    "team-alpha",
			path:      "/api/metrics/v1/api/v1/query",
			params:    url.Values{"query": {"up"}},
			param:     "query",
			wantType:  labels.MatchEqual,
			wantValue: "team-alpha",
		},
		{
			name:      "range query",
			tenant:    "team-alpha",
			path:      "/api/metrics/v1/api/v1/query_range",
			params:    url.Values{"query": {"up"}},
			param:     "query",
			wantType:  labels.MatchEqual,
			wantValue: "team-alpha",
		},
		{
			name:      "exemplars",
			tenant:    "team-alpha",
			path:      "/api/metrics/v1/api/v1/query_exemplars",
			params:    url.Values{"query": {"up"}},
			param:     "query",
			wantType:  labels.MatchEqual,
			wantValue: "team-alpha",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := enforceMetrics(t, tc.tenant, tc.path, tc.params)
			if tc.param == "query" && len(got["match[]"]) != 0 {
				t.Fatalf("query route rewrote match[]: %v", got["match[]"])
			}
			if tc.param == "match[]" && got.Get("query") != "" {
				t.Fatalf("matcher route rewrote query: %q", got.Get("query"))
			}
			ms := promMatchers(t, got.Get(tc.param))
			requirePromMatcher(t, ms, "tenant_id", tc.wantType, tc.wantValue)
			if tc.keepName != "" {
				requirePromMatcher(t, ms, tc.keepName, labels.MatchEqual, tc.keepValue)
			}
		})
	}
}

func enforceMetrics(t *testing.T, tenant, path string, params url.Values) url.Values {
	t.Helper()

	var got url.Values
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()
		w.WriteHeader(http.StatusOK)
	})
	handler := authentication.WithTenantFromHeader("THANOS-TENANT")(
		authorization.WithTenantLabel("tenant_id")(
			WithEnforceAuthorizationLabels()(inner),
		),
	)

	req := httptest.NewRequest(http.MethodGet, path, nil)
	if params != nil {
		req.URL.RawQuery = params.Encode()
	}
	req.Header.Set("THANOS-TENANT", tenant)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	return got
}

func TestMetricsEnforcerPostBodyKeepsSelectorsOffURL(t *testing.T) {
	// Mimic prometheus client_golang DoGetFallback: POST form body, empty URL query.
	var gotBody string
	var gotURLQuery url.Values
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURLQuery = r.URL.Query()
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	})
	handler := authentication.WithTenantFromHeader("THANOS-TENANT")(
		authorization.WithTenantLabel("tenant_id")(
			WithEnforceAuthorizationLabels()(inner),
		),
	)

	form := url.Values{
		"match[]": {`{__name__="observatorium_write",_id="test"}`},
		"start":   {"1"},
		"end":     {"2"},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/metrics/v1/api/v1/series", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("THANOS-TENANT", "test-oidc")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	if gotURLQuery.Get("match[]") != "" {
		t.Fatalf("URL still has match[]=%q; tenant-only URL matcher would OR with the body", gotURLQuery.Get("match[]"))
	}
	body, err := url.ParseQuery(gotBody)
	if err != nil {
		t.Fatalf("parse body: %v", err)
	}
	ms := promMatchers(t, body.Get("match[]"))
	requirePromMatcher(t, ms, "tenant_id", labels.MatchEqual, "test-oidc")
	requirePromMatcher(t, ms, "__name__", labels.MatchEqual, "observatorium_write")
	requirePromMatcher(t, ms, "_id", labels.MatchEqual, "test")
}

func promMatchers(t *testing.T, selector string) []*labels.Matcher {
	t.Helper()

	expr, err := parser.NewParser(parser.Options{}).ParseExpr(selector)
	if err != nil {
		t.Fatalf("parse %q: %v", selector, err)
	}
	vs, ok := expr.(*parser.VectorSelector)
	if !ok {
		t.Fatalf("%q parsed as %T", selector, expr)
	}
	return vs.LabelMatchers
}

func requirePromMatcher(t *testing.T, ms []*labels.Matcher, name string, typ labels.MatchType, value string) {
	t.Helper()

	for _, m := range ms {
		if m.Name == name && m.Type == typ && m.Value == value {
			return
		}
	}
	got := make([]string, 0, len(ms))
	for _, m := range ms {
		got = append(got, m.String())
	}
	t.Fatalf("matchers %v missing %s", got, (&labels.Matcher{Type: typ, Name: name, Value: value}).String())
}
