package http

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/prometheus/prometheus/model/labels"

	"github.com/stolostron/mcoa-gateway/authentication"
	"github.com/stolostron/mcoa-gateway/authorization"
	logqlv2 "github.com/stolostron/mcoa-gateway/logql/v2"
)

func TestWithTenantLabelInjectsIntoLogQL(t *testing.T) {
	tests := []struct {
		name      string
		tenant    string
		wantType  labels.MatchType
		wantValue string
	}{
		{
			name:      "single tenant",
			tenant:    "team-alpha",
			wantType:  labels.MatchEqual,
			wantValue: "team-alpha",
		},
		{
			name:      "multiple tenants",
			tenant:    "team-alpha|team-beta",
			wantType:  labels.MatchRegexp,
			wantValue: "team-alpha|team-beta",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			query := serveLogsRead(t, tc.tenant, http.MethodGet, "/loki/api/v1/query", url.Values{
				"query": {`{app="foo"}`},
			}, "")

			got := logQLMatchers(t, query)
			requireLogMatcher(t, got, "tenant_id", tc.wantType, tc.wantValue)
			requireLogMatcher(t, got, "app", labels.MatchEqual, "foo")
		})
	}
}

func TestLogsEnforcerInjectsTenantWhenQueryMissing(t *testing.T) {
	body := serveLogsAuthz(t, http.MethodGet, "/loki/api/v1/query", nil, "")
	got := logQLMatchers(t, body.Get("query"))
	requireLogMatcher(t, got, "tenant_id", labels.MatchEqual, "team-alpha")
}

func TestLogsEnforcerInjectsTenantIntoPostForm(t *testing.T) {
	form := url.Values{"query": {`{app="foo"}`}}
	body := serveLogsAuthz(t, http.MethodPost, "/loki/api/v1/query", nil, form.Encode())
	got := logQLMatchers(t, body.Get("query"))
	requireLogMatcher(t, got, "tenant_id", labels.MatchEqual, "team-alpha")
	requireLogMatcher(t, got, "app", labels.MatchEqual, "foo")
}

func TestLogsEnforcerPostPreservesURLQueryWhenBodyHasNoSelector(t *testing.T) {
	// Selector in the URL, other params in the body. Body must not invent a
	// tenant-only query that would override the URL selector.
	var gotQuery, gotBody string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("query")
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		gotBody = string(raw)
		w.WriteHeader(http.StatusOK)
	})
	handler := authentication.WithTenantFromHeader("X-Scope-OrgID")(
		authorization.WithTenantLabel("tenant_id")(
			WithEnforceAuthorizationLabels()(inner),
		),
	)

	form := url.Values{"limit": {"10"}}
	req := httptest.NewRequest(http.MethodPost, "/loki/api/v1/query", strings.NewReader(form.Encode()))
	req.URL.RawQuery = url.Values{"query": {`{app="foo"}`}}.Encode()
	req.Header.Set("X-Scope-OrgID", "team-alpha")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}

	ms := logQLMatchers(t, gotQuery)
	requireLogMatcher(t, ms, "tenant_id", labels.MatchEqual, "team-alpha")
	requireLogMatcher(t, ms, "app", labels.MatchEqual, "foo")

	body, err := url.ParseQuery(gotBody)
	if err != nil {
		t.Fatalf("parse body: %v", err)
	}
	if body.Get("limit") != "10" {
		t.Fatalf("body limit=%q, want 10", body.Get("limit"))
	}
	if body.Get("query") != "" {
		t.Fatalf("body invented query=%q; would override URL selector", body.Get("query"))
	}
}

func serveLogsRead(t *testing.T, tenant, method, path string, query url.Values, body string) string {
	t.Helper()

	var got string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query().Get("query")
		if r.Method == http.MethodPost && r.Body != nil {
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			parsed, err := url.ParseQuery(string(raw))
			if err != nil {
				t.Fatalf("parse body: %v", err)
			}
			if parsed.Get("query") != "" {
				got = parsed.Get("query")
			}
		}
		w.WriteHeader(http.StatusOK)
	})
	handler := authentication.WithTenantFromHeader("X-Scope-OrgID")(
		authorization.WithTenantLabel("tenant_id")(
			WithEnforceAuthorizationLabels()(inner),
		),
	)

	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.URL.RawQuery = query.Encode()
	req.Header.Set("X-Scope-OrgID", tenant)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	if got == "" {
		t.Fatal("upstream query is empty")
	}
	return got
}

func serveLogsAuthz(t *testing.T, method, path string, query url.Values, body string) url.Values {
	t.Helper()

	raw, err := json.Marshal(AuthzResponseData{Matchers: []*labels.Matcher{{
		Type:  labels.MatchEqual,
		Name:  "tenant_id",
		Value: "team-alpha",
	}}})
	if err != nil {
		t.Fatal(err)
	}

	var got url.Values
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()
		if r.Body != nil {
			payload, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			if len(payload) > 0 {
				parsed, err := url.ParseQuery(string(payload))
				if err != nil {
					t.Fatalf("parse body: %v", err)
				}
				if parsed.Get("query") != "" {
					got = parsed
				}
			}
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if query != nil {
		req.URL.RawQuery = query.Encode()
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req = req.WithContext(authorization.WithData(req.Context(), string(raw)))
	rr := httptest.NewRecorder()
	WithEnforceAuthorizationLabels()(inner).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	return got
}

func logQLMatchers(t *testing.T, expr string) []*labels.Matcher {
	t.Helper()

	parsed, err := logqlv2.ParseExpr(expr)
	if err != nil {
		t.Fatalf("parse %q: %v", expr, err)
	}
	switch e := parsed.(type) {
	case *logqlv2.LogQueryExpr:
		return e.Matchers()
	case *logqlv2.StreamMatcherExpr:
		return e.Matchers()
	default:
		t.Fatalf("parse %q: %T", expr, parsed)
		return nil
	}
}

func requireLogMatcher(t *testing.T, ms []*labels.Matcher, name string, typ labels.MatchType, value string) {
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
