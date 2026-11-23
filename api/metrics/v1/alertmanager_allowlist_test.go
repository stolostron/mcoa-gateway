package v1

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/alertmanager/api/v2/models"

	"github.com/stolostron/mcoa-gateway/authentication"
)

const (
	allowListLabel     = "tenant_id"
	allowListSilenceID = "802146e0-1f7a-42a6-ab0e-1e631479970b"
)

func TestWithEnforceTenancyOnFilterAllowList(t *testing.T) {
	t.Parallel()

	const label = "tenant_id"

	t.Run("dotted regexp", func(t *testing.T) {
		t.Parallel()
		filters, bare, code, body, called := serveFilter(t, "cluster.a|cluster.b", url.Values{
			label: []string{"sneaky"},
		})
		if code != http.StatusOK || !called {
			t.Fatalf("status %d called %v body %s", code, called, body)
		}
		want := `tenant_id=~"cluster\\.a|cluster\\.b"`
		if len(filters) != 1 || filters[0] != want {
			t.Fatalf("filters %v", filters)
		}
		if bare != "" {
			t.Fatalf("bare tenant param %q", bare)
		}
	})

	t.Run("drops caller tenant filter", func(t *testing.T) {
		t.Parallel()
		q := url.Values{}
		q.Add("filter", `tenant_id="cluster.a"`)
		q.Add("filter", `alertname="Watchdog"`)
		q.Set(label, "sneaky")
		filters, bare, code, body, called := serveFilter(t, "cluster.a|cluster.b", q)
		if code != http.StatusOK || !called {
			t.Fatalf("status %d called %v body %s", code, called, body)
		}
		if len(filters) != 2 || filters[0] != `tenant_id=~"cluster\\.a|cluster\\.b"` || filters[1] != `alertname="Watchdog"` {
			t.Fatalf("filters %v", filters)
		}
		if bare != "" {
			t.Fatalf("bare tenant param %q", bare)
		}
	})

	t.Run("bad caller filter", func(t *testing.T) {
		t.Parallel()
		q := url.Values{}
		q.Add("filter", "not-a-matcher")
		_, _, code, body, called := serveFilter(t, "cluster.a|cluster.b", q)
		if code != http.StatusBadRequest || called || !strings.Contains(body, "invalid filter") {
			t.Fatalf("status %d called %v body %s", code, called, body)
		}
	})

	t.Run("single cluster", func(t *testing.T) {
		t.Parallel()
		filters, _, code, body, called := serveFilter(t, "cluster-a", nil)
		if code != http.StatusOK || !called {
			t.Fatalf("status %d called %v body %s", code, called, body)
		}
		if len(filters) != 1 || filters[0] != `tenant_id="cluster-a"` {
			t.Fatalf("filters %v", filters)
		}
	})

	t.Run("missing tenant", func(t *testing.T) {
		t.Parallel()
		_, _, code, body, called := serveFilter(t, "", nil)
		if code != http.StatusInternalServerError || called || !strings.Contains(body, "error finding tenant") {
			t.Fatalf("status %d called %v body %s", code, called, body)
		}
	})
}

func TestWithEnforceTenancyOnSilenceMatchersAllowList(t *testing.T) {
	t.Parallel()

	const other = `{"name":"alertname","value":"Watchdog","isRegex":false,"isEqual":true}`
	eq := func(value string, isRegex, isEqual string) string {
		return `{"name":"tenant_id","value":"` + value + `","isRegex":` + isRegex + `,"isEqual":` + isEqual + `}`
	}
	tests := []struct {
		name      string
		tenant    string
		body      string
		want      int
		wantValue string
		wantNames []string
		wantMsg   string
		absent    string
	}{
		{
			name:      "equality cluster.a",
			tenant:    "cluster.a|cluster.b",
			body:      `{"matchers":[{"name":"severity","value":"critical","isRegex":false,"isEqual":true},` + eq("cluster.a", "false", "true") + `,` + other + `]}`,
			want:      http.StatusOK,
			wantValue: "cluster.a",
			wantNames: []string{"tenant_id", "severity", "alertname"},
		},
		{
			name:      "omitted isEqual",
			tenant:    "cluster.a|cluster.b",
			body:      `{"matchers":[{"name":"tenant_id","value":"cluster.a","isRegex":false},` + other + `]}`,
			want:      http.StatusOK,
			wantValue: "cluster.a",
			wantNames: []string{"tenant_id", "alertname"},
		},
		{
			name:      "cluster.b",
			tenant:    "cluster.a|cluster.b",
			body:      `{"matchers":[` + eq("cluster.b", "false", "true") + `,` + other + `]}`,
			want:      http.StatusOK,
			wantValue: "cluster.b",
			wantNames: []string{"tenant_id", "alertname"},
		},
		{
			name:    "omitted tenant matcher",
			tenant:  "cluster.a|cluster.b",
			body:    `{"matchers":[` + other + `]}`,
			want:    http.StatusBadRequest,
			wantMsg: "silence must name one tenant_id cluster",
		},
		{
			name:    "foreign cluster",
			tenant:  "cluster.a|cluster.b",
			body:    `{"matchers":[` + eq("cluster.c", "false", "true") + `,` + other + `]}`,
			want:    http.StatusForbidden,
			wantMsg: "forbidden",
			absent:  "cluster.c",
		},
		{
			name:    "two tenant matchers",
			tenant:  "cluster.a|cluster.b",
			body:    `{"matchers":[` + eq("cluster.a", "false", "true") + `,` + eq("cluster.b", "false", "true") + `,` + other + `]}`,
			want:    http.StatusBadRequest,
			wantMsg: "exactly one tenant_id matcher",
		},
		{
			name:    "regex name",
			tenant:  "cluster.a|cluster.b",
			body:    `{"matchers":[` + eq("cluster.a", "true", "true") + `,` + other + `]}`,
			want:    http.StatusBadRequest,
			wantMsg: "matcher must be an equality",
		},
		{
			name:    "regex of the allow-list",
			tenant:  "cluster.a|cluster.b",
			body:    `{"matchers":[{"name":"tenant_id","value":"cluster\\.a|cluster\\.b","isRegex":true,"isEqual":true},` + other + `]}`,
			want:    http.StatusBadRequest,
			wantMsg: "matcher must be an equality",
		},
		{
			name:    "regex all",
			tenant:  "cluster.a|cluster.b",
			body:    `{"matchers":[` + eq(".*", "true", "true") + `,` + other + `]}`,
			want:    http.StatusBadRequest,
			wantMsg: "matcher must be an equality",
		},
		{
			name:    "nil isRegex",
			tenant:  "cluster.a|cluster.b",
			body:    `{"matchers":[{"name":"tenant_id","value":"cluster.a","isEqual":true},` + other + `]}`,
			want:    http.StatusBadRequest,
			wantMsg: "matcher must be an equality",
		},
		{
			name:    "null isRegex",
			tenant:  "cluster.a|cluster.b",
			body:    `{"matchers":[{"name":"tenant_id","value":"cluster.a","isRegex":null,"isEqual":true},` + other + `]}`,
			want:    http.StatusBadRequest,
			wantMsg: "matcher must be an equality",
		},
		{
			name:    "negative matcher",
			tenant:  "cluster.a|cluster.b",
			body:    `{"matchers":[` + eq("cluster.a", "false", "false") + `,` + other + `]}`,
			want:    http.StatusBadRequest,
			wantMsg: "matcher must be an equality",
		},
		{
			name:    "tenant matcher only",
			tenant:  "cluster.a|cluster.b",
			body:    `{"matchers":[` + eq("cluster.a", "false", "true") + `]}`,
			want:    http.StatusBadRequest,
			wantMsg: "need at least one matcher, got none",
		},
		{
			name:    "joined string",
			tenant:  "cluster.a|cluster.b",
			body:    `{"matchers":[` + eq("cluster.a|cluster.b", "false", "true") + `,` + other + `]}`,
			want:    http.StatusForbidden,
			wantMsg: "forbidden",
			absent:  "cluster.a|cluster.b",
		},
		{
			name:      "single cluster names itself",
			tenant:    "cluster.a",
			body:      `{"matchers":[` + eq("cluster.a", "false", "true") + `,` + other + `]}`,
			want:      http.StatusOK,
			wantValue: "cluster.a",
			wantNames: []string{"tenant_id", "alertname"},
		},
		{
			name:    "single cluster omits tenant",
			tenant:  "cluster.a",
			body:    `{"matchers":[` + other + `]}`,
			want:    http.StatusBadRequest,
			wantMsg: "silence must name one tenant_id cluster",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			code, resp, got := postSilence(t, tc.tenant, http.MethodPost, tc.body)
			if code != tc.want {
				t.Fatalf("status %d body %s", code, resp)
			}
			if tc.want != http.StatusOK {
				if got != nil {
					t.Fatal("proxied a rejected silence")
				}
				if tc.wantMsg != "" && !strings.Contains(resp, tc.wantMsg) {
					t.Fatalf("body %s missing %s", resp, tc.wantMsg)
				}
				if tc.absent != "" && strings.Contains(resp, tc.absent) {
					t.Fatalf("body %s contains %s", resp, tc.absent)
				}
				return
			}
			if got == nil {
				t.Fatal("silence was not proxied")
			}
			if len(got.Matchers) != len(tc.wantNames) {
				t.Fatalf("matchers %#v", got.Matchers)
			}
			for i, name := range tc.wantNames {
				if got.Matchers[i] == nil || got.Matchers[i].Name == nil || *got.Matchers[i].Name != name {
					t.Fatalf("matcher %d %#v", i, got.Matchers[i])
				}
			}
			head := got.Matchers[0]
			if head.Value == nil || *head.Value != tc.wantValue || head.IsRegex == nil || *head.IsRegex || head.IsEqual == nil || !*head.IsEqual {
				t.Fatalf("stored %#v", head)
			}
			if *head.Value == `cluster\.a` {
				t.Fatal("stored QuoteMeta instead of the raw name")
			}
		})
	}

	t.Run("method not allowed", func(t *testing.T) {
		t.Parallel()
		code, resp, got := postSilence(t, "", http.MethodGet, "")
		if code != http.StatusMethodNotAllowed || got != nil || !strings.Contains(resp, "error method not allowed") {
			t.Fatalf("status %d body %s proxied %v", code, resp, got != nil)
		}
	})

	t.Run("bad json", func(t *testing.T) {
		t.Parallel()
		code, resp, got := postSilence(t, "cluster.a|cluster.b", http.MethodPost, "{")
		if code != http.StatusBadRequest || got != nil || !strings.Contains(resp, "can't decode") {
			t.Fatalf("status %d body %s", code, resp)
		}
	})

	t.Run("id rejected before matchers", func(t *testing.T) {
		t.Parallel()
		body := `{"id":"sid","matchers":[` + other + `]}`
		code, resp, got := postSilence(t, "cluster.a|cluster.b", http.MethodPost, body)
		if code != http.StatusUnprocessableEntity || got != nil || !strings.Contains(resp, "updates to silence by ID not allowed") {
			t.Fatalf("status %d body %s", code, resp)
		}
	})

	t.Run("missing tenant", func(t *testing.T) {
		t.Parallel()
		body := `{"matchers":[` + eq("cluster.a", "false", "true") + `,` + other + `]}`
		code, resp, got := postSilence(t, "", http.MethodPost, body)
		if code != http.StatusInternalServerError || got != nil || !strings.Contains(resp, "error finding tenant") {
			t.Fatalf("status %d body %s", code, resp)
		}
	})
}

func TestWithEnforceTenancyOnSilenceIDAllowList(t *testing.T) {
	t.Parallel()

	t.Run("owned equality proxies get and delete", func(t *testing.T) {
		t.Parallel()
		for _, method := range []string{http.MethodGet, http.MethodDelete} {
			code, resp, called := serveSilenceID(t, method, "cluster-a|cluster-b", http.StatusOK, silenceObject("cluster-a", false, boolPtr(true)))
			if code != http.StatusOK || !called {
				t.Fatalf("%s status %d called %v body %s", method, code, called, resp)
			}
		}
	})

	t.Run("single cluster still proxies", func(t *testing.T) {
		t.Parallel()
		code, _, called := serveSilenceID(t, http.MethodGet, "cluster-a", http.StatusOK, silenceObject("cluster-a", false, nil))
		if code != http.StatusOK || !called {
			t.Fatalf("status %d called %v", code, called)
		}
	})

	t.Run("foreign cluster", func(t *testing.T) {
		t.Parallel()
		code, resp, called := serveSilenceID(t, http.MethodGet, "cluster-a|cluster-b", http.StatusOK, silenceObject("cluster-c", false, boolPtr(true)))
		if code != http.StatusForbidden || called || !strings.Contains(resp, "forbidden") || strings.Contains(resp, "cluster-c") {
			t.Fatalf("status %d called %v body %s", code, called, resp)
		}
	})

	t.Run("regex", func(t *testing.T) {
		t.Parallel()
		code, resp, called := serveSilenceID(t, http.MethodGet, "cluster-a|cluster-b", http.StatusOK, silenceObject(".*", true, boolPtr(true)))
		if code != http.StatusForbidden || called || !strings.Contains(resp, "forbidden") {
			t.Fatalf("status %d called %v body %s", code, called, resp)
		}
	})

	t.Run("negative matcher", func(t *testing.T) {
		t.Parallel()
		code, _, called := serveSilenceID(t, http.MethodGet, "cluster-a|cluster-b", http.StatusOK, silenceObject("cluster-a", false, boolPtr(false)))
		if code != http.StatusForbidden || called {
			t.Fatalf("status %d called %v", code, called)
		}
	})

	t.Run("upstream not found", func(t *testing.T) {
		t.Parallel()
		code, _, called := serveSilenceID(t, http.MethodDelete, "cluster-a|cluster-b", http.StatusNotFound, "")
		if code != http.StatusNotFound || called {
			t.Fatalf("status %d called %v", code, called)
		}
	})

	t.Run("upstream error", func(t *testing.T) {
		t.Parallel()
		code, _, called := serveSilenceID(t, http.MethodGet, "cluster-a|cluster-b", http.StatusInternalServerError, `"upstream failed"`)
		if code != http.StatusBadGateway || called {
			t.Fatalf("status %d called %v", code, called)
		}
	})

	t.Run("missing tenant", func(t *testing.T) {
		t.Parallel()
		code, resp, called := serveSilenceID(t, http.MethodGet, "", http.StatusOK, silenceObject("cluster-a", false, boolPtr(true)))
		if code != http.StatusInternalServerError || called || !strings.Contains(resp, "error finding tenant") {
			t.Fatalf("status %d called %v body %s", code, called, resp)
		}
	})
}

func TestSilenceListHandler(t *testing.T) {
	t.Parallel()

	page := "[" + listedSilence("id-a", "cluster-a", false, nil) +
		"," + listedSilence("id-c", "cluster-c", false, boolPtr(true)) +
		"," + listedSilence("id-r", ".*", true, boolPtr(true)) + "]"

	t.Run("keeps owned equality", func(t *testing.T) {
		t.Parallel()
		var filters []string
		code, resp, called := serveList(t, "cluster-a|cluster-b", "", page, &filters)
		if code != http.StatusOK || !called {
			t.Fatalf("status %d called %v body %s", code, called, resp)
		}
		values := silenceTenantValues(t, []byte(resp))
		if len(values) != 1 || values[0] != "cluster-a" {
			t.Fatalf("tenants %v body %s", values, resp)
		}
		if strings.Contains(resp, "cluster-c") || strings.Contains(resp, "id-c") || strings.Contains(resp, "id-r") {
			t.Fatalf("body kept a foreign silence: %s", resp)
		}
		var sils models.GettableSilences
		if err := json.Unmarshal([]byte(resp), &sils); err != nil {
			t.Fatal(err)
		}
		if len(sils) != 1 || len(sils[0].Matchers) < 2 {
			t.Fatalf("silence %#v", sils)
		}
	})

	t.Run("content type and caller filters", func(t *testing.T) {
		t.Parallel()
		mixed := "[" + listedSilence("id-a", "cluster-a", false, boolPtr(true)) +
			"," + listedSilence("id-b", "cluster-b", false, boolPtr(true)) +
			"," + listedSilence("id-c", "cluster-c", false, boolPtr(true)) + "]"
		q := url.Values{}
		q.Add("filter", `alertname="Watchdog"`)
		q.Add("filter", `tenant_id="cluster-a"`)
		var filters []string
		code, resp, called := serveList(t, "cluster-a|cluster-b", q.Encode(), mixed, &filters)
		if code != http.StatusOK || !called {
			t.Fatalf("status %d called %v body %s", code, called, resp)
		}
		values := silenceTenantValues(t, []byte(resp))
		if len(values) != 2 || values[0] != "cluster-a" || values[1] != "cluster-b" {
			t.Fatalf("tenants %v", values)
		}
		if len(filters) != 1 || filters[0] != `alertname="Watchdog"` {
			t.Fatalf("filters %v", filters)
		}
	})

	t.Run("empty owned set", func(t *testing.T) {
		t.Parallel()
		foreign := "[" + listedSilence("id-c", "cluster-c", false, boolPtr(true)) +
			"," + listedSilence("id-r", ".*", true, boolPtr(true)) + "]"
		code, resp, called := serveList(t, "cluster-a|cluster-b", "", foreign, nil)
		if code != http.StatusOK || !called || resp != "[]" {
			t.Fatalf("status %d called %v body %q", code, called, resp)
		}
	})

	t.Run("bad caller filter", func(t *testing.T) {
		t.Parallel()
		code, resp, called := serveList(t, "cluster-a|cluster-b", "filter=not-a-matcher", page, nil)
		if code != http.StatusBadRequest || called || !strings.Contains(resp, "invalid filter") {
			t.Fatalf("status %d called %v body %s", code, called, resp)
		}
	})

	t.Run("upstream error hides silence id", func(t *testing.T) {
		t.Parallel()
		code, resp, called := serveListStatus(t, "cluster-a|cluster-b", "", http.StatusInternalServerError, `"leak-silence-id"`)
		if code != http.StatusBadGateway || !called || strings.Contains(resp, "leak-silence-id") {
			t.Fatalf("status %d called %v body %s", code, called, resp)
		}
	})

	t.Run("upstream bad request", func(t *testing.T) {
		t.Parallel()
		code, resp, called := serveListStatus(t, "cluster-a|cluster-b", "", http.StatusBadRequest, `"leak-silence-id"`)
		if code != http.StatusBadRequest || !called || strings.Contains(resp, "leak-silence-id") {
			t.Fatalf("status %d called %v body %s", code, called, resp)
		}
	})

	t.Run("single cluster", func(t *testing.T) {
		t.Parallel()
		mixed := "[" + listedSilence("id-a", "cluster-a", false, nil) +
			"," + listedSilence("id-b", "cluster-b", false, boolPtr(true)) + "]"
		code, resp, _ := serveList(t, "cluster-a", "", mixed, nil)
		values := silenceTenantValues(t, []byte(resp))
		if code != http.StatusOK || len(values) != 1 || values[0] != "cluster-a" {
			t.Fatalf("status %d tenants %v body %s", code, values, resp)
		}
	})

	t.Run("missing tenant", func(t *testing.T) {
		t.Parallel()
		code, resp, called := serveList(t, "", "", page, nil)
		if code != http.StatusInternalServerError || called || !strings.Contains(resp, "error finding tenant") {
			t.Fatalf("status %d called %v body %s", code, called, resp)
		}
	})
}

func serveFilter(t *testing.T, tenant string, q url.Values) (filters []string, bare string, code int, body string, called bool) {
	t.Helper()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		filters = r.URL.Query()["filter"]
		bare = r.URL.Query().Get("tenant_id")
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/am/api/v2/alerts", nil)
	if q != nil {
		req.URL.RawQuery = q.Encode()
	}
	if tenant != "" {
		req = req.WithContext(authentication.WithTenantValue(req.Context(), tenant))
	}
	rec := httptest.NewRecorder()
	WithEnforceTenancyOnFilter("tenant_id")(next).ServeHTTP(rec, req)
	return filters, bare, rec.Code, rec.Body.String(), called
}

func postSilence(t *testing.T, tenant, method, body string) (int, string, *models.PostableSilence) {
	t.Helper()

	var proxied *models.PostableSilence
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var sil models.PostableSilence
		if err := json.NewDecoder(r.Body).Decode(&sil); err != nil {
			t.Fatalf("decode proxied body: %v", err)
		}
		proxied = &sil
		w.WriteHeader(http.StatusOK)
	})
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, "/am/api/v2/silences", reader)
	if tenant != "" {
		req = req.WithContext(authentication.WithTenantValue(req.Context(), tenant))
	}
	rec := httptest.NewRecorder()
	WithEnforceTenancyOnSilenceMatchers("tenant_id")(next).ServeHTTP(rec, req)
	return rec.Code, rec.Body.String(), proxied
}

func serveSilenceID(t *testing.T, method, tenant string, upstreamStatus int, upstreamBody string) (int, string, bool) {
	t.Helper()

	var called bool
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/v2/silence/"+allowListSilenceID {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(upstreamStatus)
			_, _ = w.Write([]byte(upstreamBody))
			return
		}
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(upstream)
	t.Cleanup(srv.Close)
	upstreamURL, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(method, "/am/api/v2/silence/"+allowListSilenceID, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("silenceID", allowListSilenceID)
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	if tenant != "" {
		ctx = authentication.WithTenantValue(ctx, tenant)
	}
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	WithEnforceTenancyOnSilenceID("tenant_id", upstreamURL, srv.Client().Transport)(next).ServeHTTP(rec, req)
	return rec.Code, rec.Body.String(), called
}

func serveList(t *testing.T, tenant, rawQuery, page string, filters *[]string) (int, string, bool) {
	t.Helper()
	return serveListStatusQuery(t, tenant, rawQuery, http.StatusOK, page, filters)
}

func serveListStatus(t *testing.T, tenant, rawQuery string, status int, body string) (int, string, bool) {
	t.Helper()
	return serveListStatusQuery(t, tenant, rawQuery, status, body, nil)
}

func serveListStatusQuery(t *testing.T, tenant, rawQuery string, status int, body string, filters *[]string) (int, string, bool) {
	t.Helper()

	var called bool
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.URL.Path != "/api/v2/silences" {
			t.Errorf("path %s", r.URL.Path)
		}
		if filters != nil {
			*filters = r.URL.Query()["filter"]
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
	srv := httptest.NewServer(upstream)
	t.Cleanup(srv.Close)
	upstreamURL, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/am/api/v2/silences", nil)
	req.URL.RawQuery = rawQuery
	if tenant != "" {
		req = req.WithContext(authentication.WithTenantValue(req.Context(), tenant))
	}
	rec := httptest.NewRecorder()
	silenceListHandler("tenant_id", upstreamURL, srv.Client().Transport).ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		if got := rec.Header().Get("Content-Type"); got != "application/json" {
			t.Fatalf("content type %q", got)
		}
	}
	return rec.Code, rec.Body.String(), called
}

func listedSilence(id, value string, isRegex bool, isEqual *bool) string {
	regex := "false"
	if isRegex {
		regex = "true"
	}
	equal := ""
	if isEqual != nil {
		if *isEqual {
			equal = `,"isEqual":true`
		} else {
			equal = `,"isEqual":false`
		}
	}
	return `{
  "id": "` + id + `",
  "status": {"state": "active"},
  "updatedAt": "2020-01-15T09:06:23.419Z",
  "comment": "comment",
  "createdBy": "author",
  "endsAt": "2020-02-13T13:00:02.084Z",
  "matchers": [
    {"isRegex": ` + regex + equal + `, "name": "` + allowListLabel + `", "value": "` + value + `"},
    {"isRegex": false, "name": "alertname", "value": "Watchdog"}
  ],
  "startsAt": "2020-02-13T12:02:01.000Z"
}`
}

func silenceObject(value string, isRegex bool, isEqual *bool) string {
	regex := "false"
	if isRegex {
		regex = "true"
	}
	equal := ""
	if isEqual != nil {
		if *isEqual {
			equal = `,"isEqual":true`
		} else {
			equal = `,"isEqual":false`
		}
	}
	return `{
  "id": "` + allowListSilenceID + `",
  "status": {"state": "active"},
  "updatedAt": "2020-01-15T09:06:23.419Z",
  "comment": "comment",
  "createdBy": "author",
  "endsAt": "2020-02-13T13:00:02.084Z",
  "matchers": [{"isRegex": ` + regex + equal + `, "name": "` + allowListLabel + `", "value": "` + value + `"}],
  "startsAt": "2020-02-13T12:02:01.000Z"
}`
}
