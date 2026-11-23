package v1

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/alertmanager/api/v2/models"
	amlabels "github.com/prometheus/alertmanager/pkg/labels"
	"github.com/prometheus/prometheus/model/labels"

	"github.com/stolostron/mcoa-gateway/authentication"
	"github.com/stolostron/mcoa-gateway/authorization"
)

func TestParseTenantAllowList(t *testing.T) {
	t.Parallel()

	allow, err := parseTenantAllowList(" a | b ")
	if err != nil {
		t.Fatal(err)
	}
	if len(allow.names) != 2 || allow.names[0] != "a" || allow.names[1] != "b" {
		t.Fatalf("names %v", allow.names)
	}
	m, err := allow.filterMatcher("tenant_id")
	if err != nil {
		t.Fatal(err)
	}
	if m.Type != labels.MatchRegexp || m.Value != "a|b" {
		t.Fatalf("matcher type %v value %q", m.Type, m.Value)
	}

	for _, tenant := range []string{"", "|", "a|", "a||b", "   "} {
		_, err := parseTenantAllowList(tenant)
		requireAllow(t, err, http.StatusBadRequest, "empty tenant name not allowed")
	}
}

func TestFilterMatcher(t *testing.T) {
	t.Parallel()

	tests := []struct {
		tenant string
		kind   labels.MatchType
		value  string
	}{
		{tenant: "cluster-a", kind: labels.MatchEqual, value: "cluster-a"},
		{tenant: "cluster.a", kind: labels.MatchEqual, value: "cluster.a"},
		{tenant: "cluster-a|cluster-b", kind: labels.MatchRegexp, value: "cluster-a|cluster-b"},
		{tenant: "cluster.a|cluster.b", kind: labels.MatchRegexp, value: `cluster\.a|cluster\.b`},
		{tenant: "team-alpha|team-beta|team-gamma", kind: labels.MatchRegexp, value: "team-alpha|team-beta|team-gamma"},
		{tenant: "clus*ter|cluster-b", kind: labels.MatchRegexp, value: `clus\*ter|cluster-b`},
		{tenant: ".*|cluster-a", kind: labels.MatchRegexp, value: `\.\*|cluster-a`},
	}
	for _, tc := range tests {
		t.Run(tc.tenant, func(t *testing.T) {
			t.Parallel()
			allow, err := parseTenantAllowList(tc.tenant)
			if err != nil {
				t.Fatal(err)
			}
			m, err := allow.filterMatcher("tenant_id")
			if err != nil {
				t.Fatal(err)
			}
			if m.Type != tc.kind || m.Name != "tenant_id" || m.Value != tc.value {
				t.Fatalf("type %v name %q value %q", m.Type, m.Name, m.Value)
			}
		})
	}

	var zero tenantAllowList
	m, err := zero.filterMatcher("tenant_id")
	if m != nil {
		t.Fatalf("matcher %#v", m)
	}
	requireAllow(t, err, http.StatusInternalServerError, "error finding tenant")
}

func TestFilterMatcherMatchesWithTenantLabel(t *testing.T) {
	t.Parallel()

	const label = "tenant_id"
	for _, tenant := range []string{
		"cluster-a",
		"cluster.a",
		"cluster-a|cluster-b",
		"cluster.a|cluster.b",
		"team-alpha|team-beta|team-gamma",
		" a | b ",
	} {
		t.Run(tenant, func(t *testing.T) {
			t.Parallel()
			allow, err := parseTenantAllowList(tenant)
			if err != nil {
				t.Fatal(err)
			}
			got, err := allow.filterMatcher(label)
			if err != nil {
				t.Fatal(err)
			}
			want := withTenantLabelMatcher(t, label, tenant)
			if got.Type != want.Type || got.Name != want.Name || got.Value != want.Value {
				t.Fatalf("filterMatcher type=%v name=%q value=%q, WithTenantLabel type=%v name=%q value=%q",
					got.Type, got.Name, got.Value, want.Type, want.Name, want.Value)
			}
		})
	}
}

func TestFilterMatcherRoundTrip(t *testing.T) {
	t.Parallel()

	dotted, err := parseTenantAllowList("cluster.a|cluster.b")
	if err != nil {
		t.Fatal(err)
	}
	dottedMatcher, err := dotted.filterMatcher("tenant_id")
	if err != nil {
		t.Fatal(err)
	}
	if got := dottedMatcher.String(); got != `tenant_id=~"cluster\\.a|cluster\\.b"` {
		t.Fatalf("wire %s", got)
	}
	assertRegexpMatches(t, dottedMatcher.String(), []string{"cluster.a", "cluster.b"}, []string{"clusterXa"})

	star, err := parseTenantAllowList("clus*ter|cluster-b")
	if err != nil {
		t.Fatal(err)
	}
	starMatcher, err := star.filterMatcher("tenant_id")
	if err != nil {
		t.Fatal(err)
	}
	assertRegexpMatches(t, starMatcher.String(), []string{"clus*ter", "cluster-b"}, []string{"clusXter"})

	wild, err := parseTenantAllowList(".*|cluster-a")
	if err != nil {
		t.Fatal(err)
	}
	wildMatcher, err := wild.filterMatcher("tenant_id")
	if err != nil {
		t.Fatal(err)
	}
	assertRegexpMatches(t, wildMatcher.String(), []string{"cluster-a"}, []string{"other"})
}

func TestSilencePost(t *testing.T) {
	t.Parallel()

	const label = "tenant_id"
	allow := mustAllow(t, "cluster.a|cluster.b")
	falsy := false
	truthy := true
	tenant := &models.Matcher{
		Name:    strPtr(label),
		Value:   strPtr("cluster.a"),
		IsRegex: &falsy,
		IsEqual: &truthy,
	}
	alert := &models.Matcher{
		Name:    strPtr("alertname"),
		Value:   strPtr("Watchdog"),
		IsRegex: &falsy,
		IsEqual: &truthy,
	}
	got, err := allow.silencePost(label, models.Matchers{alert, tenant})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("matchers %d", len(got))
	}
	if got[0] == tenant || got[0].Name == tenant.Name || got[0].Value == tenant.Value || got[0].IsRegex == tenant.IsRegex || got[0].IsEqual == tenant.IsEqual {
		t.Fatal("tenant matcher aliases the request")
	}
	assertEquality(t, got[0], label, "cluster.a")
	if got[0].Value != nil && *got[0].Value == `cluster\.a` {
		t.Fatal("stored QuoteMeta instead of the raw name")
	}
	if *got[1].Name != "alertname" || *got[1].Value != "Watchdog" {
		t.Fatalf("kept %#v", got[1])
	}

	omitted := &models.Matcher{Name: strPtr(label), Value: strPtr("cluster.a"), IsRegex: &falsy}
	stored, err := allow.silencePost(label, models.Matchers{omitted, alert})
	if err != nil {
		t.Fatal(err)
	}
	assertEquality(t, stored[0], label, "cluster.a")

	again, err := allow.silencePost(label, got)
	if err != nil {
		t.Fatal(err)
	}
	same, err := allow.silencePost(label, models.Matchers{alert, tenant})
	if err != nil {
		t.Fatal(err)
	}
	if !sameMatcherList(got, again) || !sameMatcherList(got, same) {
		t.Fatalf("not idempotent\n%v\n%v\n%v", matcherDump(got), matcherDump(again), matcherDump(same))
	}

	_, err = allow.silencePost(label, models.Matchers{
		{Name: strPtr(label), Value: strPtr("cluster.a"), IsEqual: &truthy},
		alert,
	})
	requireAllow(t, err, http.StatusBadRequest, label+" matcher must be an equality")

	_, err = allow.silencePost(label, models.Matchers{
		{Name: strPtr(label), Value: strPtr("cluster.a"), IsRegex: &truthy, IsEqual: &truthy},
		alert,
	})
	requireAllow(t, err, http.StatusBadRequest, label+" matcher must be an equality")

	_, err = allow.silencePost(label, models.Matchers{
		{Name: strPtr(label), Value: strPtr("cluster.a"), IsRegex: &falsy, IsEqual: &falsy},
		alert,
	})
	requireAllow(t, err, http.StatusBadRequest, label+" matcher must be an equality")

	_, err = allow.silencePost(label, models.Matchers{
		{Name: strPtr(label), Value: strPtr("cluster.c"), IsRegex: &falsy, IsEqual: &truthy},
		alert,
	})
	requireAllow(t, err, http.StatusForbidden, "forbidden")
	if err != nil && (strings.Contains(err.Error(), "cluster.c") || strings.Contains(err.Error(), "cluster.a|cluster.b")) {
		t.Fatalf("error echoes a cluster: %v", err)
	}

	_, err = allow.silencePost(label, models.Matchers{tenant})
	requireAllow(t, err, http.StatusBadRequest, "need at least one matcher, got none")

	var zero tenantAllowList
	_, err = zero.silencePost(label, models.Matchers{tenant, alert})
	requireAllow(t, err, http.StatusInternalServerError, "error finding tenant")
}

func TestOwnsSilence(t *testing.T) {
	t.Parallel()

	const label = "tenant_id"
	allow := mustAllow(t, "cluster-a|cluster-b")
	falsy := false
	truthy := true
	alert := &models.Matcher{Name: strPtr("alertname"), Value: strPtr("Watchdog"), IsRegex: &truthy, IsEqual: &truthy}

	tests := []struct {
		name     string
		matchers models.Matchers
		want     bool
	}{
		{name: "nil isEqual", matchers: models.Matchers{{Name: strPtr(label), Value: strPtr("cluster-a"), IsRegex: &falsy}}, want: true},
		{name: "cluster-b", matchers: models.Matchers{{Name: strPtr(label), Value: strPtr("cluster-b"), IsRegex: &falsy, IsEqual: &truthy}}, want: true},
		{name: "with alertname regex", matchers: models.Matchers{{Name: strPtr(label), Value: strPtr("cluster-a"), IsRegex: &falsy, IsEqual: &truthy}, alert}, want: true},
		{name: "foreign", matchers: models.Matchers{{Name: strPtr(label), Value: strPtr("cluster-c"), IsRegex: &falsy, IsEqual: &truthy}}, want: false},
		{name: "joined string", matchers: models.Matchers{{Name: strPtr(label), Value: strPtr("cluster-a|cluster-b"), IsRegex: &falsy, IsEqual: &truthy}}, want: false},
		{name: "regex name", matchers: models.Matchers{{Name: strPtr(label), Value: strPtr("cluster-a"), IsRegex: &truthy, IsEqual: &truthy}}, want: false},
		{name: "regex join", matchers: models.Matchers{{Name: strPtr(label), Value: strPtr(`cluster\.a|cluster\.b`), IsRegex: &truthy}}, want: false},
		{name: "regex all", matchers: models.Matchers{{Name: strPtr(label), Value: strPtr(".*"), IsRegex: &truthy, IsEqual: &truthy}}, want: false},
		{name: "negative", matchers: models.Matchers{{Name: strPtr(label), Value: strPtr("cluster-a"), IsRegex: &falsy, IsEqual: &falsy}}, want: false},
		{name: "two owned", matchers: models.Matchers{
			{Name: strPtr(label), Value: strPtr("cluster-a"), IsRegex: &falsy, IsEqual: &truthy},
			{Name: strPtr(label), Value: strPtr("cluster-b"), IsRegex: &falsy, IsEqual: &truthy},
		}, want: false},
		{name: "owned and foreign", matchers: models.Matchers{
			{Name: strPtr(label), Value: strPtr("cluster-a"), IsRegex: &falsy, IsEqual: &truthy},
			{Name: strPtr(label), Value: strPtr("cluster-c"), IsRegex: &falsy, IsEqual: &truthy},
		}, want: false},
		{name: "none", matchers: models.Matchers{alert}, want: false},
		{name: "nil matcher", matchers: models.Matchers{nil}, want: false},
		{name: "nil name", matchers: models.Matchers{{Value: strPtr("cluster-a"), IsRegex: &falsy}}, want: false},
		{name: "nil value", matchers: models.Matchers{{Name: strPtr(label), IsRegex: &falsy}}, want: false},
		{name: "nil isRegex", matchers: models.Matchers{{Name: strPtr(label), Value: strPtr("cluster-a"), IsEqual: &truthy}}, want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := allow.ownsSilence(label, tc.matchers); got != tc.want {
				t.Fatalf("ownsSilence() = %v, want %v", got, tc.want)
			}
		})
	}

	one := mustAllow(t, "cluster-a")
	if !one.ownsSilence(label, models.Matchers{{Name: strPtr(label), Value: strPtr("cluster-a"), IsRegex: &falsy}}) {
		t.Fatal("single cluster equality")
	}
	if one.ownsSilence(label, models.Matchers{{Name: strPtr(label), Value: strPtr("tenant-b"), IsRegex: &falsy}}) {
		t.Fatal("single cluster accepted another tenant")
	}
	if one.ownsSilence(label, models.Matchers{{Name: strPtr(label), Value: strPtr("cluster-a"), IsRegex: &truthy}}) {
		t.Fatal("single cluster accepted a regex")
	}

	var zero tenantAllowList
	if zero.ownsSilence(label, models.Matchers{{Name: strPtr(label), Value: strPtr("cluster-a"), IsRegex: &falsy, IsEqual: &truthy}}) {
		t.Fatal("zero allow-list owned a silence")
	}
}

func TestVisibleSilences(t *testing.T) {
	t.Parallel()

	const label = "tenant_id"
	allow := mustAllow(t, "cluster-a|cluster-b")
	falsy := false
	ownedA := &models.GettableSilence{ID: strPtr("a"), Silence: models.Silence{Matchers: models.Matchers{
		{Name: strPtr(label), Value: strPtr("cluster-a"), IsRegex: &falsy},
	}}}
	ownedB := &models.GettableSilence{ID: strPtr("b"), Silence: models.Silence{Matchers: models.Matchers{
		{Name: strPtr(label), Value: strPtr("cluster-b"), IsRegex: &falsy, IsEqual: boolPtr(true)},
	}}}
	foreign := &models.GettableSilence{ID: strPtr("c"), Silence: models.Silence{Matchers: models.Matchers{
		{Name: strPtr(label), Value: strPtr("cluster-c"), IsRegex: &falsy},
	}}}
	regex := &models.GettableSilence{ID: strPtr("r"), Silence: models.Silence{Matchers: models.Matchers{
		{Name: strPtr(label), Value: strPtr(".*"), IsRegex: boolPtr(true)},
	}}}

	got := allow.visibleSilences(label, models.GettableSilences{ownedB, nil, foreign, ownedA, regex})
	if got == nil {
		t.Fatal("nil slice")
	}
	if len(got) != 2 || got[0] != ownedB || got[1] != ownedA {
		t.Fatalf("visible %#v", got)
	}

	empty := allow.visibleSilences(label, models.GettableSilences{foreign, nil, regex})
	if empty == nil {
		t.Fatal("nil slice")
	}
	raw, err := json.Marshal(empty)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "[]" {
		t.Fatalf("empty %s", raw)
	}
}

func withTenantLabelMatcher(t *testing.T, label, tenant string) *labels.Matcher {
	t.Helper()

	var captured string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, ok := authorization.GetData(r.Context())
		if !ok {
			t.Fatal("missing authz data")
		}
		captured = data
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(authentication.WithTenantValue(req.Context(), tenant))
	rr := httptest.NewRecorder()
	authorization.WithTenantLabel(label)(inner).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	var doc authorization.AuthzResponseData
	if err := json.Unmarshal([]byte(captured), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Matchers) != 1 || doc.Matchers[0] == nil {
		t.Fatalf("matchers %#v", doc.Matchers)
	}
	return doc.Matchers[0]
}

func assertRegexpMatches(t *testing.T, wire string, hits, misses []string) {
	t.Helper()

	parsed, err := amlabels.ParseMatcher(wire)
	if err != nil {
		t.Fatalf("parse %s: %v", wire, err)
	}
	for _, hit := range hits {
		if !parsed.Matches(hit) {
			t.Fatalf("%s does not match %s", wire, hit)
		}
	}
	for _, miss := range misses {
		if parsed.Matches(miss) {
			t.Fatalf("%s matches %s", wire, miss)
		}
	}
}

func mustAllow(t *testing.T, tenant string) tenantAllowList {
	t.Helper()
	allow, err := parseTenantAllowList(tenant)
	if err != nil {
		t.Fatal(err)
	}
	return allow
}

func requireAllow(t *testing.T, err error, status int, msg string) {
	t.Helper()
	var allow *allowListError
	if !errors.As(err, &allow) {
		t.Fatalf("got %v, want allowListError", err)
	}
	if allow.Status() != status || allow.Error() != msg {
		t.Fatalf("status %d msg %q, want %d %q", allow.Status(), allow.Error(), status, msg)
	}
}

func assertEquality(t *testing.T, m *models.Matcher, name, value string) {
	t.Helper()
	if m == nil || m.Name == nil || m.Value == nil || m.IsRegex == nil || m.IsEqual == nil {
		t.Fatalf("incomplete matcher %#v", m)
	}
	if *m.Name != name || *m.Value != value || *m.IsRegex || !*m.IsEqual {
		t.Fatalf("name %q value %q regex %v equal %v", *m.Name, *m.Value, *m.IsRegex, *m.IsEqual)
	}
}

func sameMatcherList(a, b models.Matchers) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !sameMatcher(a[i], b[i]) {
			return false
		}
	}
	return true
}

func sameMatcher(a, b *models.Matcher) bool {
	if a == nil || b == nil {
		return a == b
	}
	return strEq(a.Name, b.Name) && strEq(a.Value, b.Value) && boolEq(a.IsRegex, b.IsRegex) && boolEq(a.IsEqual, b.IsEqual)
}

func strEq(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func boolEq(a, b *bool) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func matcherDump(ms models.Matchers) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		raw, _ := json.Marshal(m)
		out = append(out, string(raw))
	}
	return out
}
