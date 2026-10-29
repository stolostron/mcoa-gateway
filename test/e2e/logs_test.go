//go:build integration

package e2e

import (
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	e2emon "github.com/efficientgo/e2e/monitoring"
	"github.com/efficientgo/e2e/monitoring/matchers"

	"github.com/efficientgo/core/testutil"
	"github.com/efficientgo/e2e"
	"github.com/gorilla/websocket"
)

func TestLogs(t *testing.T) {
	t.Parallel()

	e, err := e2e.New(e2e.WithName(uniqueE2ENetworkName(t)))
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	prepareConfigsAndCerts(t, e)
	rateLimiterAddr := startBaseServices(t, e)
	logsEndpoint, logsExtEndpoint := startServicesForLogs(t, e)

	api, err := newObservatoriumAPIService(
		e,
		withLogsEndpoints("http://"+logsEndpoint),
		withRateLimiter(rateLimiterAddr),
	)
	testutil.Ok(t, err)
	testutil.Ok(t, e2e.StartAndWaitReady(api))

	gatewayPush := "https://" + api.InternalEndpoint("https") + "/api/logs/v1/loki/api/v1/push"
	gatewayQuery := "https://" + api.Endpoint("https") + "/api/logs/v1/loki/api/v1/query"
	// up reads Loki directly; write path is what we verify through the gateway.
	lokiRead := "http://" + logsEndpoint

	t.Run("write-two-tenants-then-read", func(t *testing.T) {
		up, err := newUpRun(
			e, "up-logs-default", logs,
			lokiRead,
			gatewayPush,
			withClientCert(
				filepath.Join(e.SharedDir(), certsSharedDir, "client.pem"),
				filepath.Join(e.SharedDir(), certsSharedDir, "client.key"),
			),
			withLabels(`_id="test",tenant_id="`+defaultTenantName+`"`),
			withRunParameters(&runParams{initialDelay: "100ms", period: "1s", threshold: "1", latency: "10s", duration: "0"}),
		)
		testutil.Ok(t, err)
		testutil.Ok(t, e2e.StartAndWaitReady(up))

		up2, err := newUpRun(
			e, "up-logs-another", logs,
			lokiRead,
			gatewayPush,
			withClientCert(
				filepath.Join(e.SharedDir(), certsSharedDir, "client-another-tenant.pem"),
				filepath.Join(e.SharedDir(), certsSharedDir, "client-another-tenant.key"),
			),
			withLabels(`_id="test-another",tenant_id="`+anotherTenantName+`"`),
			withRunParameters(&runParams{initialDelay: "100ms", period: "1s", threshold: "1", latency: "10s", duration: "0"}),
		)
		testutil.Ok(t, err)
		testutil.Ok(t, e2e.StartAndWaitReady(up2))

		upMTLS, err := newUpRun(
			e, "up-logs-mtls", logs,
			lokiRead,
			gatewayPush,
			withClientCert(
				filepath.Join(e.SharedDir(), certsSharedDir, "client-mtls.pem"),
				filepath.Join(e.SharedDir(), certsSharedDir, "client-mtls.key"),
			),
			withLabels(`_id="test-mtls",tenant_id="`+mtlsTenantName+`"`),
			withRunParameters(&runParams{initialDelay: "100ms", period: "1s", threshold: "1", latency: "10s", duration: "0"}),
		)
		testutil.Ok(t, err)
		testutil.Ok(t, e2e.StartAndWaitReady(upMTLS))

		for _, u := range []*e2emon.InstrumentedRunnable{up, up2, upMTLS} {
			testutil.Ok(t, u.WaitSumMetricsWithOptions(
				e2emon.GreaterOrEqual(12),
				[]string{"up_remote_writes_total"},
				e2emon.WithLabelMatchers(
					matchers.MustNewMatcher(matchers.MatchEqual, "result", "success"),
				),
				e2emon.WaitMissingMetrics(),
			))
		}
		testutil.Ok(t, up.Kill())
		testutil.Ok(t, up2.Kill())
		testutil.Ok(t, upMTLS.Kill())

		// Write-path check: Loki orgs match cert OUs.
		assertLokiQuery(t, logsExtEndpoint, defaultTenantName, `{_id="test"}`,
			`"tenant_id":"`+defaultTenantName+`"`, "log line 1")
		assertLokiQuery(t, logsExtEndpoint, anotherTenantName, `{_id="test-another"}`,
			`"tenant_id":"`+anotherTenantName+`"`, "log line 1")
		assertLokiQuery(t, logsExtEndpoint, mtlsTenantName, `{_id="test-mtls"}`,
			`"tenant_id":"`+mtlsTenantName+`"`, "log line 1")
		// Cross-org: default tenant's org must not see the other tenant's stream.
		assertLokiQueryEmpty(t, logsExtEndpoint, defaultTenantName, `{_id="test-another"}`)

		defaultClient := newMTLSAuthClient(t, e, logsTenantHeader, defaultTenantName, "client.pem", "client.key")
		anotherClient := newMTLSAuthClient(t, e, logsTenantHeader, anotherTenantName, "client-another-tenant.pem", "client-another-tenant.key")
		mtlsClient := newMTLSAuthClient(t, e, logsTenantHeader, mtlsTenantName, "client-mtls.pem", "client-mtls.key")
		attackerClient := newMTLSAuthClient(t, e, logsTenantHeader, "test-attacker", "client-attacker.pem", "client-attacker.key")

		// Read-path through the gateway: mTLS auth + LogQL enforcer + Loki org scoping.
		assertGatewayLogsQuery(t, defaultClient, gatewayQuery, `{_id="test"}`,
			`"tenant_id":"`+defaultTenantName+`"`, "log line 1")
		assertGatewayLogsQuery(t, anotherClient, gatewayQuery, `{_id="test-another"}`,
			`"tenant_id":"`+anotherTenantName+`"`, "log line 1")
		assertGatewayLogsQuery(t, mtlsClient, gatewayQuery, `{_id="test-mtls"}`,
			`"tenant_id":"`+mtlsTenantName+`"`, "log line 1")
		assertGatewayLogsQueryEmpty(t, defaultClient, gatewayQuery, `{_id="test-another"}`)
		assertGatewayLogsQueryEmpty(t, anotherClient, gatewayQuery, `{_id="test"}`)
		assertGatewayLogsQueryEmpty(t, mtlsClient, gatewayQuery, `{_id="test"}`)
		assertGatewayLogsQueryEmpty(t, attackerClient, gatewayQuery, `{_id="test"}`)

		gatewayQueryRange := "https://" + api.Endpoint("https") + "/api/logs/v1/loki/api/v1/query_range"
		t.Run("query_shapes", func(t *testing.T) {
			for _, tc := range []struct {
				name      string
				query     string
				metric    bool // LogQL metric query (vector/matrix), not log streams
				want      []string
				wantEmpty bool
			}{
				{
					name:  "stream_equality",
					query: `{_id="test"}`,
					want:  []string{`"tenant_id":"` + defaultTenantName + `"`, "log line 1"},
				},
				{
					name:  "stream_regex",
					query: `{_id=~"tes.*"}`,
					want:  []string{`"tenant_id":"` + defaultTenantName + `"`, "log line 1"},
				},
				{
					name:  "line_filter_contains",
					query: `{_id="test"} |= "log line"`,
					want:  []string{"log line 1"},
				},
				{
					name:  "line_filter_regex",
					query: `{_id="test"} |~ "log line [0-9]+"`,
					want:  []string{"log line 1"},
				},
				{
					name:  "line_filter_not_contains",
					query: `{_id="test"} != "nomatch"`,
					want:  []string{"log line 1"},
				},
				{
					name:      "line_filter_excludes_all",
					query:     `{_id="test"} |= "nomatch"`,
					wantEmpty: true,
				},
				{
					name:   "count_over_time",
					query:  `count_over_time({_id="test"}[5m])`,
					metric: true,
					want:   []string{`"status":"success"`, `"resultType":"vector"`},
				},
				{
					name:   "rate",
					query:  `rate({_id="test"}[5m])`,
					metric: true,
					want:   []string{`"status":"success"`, `"resultType":"vector"`},
				},
				{
					name:      "cross_tenant_stream",
					query:     `{_id="test-another"}`,
					wantEmpty: true,
				},
			} {
				t.Run(tc.name, func(t *testing.T) {
					body := doLokiQuery(t, defaultClient, gatewayQuery, "", tc.query)
					if tc.wantEmpty {
						testutil.Assert(t, !strings.Contains(body, "log line 1"), "unexpected data for %s: %s", tc.query, body)
						return
					}
					for _, w := range tc.want {
						assertResponse(t, body, w)
					}
					if tc.metric {
						testutil.Assert(t, strings.Contains(body, `"result":[{`), "expected non-empty metric result for %s: %s", tc.query, body)
					}
					testutil.Assert(t, !strings.Contains(body, anotherTenantName), "leaked other tenant in %s", body)
				})
			}

			t.Run("query_range_stream", func(t *testing.T) {
				end := time.Now()
				start := end.Add(-5 * time.Minute)
				body := doLokiQueryRange(t, defaultClient, gatewayQueryRange, `{_id="test"}`, start, end)
				assertResponse(t, body, `"status":"success"`)
				assertResponse(t, body, "log line 1")
				assertResponse(t, body, `"tenant_id":"`+defaultTenantName+`"`)
			})

			t.Run("query_range_metric", func(t *testing.T) {
				end := time.Now()
				start := end.Add(-5 * time.Minute)
				body := doLokiQueryRange(t, defaultClient, gatewayQueryRange, `count_over_time({_id="test"}[1m])`, start, end)
				assertResponse(t, body, `"status":"success"`)
				assertResponse(t, body, `"resultType":"matrix"`)
				testutil.Assert(t, strings.Contains(body, `"result":[{`), "expected matrix samples: %s", body)
			})

			t.Run("post_form_query", func(t *testing.T) {
				form := url.Values{"query": {`{_id="test"}`}, "limit": {"10"}}
				body := doLokiQueryPOST(t, defaultClient, gatewayQuery, form)
				assertResponse(t, body, "log line 1")
				assertResponse(t, body, `"tenant_id":"`+defaultTenantName+`"`)
			})

			t.Run("post_body_params_url_query", func(t *testing.T) {
				// Selector in URL, other params in body — body must not invent a
				// tenant-only query that overrides the URL selector.
				form := url.Values{"limit": {"5"}}
				body := doLokiQueryPOSTWithURLQuery(t, defaultClient, gatewayQuery, `{_id="test"}`, form)
				assertResponse(t, body, "log line 1")
				assertResponse(t, body, `"tenant_id":"`+defaultTenantName+`"`)
			})
		})

		noCertClient := &http.Client{Transport: &authRoundTripper{
			rt:           &http.Transport{TLSClientConfig: getTLSClientConfig(t, e)},
			tenantHeader: logsTenantHeader,
			tenant:       defaultTenantName,
		}}
		status := logsQueryStatus(t, noCertClient, gatewayQuery, `{_id="test"}`)
		testutil.Equals(t, http.StatusUnauthorized, status)
	})

	t.Run("tail-write", func(t *testing.T) {
		up, err := newUpRun(
			e, "up-logs-tail", logs,
			lokiRead,
			gatewayPush,
			withClientCert(
				filepath.Join(e.SharedDir(), certsSharedDir, "client.pem"),
				filepath.Join(e.SharedDir(), certsSharedDir, "client.key"),
			),
			withLabels(`_id="test",tenant_id="`+defaultTenantName+`"`),
			withRunParameters(&runParams{initialDelay: "0s", period: "250ms", threshold: "1", latency: "10s", duration: "0"}),
		)
		testutil.Ok(t, err)
		testutil.Ok(t, e2e.StartAndWaitReady(up))

		testutil.Ok(t, up.WaitSumMetricsWithOptions(
			e2emon.GreaterOrEqual(5),
			[]string{"up_remote_writes_total"},
			e2emon.WithLabelMatchers(
				matchers.MustNewMatcher(matchers.MatchEqual, "result", "success"),
			),
			e2emon.WaitMissingMetrics(),
		))
		testutil.Ok(t, up.Stop())

		d := websocket.Dialer{TLSClientConfig: getTLSClientConfigWithClientCert(t, e, "client.pem", "client.key")}
		conn, resp, err := d.Dial(
			"wss://"+api.Endpoint("https")+"/api/logs/v1/loki/api/v1/tail?query=%7B_id%3D%22test%22%7D",
			http.Header{
				logsTenantHeader: []string{defaultTenantName},
			},
		)
		testutil.Ok(t, err)
		if resp != nil && resp.Body != nil {
			defer resp.Body.Close()
		}
		defer conn.Close()

		_, message, err := conn.ReadMessage()
		testutil.Ok(t, err)
		messageStr := string(message)
		assertResponse(t, messageStr, `"__name__":"observatorium_write"`)
		assertResponse(t, messageStr, `"_id":"test"`)
		assertResponse(t, messageStr, "log line 1")
	})
}

func assertLokiQuery(t *testing.T, logsExtEndpoint, org, query string, want ...string) {
	t.Helper()
	body := doLokiQuery(t, http.DefaultClient, "http://"+logsExtEndpoint+"/loki/api/v1/query", org, query)
	for _, w := range want {
		assertResponse(t, body, w)
	}
}

func assertLokiQueryEmpty(t *testing.T, logsExtEndpoint, org, query string) {
	t.Helper()
	body := doLokiQuery(t, http.DefaultClient, "http://"+logsExtEndpoint+"/loki/api/v1/query", org, query)
	testutil.Assert(t, !strings.Contains(body, "log line 1"), "org %s unexpectedly saw data for %s: %s", org, query, body)
}

func assertGatewayLogsQuery(t *testing.T, client *http.Client, gatewayQuery, query string, want ...string) {
	t.Helper()
	body := doLokiQuery(t, client, gatewayQuery, "", query)
	for _, w := range want {
		assertResponse(t, body, w)
	}
}

func assertGatewayLogsQueryEmpty(t *testing.T, client *http.Client, gatewayQuery, query string) {
	t.Helper()
	body := doLokiQuery(t, client, gatewayQuery, "", query)
	testutil.Assert(t, !strings.Contains(body, "log line 1"), "gateway query unexpectedly returned data for %s: %s", query, body)
}

func doLokiQuery(t *testing.T, client *http.Client, endpoint, org, query string) string {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, endpoint, nil)
	testutil.Ok(t, err)
	v := url.Values{}
	v.Add("query", query)
	r.URL.RawQuery = v.Encode()
	if org != "" {
		r.Header.Set(logsTenantHeader, org)
	}
	res, err := client.Do(r)
	testutil.Ok(t, err)
	defer res.Body.Close()
	testutil.Assert(t, res.StatusCode == http.StatusOK, "status %d", res.StatusCode)
	body, err := io.ReadAll(res.Body)
	testutil.Ok(t, err)
	return string(body)
}

func doLokiQueryRange(t *testing.T, client *http.Client, endpoint, query string, start, end time.Time) string {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, endpoint, nil)
	testutil.Ok(t, err)
	v := url.Values{}
	v.Set("query", query)
	v.Set("start", strconv.FormatInt(start.UnixNano(), 10))
	v.Set("end", strconv.FormatInt(end.UnixNano(), 10))
	v.Set("limit", "100")
	r.URL.RawQuery = v.Encode()
	res, err := client.Do(r)
	testutil.Ok(t, err)
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	testutil.Ok(t, err)
	testutil.Assert(t, res.StatusCode == http.StatusOK, "status %d body %s", res.StatusCode, body)
	return string(body)
}

func doLokiQueryPOST(t *testing.T, client *http.Client, endpoint string, form url.Values) string {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	testutil.Ok(t, err)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := client.Do(r)
	testutil.Ok(t, err)
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	testutil.Ok(t, err)
	testutil.Assert(t, res.StatusCode == http.StatusOK, "status %d body %s", res.StatusCode, body)
	return string(body)
}

func doLokiQueryPOSTWithURLQuery(t *testing.T, client *http.Client, endpoint, query string, form url.Values) string {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	testutil.Ok(t, err)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	v := url.Values{"query": {query}}
	r.URL.RawQuery = v.Encode()
	res, err := client.Do(r)
	testutil.Ok(t, err)
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	testutil.Ok(t, err)
	testutil.Assert(t, res.StatusCode == http.StatusOK, "status %d body %s", res.StatusCode, body)
	return string(body)
}

func logsQueryStatus(t *testing.T, client *http.Client, endpoint, query string) int {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, endpoint, nil)
	testutil.Ok(t, err)
	v := url.Values{}
	v.Add("query", query)
	r.URL.RawQuery = v.Encode()
	res, err := client.Do(r)
	testutil.Ok(t, err)
	defer res.Body.Close()
	return res.StatusCode
}
