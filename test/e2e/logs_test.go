//go:build integration

package e2e

import (
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

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
	_, token, rateLimiterAddr := startBaseServices(t, e)
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
			e, "up-logs-oidc", logs,
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

		testutil.Ok(t, up.WaitSumMetricsWithOptions(
			e2emon.GreaterOrEqual(12),
			[]string{"up_remote_writes_total"},
			e2emon.WithLabelMatchers(
				matchers.MustNewMatcher(matchers.MatchEqual, "result", "success"),
			),
			e2emon.WaitMissingMetrics(),
		))
		testutil.Ok(t, up2.WaitSumMetricsWithOptions(
			e2emon.GreaterOrEqual(12),
			[]string{"up_remote_writes_total"},
			e2emon.WithLabelMatchers(
				matchers.MustNewMatcher(matchers.MatchEqual, "result", "success"),
			),
			e2emon.WaitMissingMetrics(),
		))
		testutil.Ok(t, up.Kill())
		testutil.Ok(t, up2.Kill())

		// Write-path check: Loki orgs match cert OUs.
		assertLokiQuery(t, logsExtEndpoint, defaultTenantName, `{_id="test"}`,
			`"tenant_id":"`+defaultTenantName+`"`, "log line 1")
		assertLokiQuery(t, logsExtEndpoint, anotherTenantName, `{_id="test-another"}`,
			`"tenant_id":"`+anotherTenantName+`"`, "log line 1")
		// Cross-org: default tenant's org must not see the other tenant's stream.
		assertLokiQueryEmpty(t, logsExtEndpoint, defaultTenantName, `{_id="test-another"}`)

		tr := &http.Transport{TLSClientConfig: getTLSClientConfig(t, e)}
		oidcClient := &http.Client{Transport: &authRoundTripper{
			rt: tr, token: token, tenantHeader: logsTenantHeader, tenant: defaultTenantName,
		}}
		anotherClient := &http.Client{Transport: &authRoundTripper{
			rt: tr, token: token, tenantHeader: logsTenantHeader, tenant: anotherTenantName,
		}}
		attackerClient := &http.Client{Transport: &authRoundTripper{
			rt: tr, token: token, tenantHeader: logsTenantHeader, tenant: "test-attacker",
		}}

		// Read-path through the gateway: LogQL enforcer + Loki org scoping.
		assertGatewayLogsQuery(t, oidcClient, gatewayQuery, `{_id="test"}`,
			`"tenant_id":"`+defaultTenantName+`"`, "log line 1")
		assertGatewayLogsQuery(t, anotherClient, gatewayQuery, `{_id="test-another"}`,
			`"tenant_id":"`+anotherTenantName+`"`, "log line 1")
		assertGatewayLogsQueryEmpty(t, oidcClient, gatewayQuery, `{_id="test-another"}`)
		assertGatewayLogsQueryEmpty(t, anotherClient, gatewayQuery, `{_id="test"}`)
		assertGatewayLogsQueryEmpty(t, attackerClient, gatewayQuery, `{_id="test"}`)
	})

	t.Run("tail-write", func(t *testing.T) {
		up, err := newUpRun(
			e, "up-logs-tail", logs,
			lokiRead,
			gatewayPush,
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

		d := websocket.Dialer{TLSClientConfig: getTLSClientConfig(t, e)}
		conn, resp, err := d.Dial(
			"wss://"+api.Endpoint("https")+"/api/logs/v1/loki/api/v1/tail?query=%7B_id%3D%22test%22%7D",
			http.Header{
				"Authorization":  []string{"Bearer " + token},
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
