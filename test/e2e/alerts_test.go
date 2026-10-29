//go:build integration

package e2e

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-openapi/strfmt"

	"github.com/prometheus/alertmanager/api/v2/models"

	httptransport "github.com/go-openapi/runtime/client"
	client2 "github.com/prometheus/alertmanager/api/v2/client"
	"github.com/prometheus/alertmanager/api/v2/client/alert"
	"github.com/prometheus/alertmanager/api/v2/client/silence"

	"github.com/efficientgo/core/testutil"
	"github.com/efficientgo/e2e"
	e2emon "github.com/efficientgo/e2e/monitoring"
)

func TestAlertmanagerApiProxy(t *testing.T) {
	t.Parallel()

	e, err := e2e.New(e2e.WithName(uniqueE2ENetworkName(t)))
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	prepareConfigsAndCerts(t, e)
	rateLimiterAddr := startBaseServices(t, e)
	alertmanagerEndpoint := newAlertmanagerService(e)
	readEndpoint, writeEndpoint, _ := startServicesForMetrics(t, e)
	testutil.Ok(t, e2e.StartAndWaitReady(alertmanagerEndpoint))

	amURL := "http://" + alertmanagerEndpoint.InternalEndpoint("http")
	api, err := newObservatoriumAPIService(
		e,
		withMetricsEndpoints("http://"+readEndpoint, "http://"+writeEndpoint),
		withAlertmanagerEndpoint(amURL),
		// Same replica for fanout writes so POST /api/alertmanager/v2 is enabled
		// alongside the metrics AM read proxy.
		withAlertmanagerFanoutEndpoints(amURL),
		withRateLimiter(rateLimiterAddr),
	)
	testutil.Ok(t, err)
	testutil.Ok(t, e2e.StartAndWaitReady(api))

	authClient := newMTLSAuthClient(t, e, metricsTenantHeader, defaultTenantName, "client.pem", "client.key")
	// Fanout writes authenticate via client cert OU (no tenant header required).
	fanoutClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: getTLSClientConfigWithClientCert(t, e, "client.pem", "client.key"),
	}}

	t.Run("alerts-check-then-write-then-read", func(t *testing.T) {
		runtime := httptransport.New(api.Endpoint("https"), "/api/metrics/v1/am"+client2.DefaultBasePath, []string{"https"})
		tenantAlertmanagerClient := alert.New(runtime, strfmt.Default)

		runtimeYolo := httptransport.New(alertmanagerEndpoint.Endpoint("http"), client2.DefaultBasePath, []string{"http"})
		adminAlertmanagerClient := alert.New(runtimeYolo, strfmt.Default)

		alertsResult, err := adminAlertmanagerClient.GetAlerts(
			&alert.GetAlertsParams{
				Context:    testContextWithTimeout(t),
				HTTPClient: http.DefaultClient,
			},
		)
		testutil.Ok(t, err)
		testutil.Equals(t, 0, len(alertsResult.Payload))

		ok, err := adminAlertmanagerClient.PostAlerts(
			&alert.PostAlertsParams{
				Context:    testContextWithTimeout(t),
				HTTPClient: http.DefaultClient,
				Alerts: []*models.PostableAlert{
					{
						Annotations: models.LabelSet{"test": "true"},
						StartsAt:    strfmt.DateTime(time.Now().Add(-time.Minute)),
						EndsAt:      strfmt.DateTime(time.Now().Add(time.Hour)),
						Alert: models.Alert{
							Labels: models.LabelSet{
								"alertname": "test-alert-tenant-a",
								"severity":  "critical",
								"tenant_id": defaultTenantName,
							},
							GeneratorURL: "http://localhost",
						},
					},
					{
						Annotations: models.LabelSet{"test": "true"},
						StartsAt:    strfmt.DateTime(time.Now().Add(-time.Minute)),
						EndsAt:      strfmt.DateTime(time.Now().Add(time.Hour)),
						Alert: models.Alert{
							Labels: models.LabelSet{
								"alertname": "test-alert-tenant-a-warn",
								"severity":  "warning",
								"tenant_id": defaultTenantName,
							},
							GeneratorURL: "http://localhost",
						},
					},
					{
						Annotations: models.LabelSet{"test": "true"},
						StartsAt:    strfmt.DateTime(time.Now().Add(-time.Minute)),
						EndsAt:      strfmt.DateTime(time.Now().Add(time.Hour)),
						Alert: models.Alert{
							Labels: models.LabelSet{
								"alertname": "test-alert-tenant-b",
								"severity":  "critical",
								"tenant_id": "tenant-b",
							},
							GeneratorURL: "http://localhost",
						},
					},
				},
			},
		)
		testutil.Ok(t, err)
		testutil.Equals(t, ok.IsSuccess(), true)

		alertsResult, err = adminAlertmanagerClient.GetAlerts(
			&alert.GetAlertsParams{
				Context:    testContextWithTimeout(t),
				HTTPClient: http.DefaultClient,
			},
		)
		testutil.Ok(t, err)
		testutil.Assert(t, len(alertsResult.Payload) == 3, "expected 3 alerts, got %d", len(alertsResult.Payload))

		alertsResult, err = tenantAlertmanagerClient.GetAlerts(
			&alert.GetAlertsParams{
				Context:    testContextWithTimeout(t),
				HTTPClient: authClient,
			},
		)
		testutil.Ok(t, err)
		testutil.Assert(t, len(alertsResult.Payload) == 2, "expected 2 alerts, got %d", len(alertsResult.Payload))

		names := []string{alertsResult.Payload[0].Labels["alertname"], alertsResult.Payload[1].Labels["alertname"]}
		sort.Strings(names)
		testutil.Equals(t, []string{"test-alert-tenant-a", "test-alert-tenant-a-warn"}, names)
	})

	t.Run("silence-check-then-write-then-read", func(t *testing.T) {
		runtime := httptransport.New(api.Endpoint("https"), "/api/metrics/v1/am"+client2.DefaultBasePath, []string{"https"})
		tenantSilenceClient := silence.New(runtime, strfmt.Default)

		runtimeYolo := httptransport.New(alertmanagerEndpoint.Endpoint("http"), client2.DefaultBasePath, []string{"http"})
		adminSilenceClient := silence.New(runtimeYolo, strfmt.Default)
		adminAlertClient := alert.New(runtimeYolo, strfmt.Default)

		silenceResult, err := adminSilenceClient.GetSilences(
			&silence.GetSilencesParams{
				Context:    testContextWithTimeout(t),
				HTTPClient: http.DefaultClient,
			},
		)
		testutil.Ok(t, err)
		testutil.Equals(t, 0, len(silenceResult.Payload))

		// Match critical alerts; tenancy enforcer injects tenant_id=test-oidc so only
		// that tenant's critical alert is silenced. startsAt is in the past so the
		// silence is active even if the Alertmanager clock lags the test host.
		ok, err := tenantSilenceClient.PostSilences(
			&silence.PostSilencesParams{
				Silence: &models.PostableSilence{
					Silence: models.Silence{
						CreatedBy: toStrPtr(t, "test"),
						Comment:   toStrPtr(t, "test"),
						StartsAt:  toDateTimePtr(t, time.Now().Add(-time.Minute)),
						EndsAt:    toDateTimePtr(t, time.Now().Add(time.Hour)),
						Matchers: []*models.Matcher{
							{
								IsEqual: toBoolPtr(t, true),
								IsRegex: toBoolPtr(t, false),
								Name:    toStrPtr(t, "severity"),
								Value:   toStrPtr(t, "critical"),
							},
						},
					},
				},
				Context:    testContextWithTimeout(t),
				HTTPClient: authClient,
			},
		)
		testutil.Ok(t, err)
		testutil.Equals(t, ok.IsSuccess(), true)

		alertsResult, err := adminAlertClient.GetAlerts(
			&alert.GetAlertsParams{
				Context:    testContextWithTimeout(t),
				HTTPClient: http.DefaultClient,
			},
		)
		testutil.Ok(t, err)
		testutil.Assert(t, len(alertsResult.Payload) == 3, "expected 3 alerts, got %d", len(alertsResult.Payload))

		var silencedNames []string
		for _, a := range alertsResult.Payload {
			if len(a.Status.SilencedBy) > 0 {
				silencedNames = append(silencedNames, a.Labels["alertname"])
			}
		}
		testutil.Equals(t, []string{"test-alert-tenant-a"}, silencedNames)

		ok, err = adminSilenceClient.PostSilences(
			&silence.PostSilencesParams{
				Silence: &models.PostableSilence{
					Silence: models.Silence{
						CreatedBy: toStrPtr(t, "admin"),
						Comment:   toStrPtr(t, "admin"),
						StartsAt:  toDateTimePtr(t, time.Now().Add(-time.Minute)),
						EndsAt:    toDateTimePtr(t, time.Now().Add(time.Hour)),
						Matchers: []*models.Matcher{
							{
								IsEqual: toBoolPtr(t, true),
								IsRegex: toBoolPtr(t, false),
								Name:    toStrPtr(t, "severity"),
								Value:   toStrPtr(t, "critical"),
							},
						},
					},
				},
				Context:    testContextWithTimeout(t),
				HTTPClient: http.DefaultClient,
			},
		)
		testutil.Ok(t, err)
		testutil.Equals(t, ok.IsSuccess(), true)

		adminSilenceResult, err := adminSilenceClient.GetSilences(
			&silence.GetSilencesParams{
				Context:    testContextWithTimeout(t),
				HTTPClient: http.DefaultClient,
			},
		)
		testutil.Ok(t, err)
		testutil.Equals(t, 2, len(adminSilenceResult.Payload))

		tenantSilenceResult, err := tenantSilenceClient.GetSilences(
			&silence.GetSilencesParams{
				Context:    testContextWithTimeout(t),
				HTTPClient: authClient,
			},
		)
		testutil.Ok(t, err)
		testutil.Equals(t, 1, len(tenantSilenceResult.Payload))
	})

	t.Run("alerts-requires-client-cert", func(t *testing.T) {
		noCertClient := &http.Client{Transport: &authRoundTripper{
			rt: &http.Transport{
				TLSClientConfig: getTLSClientConfig(t, e),
			},
			tenantHeader: metricsTenantHeader,
			tenant:       defaultTenantName,
		}}
		req, err := http.NewRequest(http.MethodGet, "https://"+api.Endpoint("https")+"/api/metrics/v1/am/api/v2/alerts", nil)
		testutil.Ok(t, err)
		res, err := noCertClient.Do(req)
		testutil.Ok(t, err)
		defer res.Body.Close()
		testutil.Equals(t, http.StatusUnauthorized, res.StatusCode)
	})

	t.Run("fanout-write-then-tenant-read", func(t *testing.T) {
		// Write through the fanout path (mTLS OU → tenant ID header), then read
		// through the metrics AM proxy which enforces tenant_id matchers.
		fanoutRuntime := httptransport.New(api.Endpoint("https"), "/api/alertmanager/v2"+client2.DefaultBasePath, []string{"https"})
		fanoutAlertClient := alert.New(fanoutRuntime, strfmt.Default)

		ok, err := fanoutAlertClient.PostAlerts(
			&alert.PostAlertsParams{
				Context:    testContextWithTimeout(t),
				HTTPClient: fanoutClient,
				Alerts: []*models.PostableAlert{
					{
						Annotations: models.LabelSet{"test": "fanout"},
						StartsAt:    strfmt.DateTime(time.Now().Add(-time.Minute)),
						EndsAt:      strfmt.DateTime(time.Now().Add(time.Hour)),
						Alert: models.Alert{
							Labels: models.LabelSet{
								"alertname": "fanout-alert-tenant-a",
								"severity":  "warning",
								"tenant_id": defaultTenantName,
							},
							GeneratorURL: "http://localhost",
						},
					},
				},
			},
		)
		testutil.Ok(t, err)
		testutil.Equals(t, ok.IsSuccess(), true)

		readRuntime := httptransport.New(api.Endpoint("https"), "/api/metrics/v1/am"+client2.DefaultBasePath, []string{"https"})
		tenantAlertClient := alert.New(readRuntime, strfmt.Default)
		alertsResult, err := tenantAlertClient.GetAlerts(
			&alert.GetAlertsParams{
				Context:    testContextWithTimeout(t),
				HTTPClient: authClient,
			},
		)
		testutil.Ok(t, err)

		var found bool
		for _, a := range alertsResult.Payload {
			if a.Labels["alertname"] == "fanout-alert-tenant-a" {
				found = true
				testutil.Equals(t, defaultTenantName, a.Labels["tenant_id"])
			}
		}
		testutil.Assert(t, found, "fanout-written alert not visible via tenant read: %v", alertsResult.Payload)
	})

	t.Run("fanout-requires-client-cert", func(t *testing.T) {
		noCertClient := &http.Client{Transport: &http.Transport{
			TLSClientConfig: getTLSClientConfig(t, e),
		}}
		req, err := http.NewRequest(
			http.MethodPost,
			"https://"+api.Endpoint("https")+"/api/alertmanager/v2/api/v2/alerts",
			strings.NewReader(`[]`),
		)
		testutil.Ok(t, err)
		req.Header.Set("Content-Type", "application/json")
		res, err := noCertClient.Do(req)
		testutil.Ok(t, err)
		defer res.Body.Close()
		testutil.Equals(t, http.StatusUnauthorized, res.StatusCode)
	})
}

func TestAlertmanagerFanoutReplicas(t *testing.T) {
	t.Parallel()

	e, err := e2e.New(e2e.WithName(uniqueE2ENetworkName(t)))
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	prepareConfigsAndCerts(t, e)
	rateLimiterAddr := startBaseServices(t, e)
	am1 := newNamedAlertmanagerService(e, "alertmanager-a")
	am2 := newNamedAlertmanagerService(e, "alertmanager-b")
	readEndpoint, writeEndpoint, _ := startServicesForMetrics(t, e)
	testutil.Ok(t, e2e.StartAndWaitReady(am1, am2))

	am1URL := "http://" + am1.InternalEndpoint("http")
	am2URL := "http://" + am2.InternalEndpoint("http")
	api, err := newObservatoriumAPIService(
		e,
		withMetricsEndpoints("http://"+readEndpoint, "http://"+writeEndpoint),
		withAlertmanagerEndpoint(am1URL),
		withAlertmanagerFanoutEndpoints(am1URL, am2URL),
		withAlertmanagerAccessorToken("e2e-accessor-token"),
		withRateLimiter(rateLimiterAddr),
	)
	testutil.Ok(t, err)
	testutil.Ok(t, e2e.StartAndWaitReady(api))

	fanoutClient := &http.Client{Transport: &http.Transport{
		TLSClientConfig: getTLSClientConfigWithClientCert(t, e, "client.pem", "client.key"),
	}}
	fanoutRuntime := httptransport.New(api.Endpoint("https"), "/api/alertmanager/v2"+client2.DefaultBasePath, []string{"https"})
	fanoutAlertClient := alert.New(fanoutRuntime, strfmt.Default)

	ok, err := fanoutAlertClient.PostAlerts(
		&alert.PostAlertsParams{
			Context:    testContextWithTimeout(t),
			HTTPClient: fanoutClient,
			Alerts: []*models.PostableAlert{
				{
					Annotations: models.LabelSet{"test": "fanout-replicas"},
					StartsAt:    strfmt.DateTime(time.Now().Add(-time.Minute)),
					EndsAt:      strfmt.DateTime(time.Now().Add(time.Hour)),
					Alert: models.Alert{
						Labels: models.LabelSet{
							"alertname": "fanout-replica-alert",
							"severity":  "critical",
							"tenant_id": defaultTenantName,
						},
						GeneratorURL: "http://localhost",
					},
				},
			},
		},
	)
	testutil.Ok(t, err)
	testutil.Equals(t, ok.IsSuccess(), true)

	for _, am := range []*e2emon.InstrumentedRunnable{am1, am2} {
		adminRuntime := httptransport.New(am.Endpoint("http"), client2.DefaultBasePath, []string{"http"})
		adminClient := alert.New(adminRuntime, strfmt.Default)
		alertsResult, err := adminClient.GetAlerts(
			&alert.GetAlertsParams{
				Context:    testContextWithTimeout(t),
				HTTPClient: http.DefaultClient,
			},
		)
		testutil.Ok(t, err)
		testutil.Assert(t, len(alertsResult.Payload) >= 1, "replica %s missing fanout alert: %v", am.Name(), alertsResult.Payload)
		testutil.Equals(t, "fanout-replica-alert", alertsResult.Payload[0].Labels["alertname"])
	}
}

func testContextWithTimeout(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func toStrPtr(t *testing.T, s string) *string {
	t.Helper()
	return &s
}

func toDateTimePtr(t *testing.T, time time.Time) *strfmt.DateTime {
	t.Helper()
	dt := strfmt.DateTime(time)
	return &dt
}

func toBoolPtr(t *testing.T, b bool) *bool {
	t.Helper()
	return &b
}
