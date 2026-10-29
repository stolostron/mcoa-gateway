//go:build integration

package e2e

import (
	"context"
	"net/http"
	"sort"
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
)

func TestAlertmanagerApiProxy(t *testing.T) {
	t.Parallel()

	e, err := e2e.New(e2e.WithName(uniqueE2ENetworkName(t)))
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	prepareConfigsAndCerts(t, e)
	_, token, rateLimiterAddr := startBaseServices(t, e)
	alertmanagerEndpoint := newAlertmanagerService(e)
	readEndpoint, writeEndpoint, _ := startServicesForMetrics(t, e)
	testutil.Ok(t, e2e.StartAndWaitReady(alertmanagerEndpoint))

	api, err := newObservatoriumAPIService(
		e,
		withMetricsEndpoints("http://"+readEndpoint, "http://"+writeEndpoint),
		withAlertmanagerEndpoint("http://"+alertmanagerEndpoint.InternalEndpoint("http")),
		withRateLimiter(rateLimiterAddr),
	)
	testutil.Ok(t, err)
	testutil.Ok(t, e2e.StartAndWaitReady(api))

	authClient := &http.Client{
		Transport: &authRoundTripper{
			rt: &http.Transport{
				TLSClientConfig: getTLSClientConfig(t, e),
			},
			token:        token,
			tenantHeader: metricsTenantHeader,
			tenant:       defaultTenantName,
		},
	}

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
