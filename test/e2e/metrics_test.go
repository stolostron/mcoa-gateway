//go:build integration

package e2e

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	e2emon "github.com/efficientgo/e2e/monitoring"
	"github.com/efficientgo/e2e/monitoring/matchers"

	"github.com/efficientgo/core/testutil"
	"github.com/efficientgo/e2e"
	promapi "github.com/prometheus/client_golang/api"
	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"
)

func TestMetricsReadAndWrite(t *testing.T) {
	t.Parallel()

	e, err := e2e.New(e2e.WithName(uniqueE2ENetworkName(t)))
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	prepareConfigsAndCerts(t, e)
	rateLimiterAddr := startBaseServices(t, e)
	readEndpoint, writeEndpoint, readExtEndpoint := startServicesForMetrics(t, e)

	api, err := newObservatoriumAPIService(
		e,
		withMetricsEndpoints("http://"+readEndpoint, "http://"+writeEndpoint),
		withRateLimiter(rateLimiterAddr),
	)
	testutil.Ok(t, err)
	testutil.Ok(t, e2e.StartAndWaitReady(api))

	gatewayWrite := "https://" + api.InternalEndpoint("https") + "/api/metrics/v1/api/v1/receive"
	// up cannot send THANOS-TENANT on reads, so verify writes against Thanos directly.
	thanosRead := "http://" + readEndpoint

	t.Run("metrics-read-write", func(t *testing.T) {
		up, err := newUpRun(
			e, "up-metrics-read-write", metrics,
			thanosRead,
			gatewayWrite,
			withClientCert(
				filepath.Join(e.SharedDir(), certsSharedDir, "client.pem"),
				filepath.Join(e.SharedDir(), certsSharedDir, "client.key"),
			),
			withRunParameters(&runParams{period: "500ms", threshold: "1", latency: "10s", duration: "0"}),
		)
		testutil.Ok(t, err)
		testutil.Ok(t, e2e.StartAndWaitReady(up))

		up2, err := newUpRun(
			e, "up2-metrics-read-write", metrics,
			thanosRead,
			gatewayWrite,
			withClientCert(
				filepath.Join(e.SharedDir(), certsSharedDir, "client-another-tenant.pem"),
				filepath.Join(e.SharedDir(), certsSharedDir, "client-another-tenant.key"),
			),
			withLabels(`_id="test-another"`),
			withRunParameters(&runParams{period: "500ms", threshold: "1", latency: "10s", duration: "0"}),
		)
		testutil.Ok(t, err)
		testutil.Ok(t, e2e.StartAndWaitReady(up2))

		upMTLS, err := newUpRun(
			e, "up-metrics-mtls", metrics,
			thanosRead,
			gatewayWrite,
			withClientCert(
				filepath.Join(e.SharedDir(), certsSharedDir, "client-mtls.pem"),
				filepath.Join(e.SharedDir(), certsSharedDir, "client-mtls.key"),
			),
			withLabels(`_id="test-mtls"`),
			withRunParameters(&runParams{period: "500ms", threshold: "1", latency: "10s", duration: "0"}),
		)
		testutil.Ok(t, err)
		testutil.Ok(t, e2e.StartAndWaitReady(upMTLS))

		minimumExpectedWrites := float64(21)

		for _, u := range []*e2emon.InstrumentedRunnable{up, up2, upMTLS} {
			testutil.Ok(t, u.WaitSumMetricsWithOptions(
				e2emon.GreaterOrEqual(minimumExpectedWrites),
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

		testutil.Ok(t, api.WaitSumMetricsWithOptions(
			e2emon.GreaterOrEqual(minimumExpectedWrites*3),
			[]string{"http_requests_total"},
		))

		thanosQuery, err := promapi.NewClient(promapi.Config{Address: "http://" + readExtEndpoint})
		testutil.Ok(t, err)

		{
			now := model.Now()
			queryResult, w, err := v1.NewAPI(thanosQuery).Query(context.Background(), "observatorium_write{}", now.Time())
			testutil.Ok(t, err)
			testutil.Equals(t, 0, len(w))

			// tenant_id is the mTLS certificate OU forwarded as THANOS-TENANT to Receive.
			got := queryResult.String()
			testutil.Assert(t, regexp.MustCompile(
				fmt.Sprintf(`observatorium_write\{_id="test", receive_replica="0", tenant_id="%s"\}`, defaultTenantName),
			).MatchString(got), "missing series for %s: %s", defaultTenantName, got)
			testutil.Assert(t, regexp.MustCompile(
				fmt.Sprintf(`observatorium_write\{_id="test-another", receive_replica="0", tenant_id="%s"\}`, anotherTenantName),
			).MatchString(got), "missing series for %s: %s", anotherTenantName, got)
			testutil.Assert(t, regexp.MustCompile(
				fmt.Sprintf(`observatorium_write\{_id="test-mtls", receive_replica="0", tenant_id="%s"\}`, mtlsTenantName),
			).MatchString(got), "missing series for %s: %s", mtlsTenantName, got)
		}

		{
			now := model.Now()
			v, w, err := v1.NewAPI(thanosQuery).Query(context.Background(), "observatorium_write{}[1m]", now.Time())
			testutil.Ok(t, err)
			testutil.Equals(t, 0, len(w))

			vs := strings.Split(v.String(), "\n")[1:]
			testutil.Assert(t, len(vs) >= 38)
		}
	})

	t.Run("write-requires-client-cert", func(t *testing.T) {
		tr := &http.Transport{
			TLSClientConfig: getTLSClientConfig(t, e),
		}
		client := &http.Client{Transport: tr}

		req, err := http.NewRequest(
			http.MethodPost,
			"https://"+api.Endpoint("https")+"/api/metrics/v1/api/v1/receive",
			strings.NewReader(""),
		)
		testutil.Ok(t, err)

		res, err := client.Do(req)
		testutil.Ok(t, err)
		defer res.Body.Close()
		testutil.Equals(t, http.StatusUnauthorized, res.StatusCode)
	})

	// Query through the gateway with mTLS + THANOS-TENANT; label enforcer scopes data.
	t.Run("metrics-tenant-isolation", func(t *testing.T) {
		apiTest, err := newMetricsPromClient(t, e, api.Endpoint("https"), defaultTenantName, "client.pem", "client.key")
		testutil.Ok(t, err)
		apiAnother, err := newMetricsPromClient(t, e, api.Endpoint("https"), anotherTenantName, "client-another-tenant.pem", "client-another-tenant.key")
		testutil.Ok(t, err)
		apiMTLS, err := newMetricsPromClient(t, e, api.Endpoint("https"), mtlsTenantName, "client-mtls.pem", "client-mtls.key")
		testutil.Ok(t, err)
		apiAttacker, err := newMetricsPromClient(t, e, api.Endpoint("https"), "test-attacker", "client-attacker.pem", "client-attacker.key")
		testutil.Ok(t, err)

		now := model.Now()
		t.Run("query", func(t *testing.T) {
			v, w, err := v1.NewAPI(apiTest).Query(context.Background(), "observatorium_write{_id=\"test\"}", now.Time())
			testutil.Ok(t, err)
			testutil.Equals(t, 0, len(w), "%v", w)

			vs := strings.Split(v.String(), " => ")
			testutil.Equals(t, "observatorium_write{_id=\"test\", receive_replica=\"0\", tenant_id=\""+defaultTenantName+"\"}", vs[0])

			v, w, err = v1.NewAPI(apiAnother).Query(context.Background(), "observatorium_write{_id=\"test-another\"}", now.Time())
			testutil.Ok(t, err)
			testutil.Equals(t, 0, len(w), "%v", w)
			vs = strings.Split(v.String(), " => ")
			testutil.Equals(t, "observatorium_write{_id=\"test-another\", receive_replica=\"0\", tenant_id=\""+anotherTenantName+"\"}", vs[0])

			v, w, err = v1.NewAPI(apiMTLS).Query(context.Background(), `observatorium_write{_id="test-mtls"}`, now.Time())
			testutil.Ok(t, err)
			testutil.Equals(t, 0, len(w), "%v", w)
			vs = strings.Split(v.String(), " => ")
			testutil.Equals(t, "observatorium_write{_id=\"test-mtls\", receive_replica=\"0\", tenant_id=\""+mtlsTenantName+"\"}", vs[0])

			// Cross-tenant: each tenant must not see the other's series.
			v, w, err = v1.NewAPI(apiTest).Query(context.Background(), "observatorium_write{_id=\"test-another\"}", now.Time())
			testutil.Ok(t, err)
			testutil.Equals(t, v1.Warnings(nil), w)
			testutil.Equals(t, "", v.String())

			v, w, err = v1.NewAPI(apiMTLS).Query(context.Background(), `observatorium_write{_id="test"}`, now.Time())
			testutil.Ok(t, err)
			testutil.Equals(t, v1.Warnings(nil), w)
			testutil.Equals(t, "", v.String())

			v, w, err = v1.NewAPI(apiAttacker).Query(context.Background(), "observatorium_write{}", now.Time())
			testutil.Ok(t, err)
			testutil.Equals(t, v1.Warnings(nil), w)
			testutil.Equals(t, "", v.String())
		})
		t.Run("query_range", func(t *testing.T) {
			v, w, err := v1.NewAPI(apiTest).QueryRange(context.Background(), "observatorium_write{_id=\"test\"}", v1.Range{Start: now.Time().Add(-5 * time.Minute), End: now.Time(), Step: 1 * time.Minute})
			testutil.Ok(t, err)
			testutil.Equals(t, 0, len(w), "%v", w)

			vs := strings.Split(v.String(), " =>")
			testutil.Equals(t, "observatorium_write{_id=\"test\", receive_replica=\"0\", tenant_id=\""+defaultTenantName+"\"}", vs[0])

			v, w, err = v1.NewAPI(apiAttacker).QueryRange(context.Background(), "observatorium_write{}", v1.Range{Start: now.Time().Add(-5 * time.Minute), End: now.Time(), Step: 1 * time.Minute})
			testutil.Ok(t, err)
			testutil.Equals(t, v1.Warnings(nil), w)
			testutil.Equals(t, "", v.String())
		})
		t.Run("series", func(t *testing.T) {
			v, w, err := v1.NewAPI(apiTest).Series(context.Background(), []string{"{__name__=\"observatorium_write\",_id=\"test\"}"}, now.Time().Add(-5*time.Minute), now.Time())
			testutil.Ok(t, err)
			testutil.Equals(t, 0, len(w), "%v", w)
			testutil.Equals(t, []model.LabelSet{{"__name__": "observatorium_write", "_id": "test", "receive_replica": "0", "tenant_id": model.LabelValue(defaultTenantName)}}, v)

			v, w, err = v1.NewAPI(apiAttacker).Series(context.Background(), []string{"{__name__=\"observatorium_write\"}"}, now.Time().Add(-5*time.Minute), now.Time())
			testutil.Ok(t, err)
			testutil.Equals(t, v1.Warnings(nil), w)
			testutil.Equals(t, 0, len(v), "%v", v)
		})
		t.Run("label_names", func(t *testing.T) {
			v, w, err := v1.NewAPI(apiTest).LabelNames(context.Background(), nil, now.Time().Add(-5*time.Minute), now.Time())
			testutil.Ok(t, err)
			testutil.Equals(t, 0, len(w), "%v", w)
			testutil.Equals(t, model.LabelNames{"__name__", "_id", "receive_replica", "tenant_id"}, v)

			v, w, err = v1.NewAPI(apiAttacker).LabelNames(context.Background(), nil, now.Time().Add(-5*time.Minute), now.Time())
			testutil.Ok(t, err)
			testutil.Equals(t, 0, len(w), "%v", w)
			testutil.Equals(t, 0, len(v), "%v", v)
		})
		t.Run("labels_values", func(t *testing.T) {
			v, w, err := v1.NewAPI(apiTest).LabelValues(context.Background(), "__name__", nil, now.Time().Add(-5*time.Minute), now.Time())
			testutil.Ok(t, err)
			testutil.Equals(t, 0, len(w), "%v", w)
			testutil.Equals(t, model.LabelValues{"observatorium_write"}, v)

			v, w, err = v1.NewAPI(apiAttacker).LabelValues(context.Background(), "__name__", nil, now.Time().Add(-5*time.Minute), now.Time())
			testutil.Ok(t, err)
			testutil.Equals(t, 0, len(w), "%v", w)
			testutil.Equals(t, 0, len(v), "%v", v)
		})

		// Read without a client cert must fail authentication.
		status := metricsQueryStatus(t, api.Endpoint("https"), defaultTenantName, getTLSClientConfig(t, e),
			`observatorium_write{_id="test"}`)
		testutil.Equals(t, http.StatusUnauthorized, status)
	})
}

func newMetricsPromClient(t *testing.T, e e2e.Environment, host, tenant, certFile, keyFile string) (promapi.Client, error) {
	t.Helper()
	return promapi.NewClient(promapi.Config{
		Address: "https://" + host + "/api/metrics/v1",
		RoundTripper: &authRoundTripper{
			rt: &http.Transport{
				TLSClientConfig: getTLSClientConfigWithClientCert(t, e, certFile, keyFile),
			},
			tenantHeader: metricsTenantHeader,
			tenant:       tenant,
		},
	})
}

func metricsQueryStatus(t *testing.T, host, tenant string, tlsCfg *tls.Config, query string) int {
	t.Helper()
	client := &http.Client{Transport: &authRoundTripper{
		rt:           &http.Transport{TLSClientConfig: tlsCfg},
		tenantHeader: metricsTenantHeader,
		tenant:       tenant,
	}}
	req, err := http.NewRequest(http.MethodGet, "https://"+host+"/api/metrics/v1/api/v1/query", nil)
	testutil.Ok(t, err)
	q := req.URL.Query()
	q.Set("query", query)
	req.URL.RawQuery = q.Encode()
	res, err := client.Do(req)
	testutil.Ok(t, err)
	defer res.Body.Close()
	return res.StatusCode
}
