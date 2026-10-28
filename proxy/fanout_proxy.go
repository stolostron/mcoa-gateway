package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
)

type FanoutMetrics struct {
	requests            *prometheus.CounterVec
	fanoutRequestsTotal *prometheus.CounterVec
	fanoutErrorsTotal   *prometheus.CounterVec
}

func NewFanoutMetrics(reg prometheus.Registerer) FanoutMetrics {
	requests := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "http_fanout_requests_total",
		Help:        "Counter of HTTP requests to fanout.",
		ConstLabels: prometheus.Labels{"fanout": "fanoutv1-write"},
	}, []string{"method"})
	fanoutRequestsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "fanout_requests_total",
		Help:        "Counter of outbound HTTP requests from fanout.",
		ConstLabels: prometheus.Labels{"fanout": "fanoutv1-write"},
	}, []string{"url"})
	fanoutErrorsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:        "fanout_request_errors_total",
		Help:        "Counter of fanout request errors.",
		ConstLabels: prometheus.Labels{"fanout": "fanoutv1-write"},
	}, []string{"url"})
	reg.MustRegister(requests, fanoutRequestsTotal, fanoutErrorsTotal)
	return FanoutMetrics{requests: requests, fanoutRequestsTotal: fanoutRequestsTotal, fanoutErrorsTotal: fanoutErrorsTotal}
}

func FanoutRequestToEndpoints(client *http.Client, endpoints []*url.URL, routePath string, logger log.Logger, m FanoutMetrics) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.requests.With(prometheus.Labels{"method": r.Method}).Inc()
		rlogger := log.With(logger, "request", middleware.GetReqID(r.Context()))

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusInternalServerError)
			return
		}
		r.Body.Close()
		r.Body = io.NopCloser(bytes.NewBuffer(body))

		if len(endpoints) == 0 {
			http.Error(w, "fanout endpoints not loaded", http.StatusBadRequest)
			return
		}
		var (
			wg         sync.WaitGroup
			successCnt atomic.Int32
		)

		for _, ep := range endpoints {
			wg.Add(1)
			go func(ep *url.URL) {
				defer wg.Done()
				targetURL, err := url.JoinPath(ep.String(), routePath)
				if err != nil {
					level.Error(rlogger).Log("msg", "failed to get url", "err", err, "url", targetURL)
					m.fanoutErrorsTotal.WithLabelValues(ep.String()).Inc()
					return
				}
				req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, targetURL, bytes.NewBuffer(body))
				if err != nil {
					level.Error(rlogger).Log("msg", "failed to create fanout request", "err", err, "url", ep.String())
					m.fanoutErrorsTotal.WithLabelValues(ep.String()).Inc()
					return
				}
				req.Header = r.Header.Clone()

				m.fanoutRequestsTotal.WithLabelValues(ep.String()).Inc()
				resp, err := client.Do(req)
				if err != nil {
					level.Error(rlogger).Log("msg", "failed to send request", "err", err, "url", ep.String())
					m.fanoutErrorsTotal.WithLabelValues(ep.String()).Inc()
					return
				}

				defer resp.Body.Close()
				if resp.StatusCode < 200 || resp.StatusCode >= 300 {
					m.fanoutErrorsTotal.WithLabelValues(ep.String()).Inc()
					respBody, _ := io.ReadAll(resp.Body)
					level.Error(rlogger).Log("msg", "fanout target returned error", "code", resp.Status, "response", string(respBody), "url", ep.String())
				} else {
					successCnt.Add(1)
				}
			}(ep)
		}

		wg.Wait()
		// say n is the number of endpoints. If at least 1 of N requests succeed, return success. If all N requests
		// fail return an error. If all N fail, the the alert has not reach a single alertmanager, meaning the alert
		// notification will not fire
		if int(successCnt.Load()) < 1 {
			// note that prometheus does not retry failed alert requests, instead relying on resend delay for re-firing alert
			http.Error(w, "Failed to reach any alertmanager endpoints", http.StatusBadGateway)
		}
		w.WriteHeader(http.StatusOK)
	})
}
