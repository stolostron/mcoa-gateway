package v1

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/prometheus-community/prom-label-proxy/injectproxy"
	"github.com/prometheus/prometheus/model/labels"

	"github.com/stolostron/mcoa-gateway/authentication"
	"github.com/stolostron/mcoa-gateway/authorization"
	"github.com/stolostron/mcoa-gateway/httperr"
)

// WithEnforceTenancyOnQuery returns a middleware that ensures that every query has a tenant label enforced.
func WithEnforceTenancyOnQuery(tenantLabel, paramName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		// Adapted from
		// https://github.com/prometheus-community/prom-label-proxy/blob/952266db4e0b8ab66b690501e532eaef33300596/injectproxy/routes.go.
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant, ok := authentication.GetTenant(r.Context())
			if !ok {
				httperr.PrometheusAPIError(w, "error finding tenant", http.StatusInternalServerError)
				return
			}

			tenantMatcher := &labels.Matcher{
				Name:  tenantLabel,
				Type:  labels.MatchEqual,
				Value: tenant,
			}
			e := injectproxy.NewPromQLEnforcer(false, tenantMatcher)
			// If we cannot enforce, don't continue.
			if ok := enforceRequestQueryLabels(e, paramName, w, r); !ok {
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// WithEnforceAuthorizationLabels returns a middleware that ensures every query
// has a set of labels returned by the OPA authorizer enforced.
func WithEnforceAuthorizationLabels() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			data, ok := authorization.GetData(r.Context())
			if !ok {
				httperr.PrometheusAPIError(w, "error finding authorization label matcher", http.StatusInternalServerError)

				return
			}

			// Early pass to the next if no authz
			// label enforcement configured.
			if data == "" {
				next.ServeHTTP(w, r)

				return
			}

			var doc authorization.AuthzResponseData
			if err := json.Unmarshal([]byte(data), &doc); err != nil {
				httperr.PrometheusAPIError(w, "error parsing authorization label matcher", http.StatusInternalServerError)

				return
			}

			e := injectproxy.NewPromQLEnforcer(false, doc.Matchers...)
			// If we cannot enforce, don't continue.
			if ok := enforceRequestQueryLabels(e, metricSelectorParam(r.URL.Path), w, r); !ok {
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func metricSelectorParam(path string) string {
	switch {
	case strings.HasSuffix(path, "/series"),
		strings.HasSuffix(path, "/labels"),
		strings.HasSuffix(path, "/values"),
		strings.HasSuffix(path, "/rules"),
		strings.HasSuffix(path, "/federate"):
		return "match[]"
	default:
		return "query"
	}
}

func enforceRequestQueryLabels(e *injectproxy.PromQLEnforcer, paramName string, w http.ResponseWriter, r *http.Request) bool {
	// Selectors may live in the URL query, the POST body, or both. Prometheus
	// clients (DoGetFallback) usually POST form bodies with an empty URL query.
	// Inventing a tenant-only match[] on an empty URL OR's with the body
	// selectors; Thanos then warns "no matchers specified (excluding external
	// labels)" because tenant_id is an external label on Receive.
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			httperr.PrometheusAPIError(w, fmt.Sprintf("could not parse form: %v", err), http.StatusInternalServerError)
			return false
		}

		bodyHasParam := len(r.PostForm[paramName]) > 0
		urlHasParam := len(r.URL.Query()[paramName]) > 0

		// ParseForm consumes the body. When the selector lives only in the URL,
		// restore non-selector form fields (e.g. time=) before URL enforcement;
		// otherwise the proxy forwards an exhausted reader with the original
		// Content-Length and the transport fails.
		if !bodyHasParam && urlHasParam {
			body := r.PostForm.Encode()
			_ = r.Body.Close()
			r.Body = io.NopCloser(strings.NewReader(body))
			r.ContentLength = int64(len(body))
			r.Header.Set("Content-Length", strconv.Itoa(len(body)))
		}

		if bodyHasParam || !urlHasParam {
			bodyParams := cloneURLValues(r.PostForm)
			// match[] is an OR-list of selectors. When callers put distinct
			// values in both URL and body, merge them before enforcement so
			// deleting the URL copy does not drop part of the selection.
			if paramName == "match[]" {
				bodyParams[paramName] = append(bodyParams[paramName], r.URL.Query()[paramName]...)
			}
			q, foundForm, err := enforceQueryValues(e, paramName, bodyParams)
			if err != nil {
				httperr.PrometheusAPIError(w, fmt.Sprintf("could not enforce labels: %v", err), http.StatusBadRequest)
				return false
			}
			_ = r.Body.Close()
			r.Body = io.NopCloser(strings.NewReader(q))
			r.ContentLength = int64(len(q))
			r.Header.Set("Content-Length", strconv.Itoa(len(q)))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			// Drop any URL copy of the selector so it cannot OR with the body.
			urlQ := r.URL.Query()
			urlQ.Del(paramName)
			r.URL.RawQuery = urlQ.Encode()

			if !foundForm {
				httperr.PrometheusAPIError(w, "no query found", http.StatusBadRequest)
				return false
			}
			return true
		}
	}

	q, foundQuery, err := enforceQueryValues(e, paramName, r.URL.Query())
	if err != nil {
		httperr.PrometheusAPIError(w, fmt.Sprintf("could not enforce labels: %v", err), http.StatusBadRequest)
		return false
	}
	r.URL.RawQuery = q

	if !foundQuery {
		httperr.PrometheusAPIError(w, "no query found", http.StatusBadRequest)
		return false
	}
	return true
}

func cloneURLValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vals := range v {
		out[k] = append([]string(nil), vals...)
	}
	return out
}

// Adapted from
// https://github.com/prometheus-community/prom-label-proxy/blob/952266db4e0b8ab66b690501e532eaef33300596/injectproxy/routes.go.
func enforceQueryValues(e *injectproxy.PromQLEnforcer, paramName string, requestParams url.Values) (values string, foundQuery bool, err error) {
	if len(requestParams[paramName]) == 0 {
		// This is a dirty hack to force the introduction of a match[] param to add tenancy
		// enforcement even when the param isn't present. This is needed because match[] is
		// optional for label names and values, yet we have to add it to avoid leaks.
		// Would love to find a cleaner way to do it.
		enforcedMatchers, err := e.EnforceMatchers([]*labels.Matcher{})
		if err != nil {
			return "", false, fmt.Errorf("enforce matchers error: %w", err)
		}
		requestParams.Set(paramName, matchersToString(enforcedMatchers...))
		return requestParams.Encode(), true, nil
	}

	matchers := requestParams[paramName]
	for i, rawMatcher := range matchers {
		expr, err := promQLParser.ParseExpr(rawMatcher)
		if err != nil {
			return "", true, fmt.Errorf("parse expr error: %w", err)
		}
		if err := e.EnforceNode(expr); err != nil {
			return "", true, fmt.Errorf("enforce node error: %w", err)
		}
		matchers[i] = expr.String()
	}
	return requestParams.Encode(), true, nil
}

func matchersToString(ms ...*labels.Matcher) string {
	el := make([]string, 0, len(ms))
	for _, m := range ms {
		el = append(el, m.String())
	}
	return fmt.Sprintf("{%v}", strings.Join(el, ","))
}
