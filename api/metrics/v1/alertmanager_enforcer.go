package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"

	"github.com/go-chi/chi/v5"
	runtimeclient "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/prometheus/alertmanager/api/v2/client"
	"github.com/prometheus/alertmanager/api/v2/client/silence"
	"github.com/prometheus/alertmanager/api/v2/models"
	amlabels "github.com/prometheus/alertmanager/pkg/labels"

	"github.com/stolostron/mcoa-gateway/authentication"
	"github.com/stolostron/mcoa-gateway/httperr"
)

// WithEnforceTenancyOnFilter returns middleware that sets the alert list filter
// to the caller's allow-list. A caller filter on the tenant label is dropped.
func WithEnforceTenancyOnFilter(label string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			allow, err := tenantFromRequest(r)
			if err != nil {
				writeTenantError(w, err)
				return
			}
			m, err := allow.filterMatcher(label)
			if err != nil {
				writeTenantError(w, err)
				return
			}
			kept, err := callerFilters(label, r.URL.Query()["filter"])
			if err != nil {
				writeTenantError(w, err)
				return
			}
			q := r.URL.Query()
			q["filter"] = append([]string{m.String()}, kept...)
			q.Del(label)
			r.URL.RawQuery = q.Encode()
			next.ServeHTTP(w, r)
		})
	}
}

// WithEnforceTenancyOnSilenceMatchers returns middleware that requires a POST
// silence to name exactly one allow-listed cluster as an equality matcher.
func WithEnforceTenancyOnSilenceMatchers(label string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				httperr.PrometheusAPIError(w, "error method not allowed", http.StatusMethodNotAllowed)
				return
			}

			allow, err := tenantFromRequest(r)
			if err != nil {
				writeTenantError(w, err)
				return
			}

			var sil models.PostableSilence
			if err := json.NewDecoder(r.Body).Decode(&sil); err != nil {
				httperr.PrometheusAPIError(w, fmt.Sprintf("bad request: can't decode: %v", err), http.StatusBadRequest)
				return
			}
			if sil.ID != "" {
				httperr.PrometheusAPIError(w, "updates to silence by ID not allowed", http.StatusUnprocessableEntity)
				return
			}

			matchers, err := allow.silencePost(label, sil.Matchers)
			if err != nil {
				writeTenantError(w, err)
				return
			}
			sil.Matchers = matchers

			var buf bytes.Buffer
			if err := json.NewEncoder(&buf).Encode(&sil); err != nil {
				httperr.PrometheusAPIError(w, fmt.Sprintf("can't encode: %v", err), http.StatusInternalServerError)
				return
			}

			r = r.Clone(r.Context())
			r.Body = io.NopCloser(&buf)
			r.URL.RawQuery = ""
			r.Header["Content-Length"] = []string{strconv.Itoa(buf.Len())}
			r.ContentLength = int64(buf.Len())
			next.ServeHTTP(w, r)
		})
	}
}

// WithEnforceTenancyOnSilenceID ensures the silence in the path belongs to one
// cluster in the allow-list before proxying GET or DELETE.
func WithEnforceTenancyOnSilenceID(label string, upstream *url.URL, transport http.RoundTripper) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			silID := chi.URLParam(r, "silenceID")
			if silID == "" {
				httperr.PrometheusAPIError(w, "bad request", http.StatusBadRequest)
				return
			}

			allow, err := tenantFromRequest(r)
			if err != nil {
				writeTenantError(w, err)
				return
			}

			sil, err := getSilenceByID(r.Context(), upstream, transport, silID)
			if err != nil {
				var notFound *silence.GetSilenceNotFound
				if errors.As(err, &notFound) {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				httperr.PrometheusAPIError(w, fmt.Sprintf("proxy error: %v", err), http.StatusBadGateway)
				return
			}

			if sil == nil || !allow.ownsSilence(label, sil.Matchers) {
				httperr.PrometheusAPIError(w, "forbidden", http.StatusForbidden)
				return
			}

			r.URL.RawQuery = ""
			next.ServeHTTP(w, r)
		})
	}
}

// silenceListHandler serves GET silences. It loads the upstream list without a
// tenant filter and writes the silences ownsSilence accepts.
func silenceListHandler(label string, upstream *url.URL, transport http.RoundTripper) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allow, err := tenantFromRequest(r)
		if err != nil {
			writeTenantError(w, err)
			return
		}
		kept, err := callerFilters(label, r.URL.Query()["filter"])
		if err != nil {
			writeTenantError(w, err)
			return
		}
		raw, err := listSilences(r.Context(), upstream, transport, kept)
		if err != nil {
			var bad *silence.GetSilencesBadRequest
			if errors.As(err, &bad) {
				httperr.PrometheusAPIError(w, "bad request", http.StatusBadRequest)
				return
			}
			// The client error string includes the upstream payload.
			httperr.PrometheusAPIError(w, "bad gateway", http.StatusBadGateway)
			return
		}
		body, err := json.Marshal(allow.visibleSilences(label, raw))
		if err != nil {
			httperr.PrometheusAPIError(w, "error encoding silences", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})
}

// tenantFromRequest reads GetTenant and parses it.
// Missing GetTenant is 500. A present string that does not parse is the parse error.
func tenantFromRequest(r *http.Request) (tenantAllowList, error) {
	tenant, ok := authentication.GetTenant(r.Context())
	if !ok {
		return tenantAllowList{}, &allowListError{status: http.StatusInternalServerError, msg: "error finding tenant"}
	}
	return parseTenantAllowList(tenant)
}

// writeTenantError writes err when it is an *allowListError.
// Any other error is 500 with a fixed message.
func writeTenantError(w http.ResponseWriter, err error) {
	var allow *allowListError
	if errors.As(err, &allow) {
		httperr.PrometheusAPIError(w, allow.Error(), allow.Status())
		return
	}
	httperr.PrometheusAPIError(w, "error finding tenant", http.StatusInternalServerError)
}

// callerFilters returns the raw filter strings whose label name is not label.
// Order of the kept strings is preserved. A value amlabels.ParseMatcher rejects
// is an error. A filter on the tenant label is dropped.
func callerFilters(label string, raw []string) ([]string, error) {
	kept := make([]string, 0, len(raw))
	for _, filter := range raw {
		m, err := amlabels.ParseMatcher(filter)
		if err != nil {
			return nil, &allowListError{status: http.StatusBadRequest, msg: "invalid filter"}
		}
		if m.Name == label {
			continue
		}
		kept = append(kept, filter)
	}
	return kept, nil
}

func listSilences(ctx context.Context, upstream *url.URL, transport http.RoundTripper, filters []string) (models.GettableSilences, error) {
	params := silence.NewGetSilencesParams().WithContext(ctx)
	if len(filters) > 0 {
		params.SetFilter(filters)
	}
	res, err := alertmanagerAPI(upstream, transport).Silence.GetSilences(params)
	if err != nil {
		return nil, err
	}
	return res.Payload, nil
}

func getSilenceByID(ctx context.Context, upstream *url.URL, transport http.RoundTripper, id string) (*models.GettableSilence, error) {
	params := silence.NewGetSilenceParams().WithContext(ctx)
	params.SetSilenceID(strfmt.UUID(id))
	res, err := alertmanagerAPI(upstream, transport).Silence.GetSilence(params)
	if err != nil {
		return nil, err
	}
	return res.Payload, nil
}

// alertmanagerAPI is the client constructor getSilenceByID and listSilences share.
// Nil transport stays http.DefaultTransport.
func alertmanagerAPI(upstream *url.URL, transport http.RoundTripper) *client.AlertmanagerAPI {
	if transport == nil {
		transport = http.DefaultTransport
	}
	rt := runtimeclient.NewWithClient(
		upstream.Host,
		path.Join(upstream.Path, "/api/v2"),
		[]string{upstream.Scheme},
		&http.Client{Transport: transport},
	)
	return client.New(rt, strfmt.Default)
}
