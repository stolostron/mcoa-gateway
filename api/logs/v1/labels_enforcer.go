package http

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/prometheus/prometheus/model/labels"

	"github.com/stolostron/mcoa-gateway/authorization"
	"github.com/stolostron/mcoa-gateway/httperr"
	logqlv2 "github.com/stolostron/mcoa-gateway/logql/v2"
)

type AuthzResponseData = authorization.AuthzResponseData

const (
	logicalOr  = "or"
	queryParam = "query"
	matchParam = "match"
)

type matchersContextKey struct{}

// WithEnforceAuthorizationLabels return a middleware that ensures every query
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

			var matchersInfo AuthzResponseData
			if err := json.Unmarshal([]byte(data), &matchersInfo); err != nil {
				httperr.PrometheusAPIError(w, "error parsing authorization label matchers", http.StatusInternalServerError)

				return
			}
			r = r.WithContext(context.WithValue(r.Context(), matchersContextKey{}, matchersInfo))

			if err := enforceRequestLogQL(matchersInfo, r); err != nil {
				httperr.PrometheusAPIError(w, fmt.Sprintf("could not enforce authorization label matchers: %v", err), http.StatusInternalServerError)

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func enforceRequestLogQL(mInfo AuthzResponseData, r *http.Request) error {
	q, err := enforceValues(mInfo, r.URL)
	if err != nil {
		return err
	}
	r.URL.RawQuery = q

	if r.Method != http.MethodPost {
		return nil
	}
	if err := r.ParseForm(); err != nil {
		return fmt.Errorf("could not parse form: %w", err)
	}
	// ParseForm consumes the body. Always restore it so the proxy can forward
	// non-selector fields (e.g. limit). Only enforce a body selector when the
	// caller supplied one; otherwise body precedence would invent a tenant-only
	// query and override an already-enforced URL selector.
	body := r.PostForm.Encode()
	if len(r.PostForm[logQLParam(r.URL.Path)]) > 0 {
		body, err = enforceValuesOnLogQL(mInfo, r.PostForm, logQLParam(r.URL.Path))
		if err != nil {
			return err
		}
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(strings.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return nil
}

func enforceValues(mInfo AuthzResponseData, u *url.URL) (values string, err error) {
	return enforceValuesOnLogQL(mInfo, u.Query(), logQLParam(u.Path))
}

func logQLParam(path string) string {
	if strings.HasSuffix(path, "/series") {
		return matchParam
	}
	return queryParam
}

func enforceValuesOnLogQL(mInfo AuthzResponseData, v url.Values, paramName string) (values string, err error) {
	lm, err := initAuthzMatchers(mInfo.Matchers)
	if err != nil {
		return "", err
	}

	paramValue := v.Get(paramName)
	if paramValue == "" {
		expr := &logqlv2.StreamMatcherExpr{}
		expr.SetMatchers(lm)
		v.Set(paramName, expr.String())
		return v.Encode(), nil
	}

	expr, err := logqlv2.ParseExpr(paramValue)
	if err != nil {
		return "", fmt.Errorf("failed parsing LogQL expression: %w", err)
	}

	// Logical "OR" only applies to query expressions, not for filter params
	if mInfo.MatcherOp == logicalOr && paramName == queryParam {
		// Logical "OR" to combine multiple matchers needs to be done via LogQueryExpr > LogPipelineExpr
		expr.Walk(func(expr interface{}) {
			if le, ok := expr.(*logqlv2.LogQueryExpr); ok {
				le.AppendPipelineMatchers(mInfo.Matchers, logicalOr)
			}
		})
		v.Set(paramName, expr.String())
		return v.Encode(), nil
	}

	// Only enforce on StreamMatcherExpr: LogQueryExpr.Walk also visits its nested
	// stream matcher, and combining at both levels would duplicate authz matchers
	// once non-equality caller filters are retained alongside them.
	expr.Walk(func(expr interface{}) {
		if le, ok := expr.(*logqlv2.StreamMatcherExpr); ok {
			le.SetMatchers(combineLabelMatchers(le.Matchers(), lm))
		}
	})

	v.Set(paramName, expr.String())
	return v.Encode(), nil
}

// Combine the query label matcher and the authorization label matcher.
func combineLabelMatchers(queryMatchers, authzMatchers []*labels.Matcher) []*labels.Matcher {
	queryMatchersMap := make(map[string]*labels.Matcher)
	for _, qm := range queryMatchers {
		queryMatchersMap[qm.Name] = qm
	}

	matchers := make([]*labels.Matcher, 0)
	for _, am := range authzMatchers {
		qm := queryMatchersMap[am.Name]
		if qm == nil || qm.Type != labels.MatchEqual || !am.Matches(qm.Value) {
			// Keep the caller's non-equality filter (=~, !=, !~) so it still
			// narrows within the authorization matcher instead of being dropped.
			if qm != nil && qm.Type != labels.MatchEqual {
				matchers = append(matchers, qm)
			}
			queryMatchersMap[am.Name] = am
		}
	}

	for _, m := range queryMatchersMap {
		matchers = append(matchers, m)
	}

	return matchers
}

func initAuthzMatchers(lm []*labels.Matcher) ([]*labels.Matcher, error) {
	// Fix label matchers to include a non nil FastRegexMatcher for regex types.
	for i, m := range lm {
		nm, err := labels.NewMatcher(m.Type, m.Name, m.Value)
		if err != nil {
			return nil, fmt.Errorf("failed parsing label matcher: %w", err)
		}

		lm[i] = nm
	}

	return lm, nil
}

// AllowedNamespaces returns the list of namespaces that the user is allowed to list.
func AllowedNamespaces(ctx context.Context) []string {
	matchers := ctx.Value(matchersContextKey{})
	if matchers == nil {
		return nil
	}
	matchersTyped := matchers.(AuthzResponseData)

	var namespaces []string
	for _, m := range matchersTyped.Matchers {
		namespaces = append(namespaces, strings.Split(m.Value, "|")...)
	}
	return namespaces
}
