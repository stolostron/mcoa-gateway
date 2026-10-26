package authorization

import (
	"strings"

	"github.com/prometheus/prometheus/model/labels"

	logqlv2 "github.com/stolostron/mcoa-gateway/logql/v2"
)

func parseLogStreamSelectors(selectorNames map[string]bool, query string) (map[string][]string, bool, error) {
	expr, err := logqlv2.ParseExpr(query)
	if err != nil {
		return nil, false, err
	}

	selectors := make(map[string][]string)
	appendSelector := func(selector, value string) {
		values, ok := selectors[selector]
		if !ok {
			values = make([]string, 0)
		}

		values = append(values, value)
		selectors[selector] = values
	}

	hasWildcard := false
	expr.Walk(func(expr interface{}) {
		switch le := expr.(type) {
		case *logqlv2.StreamMatcherExpr:
			for _, m := range le.Matchers() {
				if _, ok := selectorNames[m.Name]; !ok {
					continue
				}

				switch m.Type {
				case labels.MatchEqual:
					appendSelector(m.Name, m.Value)
				case labels.MatchRegexp:
					values := strings.Split(m.Value, "|")
					for _, v := range values {
						if strings.ContainsAny(v, ".+*") {
							hasWildcard = true
							continue
						}

						appendSelector(m.Name, v)
					}
				}
			}
		default:
			// Do nothing
		}
	})

	return selectors, hasWildcard, nil
}
