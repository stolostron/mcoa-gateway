package v1

import (
	"regexp"
	"strings"

	"github.com/prometheus/alertmanager/api/v2/models"
	"github.com/prometheus/prometheus/model/labels"
)

// tenantAllowList is the clusters in one GetTenant string.
// names keeps split order and the raw text. index is the membership test.
// The zero value fails closed. parseTenantAllowList is the only constructor.
type tenantAllowList struct {
	names []string
	index map[string]struct{}
}

// allowListError is the only error this file returns.
// status is the HTTP status the shell writes. msg names the rule and the label.
// It does not list clusters or echo a foreign name.
type allowListError struct {
	status int
	msg    string
}

func (e *allowListError) Error() string { return e.msg }

func (e *allowListError) Status() int { return e.status }

// parseTenantAllowList splits on "|" the way authorization.WithTenantLabel splits.
// Each piece is trimmed. An empty piece is an error, including a blank string.
// Order is preserved. Duplicates stay in names and collapse in index.
// Names are not regex-checked and are not QuoteMeta'd.
func parseTenantAllowList(tenant string) (tenantAllowList, error) {
	parts := strings.Split(tenant, "|")
	names := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return tenantAllowList{}, &allowListError{status: 400, msg: "empty tenant name not allowed"}
		}
		names = append(names, part)
	}
	if len(names) == 0 {
		return tenantAllowList{}, &allowListError{status: 400, msg: "empty tenant name not allowed"}
	}
	index := make(map[string]struct{}, len(names))
	for _, name := range names {
		index[name] = struct{}{}
	}
	return tenantAllowList{names: names, index: index}, nil
}

// filterMatcher returns the one matcher for GET alerts.
// One name is labels.MatchEqual and the raw name.
// More than one name is labels.MatchRegexp, regexp.QuoteMeta on each name, joined with "|".
// The zero value returns 500 and does not match everything.
func (a tenantAllowList) filterMatcher(label string) (*labels.Matcher, error) {
	if len(a.names) == 0 || a.index == nil {
		return nil, &allowListError{status: 500, msg: "error finding tenant"}
	}
	if len(a.names) == 1 {
		return &labels.Matcher{Type: labels.MatchEqual, Name: label, Value: a.names[0]}, nil
	}
	quoted := make([]string, len(a.names))
	for i, name := range a.names {
		quoted[i] = regexp.QuoteMeta(name)
	}
	return &labels.Matcher{
		Type:  labels.MatchRegexp,
		Name:  label,
		Value: strings.Join(quoted, "|"),
	}, nil
}

// silencePost returns the matchers to persist.
// Element 0 is a new equality matcher for the one cluster the body named.
// Its pointers are fresh. The other body matchers follow, in order.
// Nil or true IsRegex is rejected. Nil IsEqual counts as equality.
func (a tenantAllowList) silencePost(label string, body models.Matchers) (models.Matchers, error) {
	if len(a.names) == 0 || a.index == nil {
		return nil, &allowListError{status: 500, msg: "error finding tenant"}
	}
	var chosen string
	var saw bool
	kept := make(models.Matchers, 0, len(body))
	for _, m := range body {
		if m == nil || m.Name == nil || *m.Name != label {
			kept = append(kept, m)
			continue
		}
		if saw {
			return nil, &allowListError{status: 400, msg: "exactly one " + label + " matcher"}
		}
		saw = true
		// Omitted isRegex is not false. Only an explicit false is an equality.
		if m.IsRegex == nil || *m.IsRegex || m.Value == nil || (m.IsEqual != nil && !*m.IsEqual) {
			return nil, &allowListError{status: 400, msg: label + " matcher must be an equality"}
		}
		if _, ok := a.index[*m.Value]; !ok {
			return nil, &allowListError{status: 403, msg: "forbidden"}
		}
		chosen = *m.Value
	}
	if !saw {
		return nil, &allowListError{status: 400, msg: "silence must name one " + label + " cluster"}
	}
	if len(kept) == 0 {
		return nil, &allowListError{status: 400, msg: "need at least one matcher, got none"}
	}
	isEqual, isRegex := true, false
	value := chosen
	name := label
	canonical := &models.Matcher{Name: &name, Value: &value, IsRegex: &isRegex, IsEqual: &isEqual}
	return append(models.Matchers{canonical}, kept...), nil
}

// ownsSilence reports whether matchers prove the silence is one cluster in this allow-list.
// True only for exactly one positive equality on label whose value is in index.
// Nil IsEqual counts as equality. Nil or true IsRegex does not.
// A regexp of the whole allow-list is not ownership.
func (a tenantAllowList) ownsSilence(label string, matchers models.Matchers) bool {
	if len(a.names) == 0 || a.index == nil {
		return false
	}
	saw := false
	for _, m := range matchers {
		if m == nil || m.Name == nil || *m.Name != label {
			continue
		}
		if saw {
			return false
		}
		saw = true
		if m.IsRegex == nil || *m.IsRegex || m.Value == nil || (m.IsEqual != nil && !*m.IsEqual) {
			return false
		}
		if _, ok := a.index[*m.Value]; !ok {
			return false
		}
	}
	return saw
}

// visibleSilences returns the silences ownsSilence accepts, in input order.
// The result is a new non-nil slice, including when nothing matches.
// Nil entries are skipped.
func (a tenantAllowList) visibleSilences(label string, sils models.GettableSilences) models.GettableSilences {
	out := make(models.GettableSilences, 0)
	for _, sil := range sils {
		if sil == nil {
			continue
		}
		if a.ownsSilence(label, sil.Matchers) {
			out = append(out, sil)
		}
	}
	return out
}
