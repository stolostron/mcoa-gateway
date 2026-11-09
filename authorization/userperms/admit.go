package userperms

import (
	"errors"
	"fmt"
	"strings"
)

// admitted is a tenant string that is safe to store and to forward.
// admit and derive are the only constructors.
// admit returns ok=false instead of an empty admitted.
type admitted string

func (a admitted) String() string { return string(a) }

// admit keeps requested names that allowed contains, in request order, first occurrence only.
// A name that is only in allowed is not added. "*" is a literal name, not a wildcard.
func admit(requested []string, allowed clusterSet) (admitted, bool) {
	if len(requested) == 0 || allowed.len() == 0 {
		return "", false
	}

	kept := make([]string, 0, len(requested))
	seen := make(map[string]struct{}, len(requested))
	for _, name := range requested {
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		if allowed.has(name) {
			kept = append(kept, name)
		}
	}
	if len(kept) == 0 {
		return "", false
	}
	return admitted(strings.Join(kept, "|")), true
}

// errNoClusters is an empty allow-list in derive mode.
var errNoClusters = errors.New("no clusters")

// tooManyTenantsError is returned by derive.
// The HTTP body uses max only.
type tooManyTenantsError struct {
	max int
	n   int
}

func (e *tooManyTenantsError) Error() string {
	return fmt.Sprintf("too many tenants: %d (max %d)", e.n, e.max)
}

// derive joins allowed, which newClusterSet already sorted and de-duplicated.
// It does not take the request tenant. Dots and other DNS-1123 characters pass.
// maxTenants is the normalized cap from NewMiddleware.
func derive(allowed clusterSet, maxTenants int) (admitted, error) {
	n := allowed.len()
	if n == 0 {
		return "", errNoClusters
	}
	if n > maxTenants {
		return "", &tooManyTenantsError{max: maxTenants, n: n}
	}
	return admitted(allowed.joined()), nil
}

// splitTenant splits a GetTenant value on '|', trims each piece, and drops empty pieces.
// It does not sort or dedupe.
func splitTenant(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, "|")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
