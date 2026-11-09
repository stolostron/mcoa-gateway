package userperms

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	"github.com/stolostron/mcoa-gateway/authentication"
	"github.com/stolostron/mcoa-gateway/httperr"
)

// Mode selects how NewMiddleware turns a clusterSet into the request tenant.
// The zero value is ModeIntersect, which is today's behavior. Existing tests
// that leave Mode unset keep admit().
type Mode uint8

const (
	// ModeIntersect keeps requested names that the allow-list contains,
	// in request order, first occurrence only. admit remains the constructor.
	ModeIntersect Mode = iota

	// ModeDerive ignores the client tenant value. The tenant is every allowed
	// cluster, sorted, joined with '|'. Empty is 403. Over MaxTenants is 400.
	// The list is never truncated. Names are not regex-checked.
	ModeDerive
)

// defaultMaxTenants is the derive cap when MaxTenants is <= 0.
// authentication.maxTenants is a different limit, on client-supplied headers.
// Do not alias the two.
const defaultMaxTenants = 100

func normalizeMaxTenants(n int) int {
	if n <= 0 {
		return defaultMaxTenants
	}
	return n
}

// Options is the configuration for NewMiddleware.
// There is no tenant header field. The chain that calls NewMiddleware records
// the header name in the request context.
type Options struct {
	// TTL is how long a successful cluster set is reused.
	// Zero or negative selects 30s.
	TTL time.Duration

	// Kubeconfig is the hub kubeconfig used as the impersonation base.
	// Empty selects in-cluster config.
	Kubeconfig string

	// Logger receives list failures. Nil discards them.
	// A line includes the credential kind and subject, not the bearer token.
	Logger log.Logger

	// Mode zero value is ModeIntersect.
	Mode Mode

	// MaxTenants caps a derived allow-list. <=0 selects defaultMaxTenants.
	// Intersect does not read it. It is not part of the index key.
	MaxTenants int

	// loader and now are test seams. Either one selects a private index.
	loader lister
	now    func() time.Time
}

// NewMiddleware returns read-side authorization middleware.
// It panics if Mode is unknown, or if the hub config cannot be loaded.
// Call it while building the router, not per request.
//
// ModeDerive and ModeIntersect share one accessIndex when Kubeconfig and TTL
// match. Mode and MaxTenants stay out of indexKey. The cached value is the
// full set. The cap is applied when the set is read.
func NewMiddleware(opts Options) authentication.Middleware {
	switch opts.Mode {
	case ModeIntersect, ModeDerive:
	default:
		panic("userperms: unknown mode")
	}
	opts.MaxTenants = normalizeMaxTenants(opts.MaxTenants)
	if opts.TTL <= 0 {
		opts.TTL = defaultTTL
	}
	logger := opts.Logger
	if logger == nil {
		logger = log.NewNopLogger()
	}
	idx := acquireIndex(opts)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var requested string
			if opts.Mode == ModeDerive {
				if _, ok := authentication.GetTenant(r.Context()); ok {
					httperr.PrometheusAPIError(w, "derive mode received a client tenant", http.StatusInternalServerError)
					return
				}
			} else {
				var ok bool
				requested, ok = authentication.GetTenant(r.Context())
				if !ok {
					httperr.PrometheusAPIError(w, "error finding tenant", http.StatusBadRequest)
					return
				}
			}
			header, ok := authentication.GetTenantHeader(r.Context())
			if !ok {
				httperr.PrometheusAPIError(w, "tenant header is not in the request context", http.StatusInternalServerError)
				return
			}
			cred, err := credentialFromContext(r.Context())
			if errors.Is(err, errNoCredential) {
				httperr.PrometheusAPIError(w, "subject credential required", http.StatusUnauthorized)
				return
			}
			set, err := idx.clusterSet(r.Context(), cred)
			if err != nil {
				subject := cred.user
				if subject == "" {
					subject, _ = authentication.GetSubject(r.Context())
				}
				level.Error(logger).Log(
					"msg", "userpermissions list failed",
					"err", err,
					"kind", cred.kind.String(),
					"subject", subject,
					"clusters", set.len(),
				)
				status := http.StatusServiceUnavailable
				if errors.Is(err, errHubDenied) {
					status = http.StatusForbidden
				}
				httperr.PrometheusAPIError(w, "cannot evaluate cluster access", status)
				return
			}

			var admittedTenant string
			switch opts.Mode {
			case ModeDerive:
				got, err := derive(set, opts.MaxTenants)
				if err != nil {
					if errors.Is(err, errNoClusters) {
						httperr.PrometheusAPIError(w, "no access to any cluster", http.StatusForbidden)
						return
					}
					var tooMany *tooManyTenantsError
					if errors.As(err, &tooMany) {
						level.Warn(logger).Log(
							"msg", "derived allow-list exceeds max",
							"clusters", set.len(),
							"max", opts.MaxTenants,
						)
						httperr.PrometheusAPIError(w, fmt.Sprintf("too many tenants (max %d)", tooMany.max), http.StatusBadRequest)
						return
					}
					httperr.PrometheusAPIError(w, "cannot evaluate cluster access", http.StatusInternalServerError)
					return
				}
				admittedTenant = got.String()
			default:
				got, ok := admit(splitTenant(requested), set)
				if !ok {
					httperr.PrometheusAPIError(w, "no access to the requested clusters", http.StatusForbidden)
					return
				}
				admittedTenant = got.String()
			}
			ctx := authentication.WithTenantValue(r.Context(), admittedTenant)
			r = r.WithContext(ctx)
			r.Header.Set(header, admittedTenant)
			next.ServeHTTP(w, r)
		})
	}
}

var errNoCredential = errors.New("no subject credential")

// credentialFromContext prefers a non-empty access token.
// There is no fallback from a bearer token to impersonation.
// Without a token, a non-empty subject is impersonated. Missing groups are an empty list.
func credentialFromContext(ctx context.Context) (credential, error) {
	if token, ok := authentication.GetAccessToken(ctx); ok && token != "" {
		return credential{kind: credBearer, token: token}, nil
	}
	subject, ok := authentication.GetSubject(ctx)
	if !ok || subject == "" {
		return credential{}, errNoCredential
	}
	groups, _ := authentication.GetGroups(ctx)
	return credential{
		kind:   credImpersonate,
		user:   subject,
		groups: normalizeGroups(groups),
	}, nil
}

// HeaderChain is the read chain for --userperms.disable.
// It requires the client tenant header and looks up that tenant's authenticator,
// falling back to DefaultTenantName. It does not call NewMiddleware.
func HeaderChain(pm *authentication.ProviderManager, header string) authentication.Middleware {
	if pm == nil {
		panic("userperms: nil provider manager")
	}
	if header == "" {
		panic("userperms: empty tenant header")
	}
	return compose(
		authentication.WithTenantFromHeader(header),
		authentication.WithTenantMiddlewares(pm.Middlewares),
	)
}

// ReadChain is the authentication plus UserPermissions prefix when
// UserPermissions is enabled. Callers that enforce labels append
// authorization.WithTenantLabel after it. Alertmanager does not.
// ModeDerive uses WithTenantHeaderName, WithDefaultTenantMiddlewares, and NewMiddleware.
// ModeIntersect uses WithTenantFromHeader, WithTenantMiddlewares, and NewMiddleware.
// The zero Mode is ModeIntersect. ReadChain panics on an unknown mode, a nil
// manager, or an empty header. It calls NewMiddleware, which loads hub config.
func ReadChain(pm *authentication.ProviderManager, header string, opts Options) authentication.Middleware {
	if pm == nil {
		panic("userperms: nil provider manager")
	}
	if header == "" {
		panic("userperms: empty tenant header")
	}
	switch opts.Mode {
	case ModeDerive:
		return compose(
			authentication.WithTenantHeaderName(header),
			authentication.WithDefaultTenantMiddlewares(pm),
			NewMiddleware(opts),
		)
	case ModeIntersect:
		return compose(
			authentication.WithTenantFromHeader(header),
			authentication.WithTenantMiddlewares(pm.Middlewares),
			NewMiddleware(opts),
		)
	default:
		panic("userperms: unknown mode")
	}
}

// compose applies ms in order, first middleware outermost.
func compose(ms ...authentication.Middleware) authentication.Middleware {
	return func(next http.Handler) http.Handler {
		for i := len(ms) - 1; i >= 0; i-- {
			next = ms[i](next)
		}
		return next
	}
}
