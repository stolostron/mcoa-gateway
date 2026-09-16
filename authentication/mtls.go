package authentication

import (
	"context"
	"net/http"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	grpc_middleware_auth "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/observatorium/api/httperr"
)

// MTLSAuthenticatorType represents the mTLS authentication provider type.
const MTLSAuthenticatorType = "mtls"

func init() {
	onboardNewProvider(MTLSAuthenticatorType, newMTLSAuthenticator)
}

// MTLSAuthenticator provides authentication based on client certificates.
// It relies on TLS-level certificate verification (via --tls.client-ca-file and tls.Config.ClientCAs)
// and only checks that a verified certificate is present, then extracts identity from it.
type MTLSAuthenticator struct {
	tenant string
	logger log.Logger
}

func newMTLSAuthenticator(c map[string]interface{}, tenant string, registrationRetryCount *prometheus.CounterVec, logger log.Logger) (Provider, error) {
	return MTLSAuthenticator{
		tenant: tenant,
		logger: logger,
	}, nil
}

func (a MTLSAuthenticator) Middleware() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check that TLS connection exists
			if r.TLS == nil {
				level.Debug(a.logger).Log("msg", "no TLS connection", "tenant", a.tenant)
				httperr.PrometheusAPIError(w, "TLS connection required", http.StatusUnauthorized)
				return
			}

			// Check that client presented a certificate
			if len(r.TLS.PeerCertificates) == 0 {
				level.Debug(a.logger).Log("msg", "no client certificate presented", "tenant", a.tenant)
				httperr.PrometheusAPIError(w, "client certificate required", http.StatusUnauthorized)
				return
			}

			// The certificate has already been verified by the TLS layer against the global CA
			// (configured via --tls.client-ca-file and tls.Config.ClientCAs).
			// We trust that verification and just extract identity information.

			cert := r.TLS.PeerCertificates[0]

			// Extract subject from certificate
			var sub string
			switch {
			case len(cert.EmailAddresses) > 0:
				sub = cert.EmailAddresses[0]
			case len(cert.URIs) > 0:
				sub = cert.URIs[0].String()
			case len(cert.DNSNames) > 0:
				sub = cert.DNSNames[0]
			case len(cert.IPAddresses) > 0:
				sub = cert.IPAddresses[0].String()
			case cert.Subject.CommonName != "":
				sub = cert.Subject.CommonName
			default:
				level.Debug(a.logger).Log("msg", "could not determine subject from certificate", "tenant", a.tenant)
				httperr.PrometheusAPIError(w, "could not determine subject from certificate", http.StatusBadRequest)
				return
			}

			level.Debug(a.logger).Log("msg", "authenticated via mTLS", "tenant", a.tenant, "subject", sub)

			ctx := context.WithValue(r.Context(), subjectKey, sub)

			// Add organizational units as groups
			ctx = context.WithValue(ctx, groupsKey, cert.Subject.OrganizationalUnit)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (a MTLSAuthenticator) GRPCMiddleware() grpc.StreamServerInterceptor {
	return grpc_middleware_auth.StreamServerInterceptor(func(ctx context.Context) (context.Context, error) {
		return ctx, status.Error(codes.Unimplemented, "mTLS authentication not implemented for gRPC")
	})
}

func (a MTLSAuthenticator) Handler() (string, http.Handler) {
	return "", nil
}
