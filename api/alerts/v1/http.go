package v1

import (
	"crypto/tls"
	"crypto/x509"
	stdlog "log"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/stolostron/mcoa-gateway/authentication"
	"github.com/stolostron/mcoa-gateway/proxy"
)

const (
	dialTimeout             = 30 * time.Second
	AlertmanagerAlertsRoute = "/api/v2/alerts"
)

type handlerConfiguration struct {
	logger           log.Logger
	registry         *prometheus.Registry
	instrument       handlerInstrumenter
	writeMiddlewares []func(http.Handler) http.Handler
}

type handlerInstrumenter interface {
	NewHandler(labels prometheus.Labels, handler http.Handler) http.HandlerFunc
}

type HandlerOption func(h *handlerConfiguration)

func Logger(logger log.Logger) HandlerOption {
	return func(h *handlerConfiguration) {
		h.logger = logger
	}
}

func Registry(r *prometheus.Registry) HandlerOption {
	return func(h *handlerConfiguration) {
		h.registry = r
	}
}

func WriteMiddleware(m func(http.Handler) http.Handler) HandlerOption {
	return func(h *handlerConfiguration) {
		h.writeMiddlewares = append(h.writeMiddlewares, m)
	}
}

// WithAccessorToken sets the Authorization header on forwarded alert writes.
func WithAccessorToken(token string) HandlerOption {
	return func(h *handlerConfiguration) {
		if token == "" {
			return
		}

		h.writeMiddlewares = append(h.writeMiddlewares, func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.Header.Set("Authorization", "Bearer "+token)
				next.ServeHTTP(w, r)
			})
		})
	}
}

// WithTenantHeader sets the configured tenant ID header before forwarding an
// alert. If no ID is configured for the tenant, its tenant name is forwarded.
func WithTenantHeader(header string, tenantIDs map[string]string) HandlerOption {
	return func(h *handlerConfiguration) {
		if header == "" {
			return
		}

		h.writeMiddlewares = append(h.writeMiddlewares, func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tenant, ok := authentication.GetTenant(r.Context())
				if !ok || tenant == "" {
					http.Error(w, "tenant not found", http.StatusBadRequest)
					return
				}
				if tenantID := tenantIDs[tenant]; tenantID != "" {
					tenant = tenantID
				}
				r.Header.Set(header, tenant)
				next.ServeHTTP(w, r)
			})
		})
	}
}

type nopInstrumentHandler struct{}

func (n nopInstrumentHandler) NewHandler(_ prometheus.Labels, handler http.Handler) http.HandlerFunc {
	return handler.ServeHTTP
}

func loadCACertPool(caPath string) *x509.CertPool {
	if caPath == "" {
		return nil
	}
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		stdlog.Printf("CA certificate not available at %s, using system roots: %v", caPath, err)
		return nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		stdlog.Printf("failed to parse CA certificate from %s, using system roots", caPath)
		return nil
	}
	return pool
}

func newHTTPClient(caPool *x509.CertPool, serverName string) *http.Client {
	transport := &http.Transport{
		DisableKeepAlives: true,
		IdleConnTimeout:   dialTimeout,
		DialContext: (&net.Dialer{
			Timeout:   dialTimeout,
			KeepAlive: dialTimeout,
		}).DialContext,
	}

	if caPool != nil || serverName != "" {
		transport.TLSClientConfig = &tls.Config{
			ServerName: serverName,
			RootCAs:    caPool,
		}
	}

	return &http.Client{Transport: transport}
}

func NewHandler(endpoints []*url.URL, upstreamCAFile string, upstreamServerName string, opts ...HandlerOption) http.Handler {
	c := &handlerConfiguration{
		logger:     log.NewNopLogger(),
		registry:   prometheus.NewRegistry(),
		instrument: nopInstrumentHandler{},
	}
	for _, o := range opts {
		o(c)
	}
	r := chi.NewRouter()

	caPool := loadCACertPool(upstreamCAFile)
	client := newHTTPClient(caPool, upstreamServerName)

	alertFanout := proxy.FanoutRequestToEndpoints(client, endpoints, AlertmanagerAlertsRoute, c.logger, proxy.NewFanoutMetrics(c.registry))
	r.Group(func(r chi.Router) {
		r.Use(c.writeMiddlewares...)
		r.Post(AlertmanagerAlertsRoute, alertFanout.ServeHTTP)
	})
	return r
}
