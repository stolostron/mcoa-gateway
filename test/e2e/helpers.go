//go:build integration

package e2e

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efficientgo/core/testutil"
	"github.com/efficientgo/e2e"
	"github.com/stolostron/mcoa-gateway/test/testtls"
)

// uniqueE2ENetworkName returns a Docker-valid e2e network name (≤16 chars, [-a-zA-Z0-9])
// that is distinct for each Go test. efficientgo/e2e's bare e2e.New() would assign the same
// network to all parallel tests leading to Docker network races.
func uniqueE2ENetworkName(t *testing.T) string {
	t.Helper()
	sum := sha256.Sum256([]byte(t.Name()))
	return fmt.Sprintf("%x", sum[:8]) // 16 hex digits
}

// Generates certificates and copies static configuration to the shared directory.
func prepareConfigsAndCerts(t *testing.T, e e2e.Environment) {
	testutil.Ok(
		t,
		testtls.GenerateCerts(
			filepath.Join(e.SharedDir(), certsSharedDir),
			getContainerName(e, "mcoa-gateway"),
			[]string{
				getContainerName(e, "mcoa-gateway"),
				"127.0.0.1",
				"host.docker.internal",
			},
		),
	)

	testutil.Ok(t, exec.Command("cp", "-r", "../config", filepath.Join(e.SharedDir(), configSharedDir)).Run())
}

// getContainerName returns the Docker DNS hostname for a service in this environment.
// It must match e2e's naming ({networkName}-{runnableName}) so TLS SANs stay correct.
func getContainerName(e e2e.Environment, serviceName string) string {
	return e.Name() + "-" + serviceName
}

func getTLSClientConfig(t *testing.T, e e2e.Environment) *tls.Config {
	cert, err := os.ReadFile(filepath.Join(e.SharedDir(), certsSharedDir, "ca.pem"))
	testutil.Ok(t, err)

	cp := x509.NewCertPool()
	if ok := cp.AppendCertsFromPEM(cert); !ok {
		t.Fatal("failed to parse CA certificate from ca.pem")
	}

	return &tls.Config{
		RootCAs: cp,
	}
}

// getTLSClientConfigWithClientCert returns a TLS config that presents a client
// certificate (needed for write-path mTLS tenant extraction and mTLS read auth).
func getTLSClientConfigWithClientCert(t *testing.T, e e2e.Environment, certFile, keyFile string) *tls.Config {
	t.Helper()
	cfg := getTLSClientConfig(t, e)
	cert, err := tls.LoadX509KeyPair(
		filepath.Join(e.SharedDir(), certsSharedDir, certFile),
		filepath.Join(e.SharedDir(), certsSharedDir, keyFile),
	)
	testutil.Ok(t, err)
	cfg.Certificates = []tls.Certificate{cert}
	return cfg
}

// newMTLSAuthClient builds an HTTP client that authenticates with a client cert
// and sets the read-path tenant header (no bearer token).
func newMTLSAuthClient(t *testing.T, e e2e.Environment, tenantHeader, tenant, certFile, keyFile string) *http.Client {
	t.Helper()
	return &http.Client{Transport: &authRoundTripper{
		rt: &http.Transport{
			TLSClientConfig: getTLSClientConfigWithClientCert(t, e, certFile, keyFile),
		},
		tenantHeader: tenantHeader,
		tenant:       tenant,
	}}
}

func assertResponse(t *testing.T, response string, expected string) {
	t.Helper()
	testutil.Assert(
		t,
		strings.Contains(response, expected),
		fmt.Sprintf("failed to assert that the response '%s' contains '%s'", response, expected),
	)
}

// authRoundTripper attaches the read-path tenant header. Authentication is via
// the underlying RoundTripper's TLS client certificate.
type authRoundTripper struct {
	rt           http.RoundTripper
	tenantHeader string
	tenant       string
}

func (rt *authRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if rt.tenantHeader != "" && rt.tenant != "" {
		r.Header.Set(rt.tenantHeader, rt.tenant)
	}
	return rt.rt.RoundTrip(r)
}
