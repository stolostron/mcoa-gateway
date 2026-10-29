package testtls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const expireDays = 1

type certBundle struct {
	cert []byte
	key  []byte
}

// ClientCert describes an mTLS client certificate to issue.
// OrganizationalUnit[0] is used by the gateway as the write-path tenant.
type ClientCert struct {
	FilePrefix string // written as {FilePrefix}.pem / {FilePrefix}.key
	CommonName string
	OU         string
}

func GenerateCerts(
	path string,
	apiCommonName string,
	apiSANs []string,
	dexCommonName string,
	dexSANs []string,
) error {
	return GenerateCertsWithClients(path, apiCommonName, apiSANs, dexCommonName, dexSANs,
		ClientCert{FilePrefix: "client", CommonName: "up", OU: "test-oidc"},
		ClientCert{FilePrefix: "client-another-tenant", CommonName: "up-another", OU: "another-tenant"},
	)
}

func GenerateCertsWithClients(
	path string,
	apiCommonName string,
	apiSANs []string,
	dexCommonName string,
	dexSANs []string,
	clients ...ClientCert,
) error {
	caCommonName := "observatorium"

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}
	ca := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: caCommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, expireDays),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return err
	}

	// Use the parsed CA for signing leaves so leaf AuthorityKeyId matches the issued CA's
	// SubjectKeyId (the in-memory template may omit fields the encoder adds).
	caParsed, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return fmt.Errorf("parse CA certificate: %w", err)
	}

	caPEM := new(bytes.Buffer)
	if err := pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	}); err != nil {
		return err
	}
	caPrivKeyPEM := new(bytes.Buffer)
	key, err := x509.MarshalECPrivateKey(caPrivKey)
	if err != nil {
		return err
	}
	if err := pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: key,
	}); err != nil {
		return err
	}
	caBundle := certBundle{
		cert: caPEM.Bytes(),
		key:  caPrivKeyPEM.Bytes(),
	}

	apiBundle, err := generateCert(caParsed, caPrivKey, false, apiCommonName, apiSANs, nil)
	if err != nil {
		return err
	}
	dexBundle, err := generateCert(caParsed, caPrivKey, false, dexCommonName, dexSANs, nil)
	if err != nil {
		return err
	}

	files := map[string][]byte{
		"ca.key":     caBundle.key,
		"ca.pem":     caBundle.cert,
		"server.key": apiBundle.key,
		"server.pem": apiBundle.cert,
		"dex.key":    dexBundle.key,
		"dex.pem":    dexBundle.cert,
	}

	for _, c := range clients {
		bundle, err := generateCert(caParsed, caPrivKey, true, c.CommonName, []string{c.CommonName}, []string{c.OU})
		if err != nil {
			return err
		}
		files[c.FilePrefix+".pem"] = bundle.cert
		files[c.FilePrefix+".key"] = bundle.key
	}

	if err := os.MkdirAll(path, 0o750); err != nil {
		return fmt.Errorf("mkdir %s: %v", path, err)
	}

	for file, content := range files {
		if err := os.WriteFile(filepath.Join(path, file), content, 0o644); err != nil {
			return fmt.Errorf("write file %s: %v", file, err)
		}
	}
	return nil
}

func generateCert(caCert *x509.Certificate, caPrivateKey crypto.Signer, client bool, commonName string, dnsNames, ou []string) (*certBundle, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	apiCert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         commonName,
			OrganizationalUnit: ou,
		},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:   time.Now(),

		NotAfter:              time.Now().AddDate(0, 0, expireDays),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:              dnsNames,
		BasicConstraintsValid: true,
		IsCA:                  false,
		AuthorityKeyId:        caCert.SubjectKeyId,
	}
	if client {
		apiCert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	certPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, apiCert, caCert, &certPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, err
	}

	certPEM := new(bytes.Buffer)
	if err := pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}); err != nil {
		return nil, err
	}

	key, err := x509.MarshalECPrivateKey(certPrivateKey)
	if err != nil {
		return nil, err
	}
	certPrivateKeyPEM := new(bytes.Buffer)
	if err = pem.Encode(certPrivateKeyPEM, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: key,
	}); err != nil {
		return nil, err
	}
	return &certBundle{
		cert: certPEM.Bytes(),
		key:  certPrivateKeyPEM.Bytes(),
	}, nil
}
