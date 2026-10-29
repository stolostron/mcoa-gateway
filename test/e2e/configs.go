//go:build integration

package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efficientgo/core/testutil"
	"github.com/efficientgo/e2e"
)

type testType string

const (
	metrics        testType = "metrics"
	rules          testType = "rules"
	alerts         testType = "alerts"
	logs           testType = "logs"
	traces         testType = "traces"
	tracesTemplate testType = "tracesTemplate"
	tracesTempo    testType = "tracesTempo"
	probes         testType = "probes"

	certsSharedDir  = "certs"
	configSharedDir = "config"

	defaultTenantID = "1610b0c3-c509-4592-a256-a1871353dbfa"

	defaultTenantName = "test-oidc"
	anotherTenantName = "another-tenant"
	mtlsTenantName    = "test-mtls"

	metricsTenantHeader = "THANOS-TENANT"
	logsTenantHeader    = "X-Scope-OrgID"
)

// All e2e tenants authenticate with mTLS (global CA). Tenant on reads comes from
// the request header; write-path tenant comes from the client cert OU.
const tenantsYamlTpl = `
tenants:
- name: test-oidc
  id: 1610b0c3-c509-4592-a256-a1871353dbfa
  mTLS:
    caPath: %[1]s
  opa:
    query: data.observatorium.allow
    paths:
      - %[2]s
      - %[3]s
  rateLimits:
    - endpoint: "/api/metrics/v1/api/v1/receive"
      limit: 100
      window: 1s
    - endpoint: "/api/logs/v1/.*"
      limit: 100
      window: 1s
- name: another-tenant
  id: 177ef09c-04e1-46c5-86f7-dc3250bfe869
  mTLS:
    caPath: %[1]s
  opa:
    query: data.observatorium.allow
    paths:
    - %[2]s
    - %[3]s
- name: test-attacker
  id: 066df98b-04e1-46c5-86f7-dc3250bfe869
  mTLS:
    caPath: %[1]s
  opa:
    query: data.observatorium.allow
    paths:
    - %[2]s
    - %[3]s
- name: test-mtls
  id: 845cdfd9-f936-443c-979c-2ee7dc91f646
  mTLS:
    caPath: %[1]s
  opa:
    query: data.observatorium.allow
    paths:
    - %[2]s
    - %[3]s
  rateLimits:
    - endpoint: "/api/metrics/v1/api/v1/receive"
      limit: 100
      window: 1s
    - endpoint: "/api/logs/v1/.*"
      limit: 100
      window: 1s
- name: test-probes
  id: 76480613-1952-48a0-8025-34307a07a822
  mTLS:
    caPath: %[1]s
  opa:
    query: data.observatorium.allow
    paths:
    - %[2]s
    - %[3]s
`

func createTenantsYAML(t *testing.T, e e2e.Environment) {
	caPath := filepath.Join(e.SharedDir(), certsSharedDir, "ca.pem")
	yamlContent := []byte(fmt.Sprintf(
		tenantsYamlTpl,
		caPath,
		filepath.Join(e.SharedDir(), configSharedDir, "observatorium.rego"),
		filepath.Join(e.SharedDir(), configSharedDir, "rbac.yaml"),
	))

	err := os.WriteFile(
		filepath.Join(e.SharedDir(), configSharedDir, "tenants.yaml"),
		yamlContent,
		os.FileMode(0755),
	)
	testutil.Ok(t, err)
}

const rulesYAMLTpl = `
type: S3
config:
  bucket: %s
  endpoint: %s
  access_key: %s
  insecure: true
  secret_key: %s
`

func createRulesYAML(
	t *testing.T,
	e e2e.Environment,
	bucket, endpoint, accessKey, secretKey string,
) {
	yamlContent := []byte(fmt.Sprintf(
		rulesYAMLTpl,
		bucket,
		endpoint,
		accessKey,
		secretKey,
	))

	err := os.WriteFile(
		filepath.Join(e.SharedDir(), configSharedDir, "rules-objstore.yaml"),
		yamlContent,
		os.FileMode(0755),
	)
	testutil.Ok(t, err)
}

const otelConfigTpl = `
receivers:
    otlp:
      protocols:
        grpc:
            endpoint: "0.0.0.0:4317"
        http:
            endpoint: "0.0.0.0:4318"

exporters:
    debug:
        verbosity: detailed
    otlp:
        endpoint: %[1]s
        tls:
          insecure: true

service:
    telemetry:
      metrics:
        readers:
          - pull:
              exporter:
                prometheus:
                  host: 0.0.0.0
                  port: 8888
        level: detailed
      logs:
        level: DEBUG

    pipelines:
        traces/grpc:
            receivers: [otlp]
            exporters: [debug,otlp]
`

// createOtelCollectorConfigYAML() creates YAML for an Open Telemetry collector inside the Observatorium API boundary.
func createOtelCollectorConfigYAML(
	t *testing.T,
	e e2e.Environment,
	jaegerGRPCEndpoint string,
) {
	// Warn if a YAML change introduced a tab character
	if strings.ContainsRune(otelConfigTpl, '\t') {
		t.Errorf("Tab in the YAML")
	}

	yamlContent := []byte(fmt.Sprintf(
		otelConfigTpl,
		jaegerGRPCEndpoint))

	err := os.WriteFile(
		filepath.Join(e.SharedDir(), configSharedDir, "collector.yaml"),
		yamlContent,
		os.FileMode(0644),
	)
	testutil.Ok(t, err)
}

// OTel trace collector that receives in HTTP w/o security, but exports in gRPC with security.
const otelForwardingConfigTpl = `
receivers:
    otlp:
      protocols:
        http:
            endpoint: 0.0.0.0:4318
        grpc:
            endpoint: 0.0.0.0:4317

exporters:
    debug:
      verbosity: detailed
    otlp:
      endpoint: %[1]s
      # auth:
      #   authenticator: oauth2client
      tls:
        insecure_skip_verify: true
      compression: none
      headers:
        x-tenant: test-oidc

extensions:
  health_check:
    endpoint: 0.0.0.0:13133
  zpages:
    endpoint: 0.0.0.0:55679

service:
    extensions: [health_check, zpages]
    telemetry:
      metrics:
        readers:
          - pull:
              exporter:
                prometheus:
                  host: 0.0.0.0
                  port: 8888
        level: detailed
    # extensions: [oauth2client]
    pipelines:
      traces:
        receivers: [otlp]
        exporters: [debug,otlp]
`

// createOtelForwardingCollectorConfigYAML() creates YAML for an Open Telemetry collector outside the
// Observatorium API boundary that forwards traces via GRPC to Observatorium.
func createOtelForwardingCollectorConfigYAML(
	t *testing.T,
	e e2e.Environment,
	observatoriumGRPCEndpoint string,
) {
	// Warn if a YAML change introduced a tab character
	if strings.ContainsRune(otelForwardingConfigTpl, '\t') {
		t.Errorf("Tab in the YAML")
	}

	yamlContent := []byte(fmt.Sprintf(
		otelForwardingConfigTpl,
		observatoriumGRPCEndpoint,
	))

	err := os.WriteFile(
		filepath.Join(e.SharedDir(), configSharedDir, "forwarding-collector.yaml"),
		yamlContent,
		os.FileMode(0644),
	)
	testutil.Ok(t, err)
}

const lokiYAMLTpl = `auth_enabled: true

server:
  http_listen_port: 3100

common:
 storage:
  s3:
    s3forcepathstyle: true
    access_key_id: %[1]s
    secret_access_key: %[2]s
    endpoint: %[3]s
    bucketnames: %[4]s
    insecure: true

compactor:
  working_directory: /tmp/loki/compactor
  shared_store: s3
  compaction_interval: 5m

distributor:
  ring:
    kvstore:
      store: inmemory

ingester:
  lifecycler:
    address: 0.0.0.0
    ring:
      kvstore:
        store: inmemory
      replication_factor: 1

    final_sleep: 0s
  chunk_idle_period: 5m
  chunk_retain_period: 30s
  wal:
    dir: /tmp/loki/ingester/wal
    enabled: false

querier:
  engine:
    max_look_back_period: 5m
    timeout: 3m

ruler:
  storage:
    type: s3
  wal:
   dir: /tmp/loki/ruler/wal
  rule_path: /tmp/loki/

schema_config:
  configs:
  - from: 2019-01-01
    store: boltdb-shipper
    object_store: s3
    schema: v12
    index:
      prefix: index_
      period: 24h

storage_config:
  boltdb_shipper:
    active_index_directory: /tmp/loki/index
    cache_location: /tmp/loki/index_cache
    shared_store: s3

limits_config:
  enforce_metric_name: false
  reject_old_samples: false

`

func createLokiYAML(
	t *testing.T,
	e e2e.Environment,
	accessId, accessKey, endpoint, bucket string,
) {
	yamlContent := []byte(fmt.Sprintf(lokiYAMLTpl, accessId, accessKey, endpoint, bucket))

	err := os.WriteFile(
		filepath.Join(e.SharedDir(), configSharedDir, "loki.yml"),
		yamlContent,
		os.FileMode(0755),
	)

	testutil.Ok(t, err)
}

const tempoConfig = `
server:
  http_listen_port: 3200

query_frontend:
  search:
    duration_slo: 5s
    throughput_bytes_slo: 1.073741824e+09
  trace_by_id:
    duration_slo: 5s

distributor:
  receivers:
    otlp:
      protocols:
        http:
          endpoint: 0.0.0.0:4318
        grpc:
          endpoint: 0.0.0.0:4317
    opencensus:

ingester:
  max_block_duration: 5m               # cut the headblock when this much time passes. this is being set for demo purposes and should probably be left alone normally

compactor:
  compaction:
    block_retention: 1h                # overall Tempo trace retention. set for demo purposes

storage:
  trace:
    backend: local                     # backend configuration to use
    wal:
      path: /tmp/tempo/wal             # where to store the the wal locally
    local:
      path: /tmp/tempo/blocks
`

// createTempoConfigYAML() creates YAML for Tempo inside the Observatorium API boundary.
func createTempoConfigYAML(
	t *testing.T,
	e e2e.Environment,
) {
	// Warn if a YAML change introduced a tab character
	if strings.ContainsRune(tempoConfig, '\t') {
		t.Errorf("Tab in the YAML")
	}

	yamlContent := []byte(tempoConfig)

	err := os.WriteFile(
		filepath.Join(e.SharedDir(), configSharedDir, "tempo.yaml"),
		yamlContent,
		os.FileMode(0644),
	)
	testutil.Ok(t, err)
}
