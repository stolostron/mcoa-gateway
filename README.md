# MCOA Gateway

Multi-tenant observability gateway that provides authenticated and authorized access to metrics, logs, and traces backends.

MCOA Gateway is a reverse proxy that sits between observability clients (Prometheus, Grafana, Loki agents) and backends (Thanos, Loki, Tempo), providing:

- **Multi-tenancy** - Tenant isolation for metrics, logs, and traces
- **Authentication** - mTLS for write path, OIDC/mTLS/OpenShift for read path
- **Authorization** - Label-based tenant isolation for queries
- **Rate limiting** - Per-tenant rate limits with local or shared (Redis/gRPC) backends
- **TLS** - End-to-end TLS with certificate rotation support

## Table of Contents

- [Architecture](#architecture)
- [Features](#features)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
  - [Server Configuration](#server-configuration)
  - [TLS Configuration](#tls-configuration)
  - [Tenant Configuration](#tenant-configuration)
  - [Backend Configuration](#backend-configuration)
- [Authentication](#authentication)
  - [Write Path (mTLS)](#write-path-mtls)
  - [Read Path (OIDC/mTLS)](#read-path-oidcmtls)
- [Rate Limiting](#rate-limiting)
- [Examples](#examples)
- [Certificate Setup](#certificate-setup)
- [Testing](#testing)

---

## Architecture

```
┌─────────────┐         ┌─────────────────────────────────┐         ┌──────────┐
│  Prometheus │─mTLS───▶│                                 │         │  Thanos  │
│   (write)   │         │                                 ├────────▶│ Receiver │
└─────────────┘         │                                 │         └──────────┘
                        │                                 │
┌─────────────┐         │        MCOA Gateway             │         ┌──────────┐
│   Grafana   │─OIDC───▶│                                 ├────────▶│  Thanos  │
│   (read)    │         │    - Authentication             │         │  Query   │
└─────────────┘         │    - Authorization              │         └──────────┘
                        │    - Rate Limiting              │
┌─────────────┐         │    - Tenant Isolation           │         ┌──────────┐
│ Loki Agent  │─mTLS───▶│                                 ├────────▶│   Loki   │
│   (write)   │         │                                 │         │          │
└─────────────┘         └─────────────────────────────────┘         └──────────┘
```

### Request Flow

**Write Path (Metrics/Logs Ingestion):**
1. Client connects with mTLS certificate
2. TLS layer verifies certificate against global CA (`--tls.client-ca-file`)
3. Gateway extracts tenant from certificate OU field
4. Rate limiting applied (if configured)
5. Request proxied to backend with tenant header

**Read Path (Queries):**
1. Client authenticates (OIDC/mTLS/OpenShift - per tenant)
2. Tenant extracted from URL path (`/api/metrics/v1/{tenant}/...`)
3. Authorization enforced (label matching for tenant isolation)
4. Request proxied to backend with tenant header

---

## Features

### Multi-Tenancy
- **Tenant isolation** - Each tenant's data is isolated via tenant headers and label enforcement
- **Tenant validation** - Tenant names validated against `^[a-zA-Z0-9_-]+$` pattern (1-256 chars)
- **Multi-tenant queries** - Support for querying multiple tenants via pipe-separated headers or multiple header values

### Authentication

**Write Path:**
- **mTLS only** - Machine-to-machine authentication
- **Global CA** - Single CA file verifies all client certificates
- **Tenant extraction** - Tenant extracted from certificate OU field
- **No OIDC** - Write path designed for scrape targets/agents

**Read Path (per-tenant):**
- **OIDC** - OpenID Connect for human users (browser-based)
- **mTLS** - Client certificates for machine-to-machine
- **OpenShift** - Service account token authentication
- **Flexible** - Each tenant can use different auth method

### Authorization
- **Label enforcement** - Queries automatically filtered by tenant label
- **Tenant label injection** - Read queries modified to include `{tenant_id="tenant-name"}`
- **RBAC support** - Optional RBAC for traces queries

### Rate Limiting
- **Per-tenant limits** - Configure different rate limits per tenant and endpoint
- **Multiple backends:**
  - **Local** - In-memory rate limiting (single instance)
  - **Redis** - Shared rate limiting across multiple gateway instances (leaky bucket)
  - **gRPC** - External rate limiter service
- **Fallback behavior** - Configurable fail-open/fail-closed on rate limiter errors
- **Retry-After header** - Supports backoff hints for Prometheus remote write

### TLS
- **Server TLS** - HTTPS for client connections
- **Client certificate verification** - Verify client certs against CA
- **Upstream TLS** - TLS connections to backends (Thanos/Loki/Tempo)
- **Certificate rotation** - Hot reload of certificates without restart
- **Configurable cipher suites** - TLS 1.2/1.3 support

---

## Quick Start

### 1. Build

```bash
# Using Makefile (recommended)
make build

# Binary will be created as: mcoa-gateway
```

### 2. Create Certificates

See [Certificate Setup](#certificate-setup) for detailed instructions.

```bash
# Server certificate
openssl req -new -x509 -days 365 -nodes \
  -keyout server.key -out server.crt \
  -subj "/CN=gateway.example.com"

# Client CA (for verifying client certificates)
openssl genrsa -out client-ca.key 4096
openssl req -new -x509 -days 3650 -key client-ca.key -out client-ca.crt \
  -subj "/CN=MCOA Client CA"

# Client certificate (for tenant-alpha)
openssl genrsa -out tenant-alpha.key 2048
openssl req -new -key tenant-alpha.key -out tenant-alpha.csr \
  -subj "/CN=tenant-alpha/OU=tenant-alpha"
openssl x509 -req -in tenant-alpha.csr \
  -CA client-ca.crt -CAkey client-ca.key -CAcreateserial \
  -out tenant-alpha.crt -days 365
```

### 3. Create Tenant Configuration

```yaml
# tenants.yaml
tenants:
  - name: tenant-alpha
    id: tenant-alpha
    oidc:
      clientID: mcoa
      clientSecret: secret
      issuerURL: https://sso.example.com
      redirectURL: https://gateway.example.com/oidc/tenant-alpha/callback
      usernameClaim: email
```

### 4. Run

```bash
./mcoa-gateway \
  --web.listen=:8080 \
  --tls.server.cert-file=server.crt \
  --tls.server.key-file=server.key \
  --tls.client-ca-file=client-ca.crt \
  --tls.client-auth-type=RequireAndVerifyClientCert \
  --tenants.config=tenants.yaml \
  --metrics.write.endpoint=https://thanos:19291/api/v1/receive \
  --metrics.read.endpoint=https://thanos:9090/api/v1 \
  --logs.write.endpoint=https://loki:3100/loki/api/v1/push \
  --logs.read.endpoint=https://loki:3100
```

### 5. Test Write Path (mTLS)

```bash
# Write metrics
curl -X POST https://localhost:8080/api/metrics/v1/api/v1/receive \
  --cert tenant-alpha.crt \
  --key tenant-alpha.key \
  --cacert server.crt \
  -H "Content-Type: application/x-protobuf" \
  --data-binary @metrics.pb
```

### 6. Test Read Path (OIDC)

Navigate to `https://localhost:8080/api/metrics/v1/tenant-alpha/api/v1/query?query=up` in browser - you'll be redirected to OIDC login.

---

## Configuration

### Server Configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--web.listen` | `:8080` | Address to listen on for external HTTP/HTTPS |
| `--grpc.listen` | (empty) | Address to listen on for gRPC (if enabled) |
| `--web.internal.listen` | `:8081` | Address for internal/health endpoints |
| `--web.healthchecks.url` | `http://localhost:8080` | URL for health checks |
| `--log.level` | `info` | Log level (debug, info, warn, error) |
| `--log.format` | `logfmt` | Log format (logfmt, json) |
| `--tenants.config` | `tenants.yaml` | Path to tenant configuration file |

### TLS Configuration

#### Server TLS (Client → Gateway)

| Flag | Default | Description |
|------|---------|-------------|
| `--tls.server.cert-file` | (empty) | Server TLS certificate file |
| `--tls.server.key-file` | (empty) | Server TLS private key file |
| `--tls.min-version` | `VersionTLS13` | Minimum TLS version (VersionTLS10/11/12/13) |
| `--tls.max-version` | `VersionTLS13` | Maximum TLS version |
| `--tls.cipher-suites` | (default) | Comma-separated cipher suites |
| `--tls.reload-interval` | `1m` | Certificate reload interval |

#### Client Certificate Verification (mTLS)

| Flag | Default | Description |
|------|---------|-------------|
| `--tls.client-ca-file` | (empty) | **CA certificate for verifying client certificates** |
| `--tls.client-auth-type` | `RequestClientCert` | Client auth policy (see table below) |

**Client Auth Types:**

| Type | Client Cert Required? | Verified Against CA? | Use Case |
|------|----------------------|---------------------|----------|
| `NoClientCert` | ❌ No | N/A | No mTLS (HTTPS only) |
| `RequestClientCert` | ⚠️ Optional | ❌ No | **Not recommended** |
| `RequireAnyClientCert` | ✅ Yes | ❌ No | **Not recommended** |
| `VerifyClientCertIfGiven` | ⚠️ Optional | ✅ Yes (if provided) | Optional mTLS |
| `RequireAndVerifyClientCert` | ✅ Yes | ✅ Yes | **Recommended for mTLS** ✅ |

**For production mTLS, use:**
```bash
--tls.client-auth-type=RequireAndVerifyClientCert \
--tls.client-ca-file=/path/to/client-ca.crt
```

#### Upstream TLS (Gateway → Backends)

For each backend (metrics/logs/traces/probes):

| Flag Pattern | Description |
|--------------|-------------|
| `--{backend}.tls.ca-file` | CA to verify upstream server certificates |
| `--{backend}.tls.cert-file` | Client cert for mTLS to upstream |
| `--{backend}.tls.key-file` | Client key for mTLS to upstream |
| `--{backend}.tls.watch-certs` | Enable hot reload of upstream certs |

Example:
```bash
--metrics.tls.ca-file=/etc/certs/thanos-ca.crt \
--metrics.tls.cert-file=/etc/certs/gateway-client.crt \
--metrics.tls.key-file=/etc/certs/gateway-client.key \
--metrics.tls.watch-certs=true
```

### Tenant Configuration

Tenants are configured via YAML file (`--tenants.config`).

#### Scalable Configuration: Default Tenant

**For thousands of tenants**, use a special **`__mcoa_default__`** tenant that acts as a fallback authenticator:

```yaml
# tenants.yaml - ONE entry for ALL tenants
tenants:
  - name: __mcoa_default__
    oidc:
      clientID: mcoa
      clientSecret: secret
      issuerURL: https://auth.example.com
      redirectURL: https://gateway.example.com/oidc/__mcoa_default__/callback
    rateLimits:
      - endpoint: ".*"
        limit: 1000
        window: 1s
```

**How it works:**
1. Request for `tenant-12345` arrives
2. Gateway checks if `tenant-12345` exists in tenants.yaml
3. **If NOT found** → Uses `__mcoa_default__` tenant authenticator
4. Authentication succeeds, request processed

**Result:**
- ✅ 1000 tenants write via mTLS (cert OU = tenant)
- ✅ All tenants readable via single OIDC login
- ✅ Global rate limit applies to all tenants
- ✅ Override specific tenants if needed

**Best Practice:** Use `__mcoa_default__` for thousands of tenants instead of listing each one individually in tenants.yaml.

#### When Tenant Configuration is Required

**Tenant config is REQUIRED for:**
- ✅ **Read path authentication** - Each tenant that needs query access must be listed with an authenticator
- ✅ **Rate limiting** - Per-tenant rate limits on read or write endpoints

**Tenant config is OPTIONAL for:**
- ⚠️ **Write path only** - If you only use write endpoints (metrics/logs ingestion) and don't need rate limiting, you can run without tenant config
  - Write path always uses global CA mTLS (tenant extracted from cert OU)
  - No per-tenant authentication needed
  - Gateway will accept writes but queries will fail (no authenticator configured)

**Summary:**

| Use Case | Tenant Config Needed? | Why |
|----------|----------------------|-----|
| Write + Read (same tenants) | ✅ Yes, all tenants OR use `__mcoa_default__` | Each tenant needs authenticator OR use fallback |
| Write only, with rate limits | ✅ Yes OR use `__mcoa_default__` with rate limits | Rate limits configured per tenant or globally |
| Write only, no rate limits | ⚠️ Optional | Write uses global CA, but no queries possible |
| **Thousands of tenants** | ✅ **Use `__mcoa_default__` tenant** | **One config entry handles all tenants** |

**Recommendation:**
- **Any number of tenants**: Use `__mcoa_default__` tenant (see above)

#### Tenant Schema

```yaml
tenants:
  - name: <tenant-name>        # Required: tenant identifier (1-256 chars, ^[a-zA-Z0-9_-]+$)
    id: <tenant-id>            # Optional: alternative tenant ID
    
    # Authentication (choose one):
    
    # Option 1: OIDC (for read path, human users)
    oidc:
      clientID: <client-id>
      clientSecret: <client-secret>
      issuerURL: <issuer-url>
      redirectURL: <redirect-url>
      usernameClaim: email              # Optional: claim for username
      groupClaim: groups                # Optional: claim for groups
    
    # Option 2: mTLS (for read path, uses global CA)
    mTLS: {}
    
    # Option 3: OpenShift (for read path)
    openshift:
      serviceAccount: <sa-name>
      kubeconfig: <path>
      redirectURL: <redirect-url>
    
    # Rate Limits (optional)
    rateLimits:
      - endpoint: <regex>               # Endpoint pattern (e.g., ".*receive.*")
        limit: <rps>                    # Requests per second
        window: <duration>              # Time window (e.g., "1s", "1m")
        failOpen: <bool>                # Fail open on rate limiter errors
        retryAfterMin: <duration>       # Min Retry-After value
        retryAfterMax: <duration>       # Max Retry-After value
```

#### Example Tenant Configurations

**OIDC Tenant:**
```yaml
tenants:
  - name: tenant-alpha
    oidc:
      clientID: mcoa
      clientSecret: my-secret
      issuerURL: https://auth.example.com
      redirectURL: https://gateway.example.com/oidc/tenant-alpha/callback
      usernameClaim: email
      groupClaim: groups
    rateLimits:
      - endpoint: ".*receive.*"
        limit: 1000
        window: 1s
```

**mTLS Tenant:**
```yaml
tenants:
  - name: tenant-beta
    mTLS: {}  # Uses global CA from --tls.client-ca-file
    rateLimits:
      - endpoint: ".*query.*"
        limit: 100
        window: 1s
```

**Mixed Tenants:**
```yaml
tenants:
  - name: tenant-alpha
    oidc:  # Read path: OIDC
      clientID: mcoa
      clientSecret: secret
      issuerURL: https://auth.example.com
      redirectURL: https://gateway.example.com/oidc/tenant-alpha/callback
    # Write path: Always mTLS (global CA)
  
  - name: tenant-beta
    mTLS: {}  # Read and write: mTLS
```

#### Tenant Configuration Examples by Use Case

**Use Case 1: Write-only (ingestion only, no queries)**

If you only need the write path (Prometheus remote write, Loki push) and don't need to query data through the gateway:

```bash
# NO tenant config needed - write path works with global CA only
./mcoa-gateway \
  --tls.server.cert-file=server.crt \
  --tls.server.key-file=server.key \
  --tls.client-ca-file=client-ca.crt \
  --tls.client-auth-type=RequireAndVerifyClientCert \
  --metrics.write.endpoint=https://thanos:19291/api/v1/receive \
  --logs.write.endpoint=https://loki:3100/loki/api/v1/push
```

**Result:**
- ✅ Write requests work (tenant from certificate OU field)
- ❌ Read requests fail (no authenticator configured for queries)
- ⚠️ No rate limiting available

**Use Case 2: Write + Read (full gateway)**

For production use with both ingestion and queries:

```yaml
# tenants.yaml
tenants:
  - name: tenant-alpha
    oidc:  # Read authentication
      clientID: mcoa
      clientSecret: secret
      issuerURL: https://auth.example.com
      redirectURL: https://gateway.example.com/oidc/tenant-alpha/callback
    rateLimits:  # Optional rate limits
      - endpoint: ".*receive.*"
        limit: 1000
        window: 1s
```

```bash
./mcoa-gateway \
  --tenants.config=tenants.yaml \
  --tls.client-ca-file=client-ca.crt \
  --tls.client-auth-type=RequireAndVerifyClientCert \
  --metrics.write.endpoint=https://thanos:19291/api/v1/receive \
  --metrics.read.endpoint=https://thanos:9090/api/v1
```

**Result:**
- ✅ Write requests work (global CA mTLS)
- ✅ Read requests work (OIDC authentication)
- ✅ Rate limiting applied

**Use Case 3: Read-only (query gateway)**

For a gateway that only serves queries (data already in backends):

```yaml
# tenants.yaml
tenants:
  - name: tenant-alpha
    oidc:
      clientID: mcoa
      issuerURL: https://auth.example.com
      redirectURL: https://gateway.example.com/oidc/tenant-alpha/callback
```

```bash
./mcoa-gateway \
  --tenants.config=tenants.yaml \
  --metrics.read.endpoint=https://thanos:9090/api/v1 \
  --logs.read.endpoint=https://loki:3100
```

**Result:**
- ❌ Write requests not available (no write endpoints configured)
- ✅ Read requests work (OIDC authentication)

### Backend Configuration

#### Metrics (Thanos/Prometheus/Cortex)

| Flag | Description |
|------|-------------|
| `--metrics.read.endpoint` | Read endpoint (Thanos Query, Prometheus) |
| `--metrics.write.endpoint` | Write endpoint (Thanos Receive, Cortex) |
| `--metrics.rules.endpoint` | Rules API endpoint |
| `--metrics.alertmanager.endpoint` | Alertmanager API endpoint |
| `--metrics.write-timeout` | Upstream write timeout (default: 5m) |
| `--metrics.tenant-header` | Tenant header name (default: `THANOS-TENANT`) |
| `--metrics.tenant-label` | Tenant label for filtering (default: `tenant_id`) |

#### Logs (Loki)

| Flag | Description |
|------|-------------|
| `--logs.read.endpoint` | Read endpoint (Loki) |
| `--logs.write.endpoint` | Write endpoint (Loki) |
| `--logs.tail.endpoint` | Tail/streaming endpoint |
| `--logs.rules.endpoint` | Rules API endpoint |
| `--logs.write-timeout` | Upstream write timeout (default: 5m) |
| `--logs.tenant-header` | Tenant header name (default: `X-Scope-OrgID`) |
| `--logs.rules.tenant-label` | Tenant label for rules (default: `tenant_id`) |

#### Traces (Tempo)

| Flag | Description |
|------|-------------|
| `--traces.read.endpoint` | Read endpoint (Tempo) |
| `--traces.write.otlpgrpc.endpoint` | OTLP gRPC write endpoint |
| `--traces.write.otlphttp.endpoint` | OTLP HTTP write endpoint |
| `--traces.write-timeout` | Upstream write timeout (default: 30s) |
| `--traces.tenant-header` | Tenant header name (default: `X-Tenant`) |
| `--traces.query-rbac` | Enable RBAC for queries (default: false) |

---

## Authentication

MCOA Gateway uses **different authentication models** for write and read paths.

### Write Path (mTLS)

**Purpose:** Machine-to-machine authentication for metrics/logs/traces ingestion

**Authentication Method:** mTLS only (no OIDC option)

**How it works:**
1. Client presents certificate during TLS handshake
2. Gateway verifies certificate against **global CA** (`--tls.client-ca-file`)
3. If verification succeeds, connection established
4. Gateway extracts tenant from certificate's **OU (OrganizationalUnit)** field
5. Request proxied to backend with tenant header

**Requirements:**
- Client certificate must be signed by global CA
- Certificate must have **OU field set to tenant name**
- Global CA configured: `--tls.client-ca-file`
- Client auth enabled: `--tls.client-auth-type=RequireAndVerifyClientCert`

**Write Endpoints:**
- `POST /api/metrics/v1/api/v1/receive` - Prometheus remote write
- `POST /api/logs/v1/loki/api/v1/push` - Loki push
- `POST /api/traces/v1/traces` - OTLP traces

**Example:**
```bash
# Create client cert with OU=tenant-alpha
openssl req -new -key client.key -out client.csr \
  -subj "/CN=prometheus-1/OU=tenant-alpha/O=MyOrg"

# Write metrics
curl -X POST https://gateway:8080/api/metrics/v1/api/v1/receive \
  --cert tenant-alpha.crt \
  --key tenant-alpha.key \
  --cacert server-ca.crt \
  -H "Content-Type: application/x-protobuf" \
  --data-binary @metrics.pb
```

**Tenant Extraction:**
- Certificate: `CN=prometheus-1, OU=tenant-alpha, O=MyOrg`
- Extracted tenant: `tenant-alpha`
- Forwarded header: `THANOS-TENANT: tenant-alpha`

### Read Path (OIDC/mTLS)

**Purpose:** Query authentication for humans (Grafana) or machines (automation)

**Authentication Method:** Per-tenant configuration (OIDC, mTLS, or OpenShift)

**How it works:**
1. Tenant extracted from **URL path**: `/api/metrics/v1/{tenant}/...`
2. Tenant's configured authenticator applied
3. If authentication succeeds, request proxied to backend
4. Query automatically filtered by tenant label

**Authentication Options:**

#### Option 1: OIDC (Recommended for humans)

```yaml
tenants:
  - name: tenant-alpha
    oidc:
      clientID: mcoa
      clientSecret: my-secret
      issuerURL: https://auth.example.com
      redirectURL: https://gateway.example.com/oidc/tenant-alpha/callback
      usernameClaim: email
```

**Flow:**
1. User navigates to `/api/metrics/v1/tenant-alpha/api/v1/query?query=up`
2. Not authenticated → redirect to OIDC provider
3. User logs in at OIDC provider
4. Redirect back to gateway with auth code
5. Gateway exchanges code for token
6. Session established, query executed

**Use case:** Grafana dashboards, human users

#### Option 2: mTLS (Recommended for machines)

```yaml
tenants:
  - name: tenant-beta
    mTLS: {}  # Uses global CA from --tls.client-ca-file
```

**Flow:**
1. Client connects with certificate (verified by global CA)
2. Gateway checks certificate is present and verified
3. Extracts subject and groups from certificate
4. Query executed with tenant from URL path

**Use case:** Automated queries, machine-to-machine

#### Option 3: OpenShift

```yaml
tenants:
  - name: tenant-gamma
    openshift:
      serviceAccount: mcoa-gateway
      kubeconfig: /etc/kubeconfig
```

**Use case:** OpenShift clusters with service account tokens

**Read Endpoints:**
- `GET /api/metrics/v1/{tenant}/api/v1/query` - Prometheus instant query
- `GET /api/metrics/v1/{tenant}/api/v1/query_range` - Prometheus range query
- `GET /api/logs/v1/{tenant}/loki/api/v1/query` - Loki query
- `GET /api/traces/v1/{tenant}/api/traces/{traceID}` - Tempo trace lookup

---

## Rate Limiting

### Configuration

Rate limits are configured **per tenant** in `tenants.yaml`:

```yaml
tenants:
  - name: tenant-alpha
    oidc: {...}
    rateLimits:
      - endpoint: ".*receive.*"     # Regex matching endpoint path
        limit: 1000                 # Requests per second
        window: 1s                  # Time window
        failOpen: true              # Fail open on rate limiter errors
        retryAfterMin: 10s          # Min Retry-After header value
        retryAfterMax: 5m           # Max Retry-After header value
```

### Rate Limiter Backends

Configure via `--middleware.rate-limiter.*` flags:

#### Local (Default)

```bash
--middleware.rate-limiter.type=local
```

- In-memory rate limiting
- Per-instance (not shared across multiple gateways)
- No external dependencies
- Good for: Single instance deployments

#### Redis (Leaky Bucket)

```bash
--middleware.rate-limiter.type=redis \
--middleware.rate-limiter.address=redis://localhost:6379 \
--middleware.rate-limiter.address=redis://localhost:6380  # Can specify multiple for cluster
```

- Shared rate limiting across multiple gateway instances
- Uses leaky bucket algorithm
- Requires: Redis server or cluster
- Good for: Multi-instance deployments

#### gRPC Rate Limiter

```bash
--middleware.grpc-rate-limiter.address=localhost:8081
```

- External rate limiter service (e.g., Envoy Ratelimit)
- Most flexible, can implement custom logic
- Requires: gRPC rate limiter service
- Good for: Complex rate limiting scenarios

### Rate Limit Behavior

**When rate limit exceeded:**
1. Request rejected with `429 Too Many Requests`
2. `Retry-After` header set (if configured)
3. Prometheus remote write respects `Retry-After` and backs off

**Retry-After backoff:**
- First rejection: `retryAfterMin` (e.g., 10s)
- Each subsequent: doubled (20s, 40s, 80s, ...)
- Capped at: `retryAfterMax` (e.g., 5m)

**Fail open/closed:**
- `failOpen: true` - If rate limiter unavailable, allow request
- `failOpen: false` - If rate limiter unavailable, reject request

### Example Configurations

**Separate write/read limits:**
```yaml
tenants:
  - name: tenant-alpha
    oidc: {...}
    rateLimits:
      - endpoint: ".*receive.*"      # Write path
        limit: 10000
        window: 1s
      - endpoint: ".*query.*"        # Read path
        limit: 100
        window: 1s
```

**Per-endpoint limits:**
```yaml
tenants:
  - name: tenant-beta
    mTLS: {}
    rateLimits:
      - endpoint: "/api/metrics/v1/api/v1/receive"
        limit: 5000
        window: 1s
      - endpoint: "/api/logs/v1/loki/api/v1/push"
        limit: 2000
        window: 1s
```

---

## Examples

### Complete Production Setup

```bash
#!/bin/bash

# Start MCOA Gateway
./mcoa-gateway \
  # Server
  --web.listen=:8080 \
  --web.internal.listen=:8081 \
  --log.level=info \
  --log.format=json \
  \
  # TLS - Server
  --tls.server.cert-file=/etc/mcoa/certs/server.crt \
  --tls.server.key-file=/etc/mcoa/certs/server.key \
  --tls.min-version=VersionTLS13 \
  --tls.reload-interval=5m \
  \
  # TLS - Client Certificate Verification (mTLS)
  --tls.client-ca-file=/etc/mcoa/certs/client-ca.crt \
  --tls.client-auth-type=RequireAndVerifyClientCert \
  \
  # Tenants
  --tenants.config=/etc/mcoa/tenants.yaml \
  \
  # Metrics Backend (Thanos)
  --metrics.write.endpoint=https://thanos-receive:19291/api/v1/receive \
  --metrics.read.endpoint=https://thanos-query:9090/api/v1 \
  --metrics.rules.endpoint=https://thanos-ruler:9090/api/v1 \
  --metrics.tls.ca-file=/etc/mcoa/certs/thanos-ca.crt \
  --metrics.tls.cert-file=/etc/mcoa/certs/gateway-client.crt \
  --metrics.tls.key-file=/etc/mcoa/certs/gateway-client.key \
  --metrics.tls.watch-certs=true \
  --metrics.tenant-header=THANOS-TENANT \
  --metrics.tenant-label=tenant_id \
  \
  # Logs Backend (Loki)
  --logs.write.endpoint=https://loki:3100/loki/api/v1/push \
  --logs.read.endpoint=https://loki:3100 \
  --logs.tls.ca-file=/etc/mcoa/certs/loki-ca.crt \
  --logs.tls.cert-file=/etc/mcoa/certs/gateway-client.crt \
  --logs.tls.key-file=/etc/mcoa/certs/gateway-client.key \
  --logs.tenant-header=X-Scope-OrgID \
  \
  # Rate Limiting (Redis)
  --middleware.rate-limiter.type=redis \
  --middleware.rate-limiter.address=redis://redis-1:6379 \
  --middleware.rate-limiter.address=redis://redis-2:6379 \
  --middleware.rate-limiter.address=redis://redis-3:6379
```

### Prometheus Remote Write Configuration

```yaml
# prometheus.yml
remote_write:
  - url: https://gateway.example.com/api/metrics/v1/api/v1/receive
    tls_config:
      # Server CA (to verify gateway's server certificate)
      ca_file: /etc/prometheus/certs/server-ca.crt
      # Client certificate (must have OU=tenant-alpha)
      cert_file: /etc/prometheus/certs/tenant-alpha.crt
      key_file: /etc/prometheus/certs/tenant-alpha.key
    # Remote write respects Retry-After headers
    queue_config:
      max_backoff: 5m
```

### Grafana Data Source Configuration

```yaml
# grafana-datasource.yaml
apiVersion: 1
datasources:
  - name: MCOA Metrics (tenant-alpha)
    type: prometheus
    access: proxy
    url: https://gateway.example.com/api/metrics/v1/tenant-alpha
    jsonData:
      httpMethod: GET
      # Uses OIDC authentication - Grafana will redirect to login
```

### Multi-Tenant Query (Admin Use Case)

Query multiple tenants with a single authenticated user:

```yaml
# tenants.yaml - single admin tenant
tenants:
  - name: admin
    oidc:
      clientID: grafana
      clientSecret: secret
      issuerURL: https://auth.example.com
      redirectURL: https://gateway.example.com/oidc/admin/callback
```

```bash
# Query multiple tenants (tenant-alpha and tenant-beta)
# Note: Authenticates as "admin", but queries tenant-alpha and tenant-beta data
curl -G https://gateway.example.com/api/metrics/v1/api/v1/query \
  -H "THANOS-TENANT: tenant-alpha|tenant-beta" \
  --data-urlencode 'query=up' \
  # Uses OIDC session for "admin" tenant

# Or using multiple headers
curl -G https://gateway.example.com/api/metrics/v1/api/v1/query \
  -H "THANOS-TENANT: tenant-alpha" \
  -H "THANOS-TENANT: tenant-beta" \
  --data-urlencode 'query=up'

# Query ALL tenants (useful for aggregated dashboards)
curl -G https://gateway.example.com/api/metrics/v1/api/v1/query \
  -H "THANOS-TENANT: tenant-1|tenant-2|tenant-3|...|tenant-100" \
  --data-urlencode 'query=sum(up) by (tenant_id)'
```

**Use case:** Grafana dashboard with admin OIDC login can query all tenant data without listing every tenant in tenants.yaml.

---

## Certificate Setup

### Architecture Overview

MCOA Gateway uses **three types of certificates**:

1. **Server certificate** - For HTTPS (clients verify gateway)
2. **Client CA certificate** - For mTLS (gateway verifies clients)
3. **Upstream client certificate** - For mTLS to backends (optional)

```
┌──────────┐  ①verify    ┌─────────┐  ③verify   ┌─────────┐
│  Client  │────────────▶│ Gateway │───────────▶│ Backend │
│          │             │         │            │ (Thanos)│
│  ②present│             │ ④present│            │         │
│    cert  │             │   cert  │            │         │
└──────────┘             └─────────┘            └─────────┘
     │                        │                      │
     │ signed by              │ signed by            │ signed by
     ▼                        ▼                      ▼
┌──────────┐             ┌─────────┐            ┌─────────┐
│ Client   │             │ Server  │            │ Backend │
│   CA     │             │  Cert   │            │   CA    │
└──────────┘             └─────────┘            └─────────┘
  (gateway                (gateway                (backend
   has this)               has this)               has this)
```

### Step 1: Create Server Certificate

**Gateway's HTTPS certificate:**

```bash
# Generate server private key
openssl genrsa -out server.key 4096

# Create server certificate
openssl req -new -x509 -days 365 -key server.key -out server.crt \
  -subj "/CN=gateway.example.com/O=MyOrg" \
  -addext "subjectAltName=DNS:gateway.example.com,DNS:localhost,IP:127.0.0.1"

# Verify
openssl x509 -in server.crt -text -noout
```

### Step 2: Create Client CA

**CA for verifying client certificates (global CA):**

```bash
# Generate CA private key
openssl genrsa -out client-ca.key 4096

# Create CA certificate
openssl req -new -x509 -days 3650 -key client-ca.key -out client-ca.crt \
  -subj "/CN=MCOA Client CA/O=MyOrg"

# Verify
openssl x509 -in client-ca.crt -text -noout

# IMPORTANT: Protect the CA private key!
chmod 400 client-ca.key
```

### Step 3: Create Client Certificates

**For write path (must have OU field):**

```bash
# Generate client private key
openssl genrsa -out tenant-alpha.key 2048

# Create CSR with OU field (IMPORTANT: OU = tenant name)
openssl req -new -key tenant-alpha.key -out tenant-alpha.csr \
  -subj "/CN=prometheus-tenant-alpha/OU=tenant-alpha/O=MyOrg"
#                                         ^^^^^^^^^^^^
#                                         Must match tenant name!

# Sign with client CA
openssl x509 -req -in tenant-alpha.csr \
  -CA client-ca.crt -CAkey client-ca.key -CAcreateserial \
  -out tenant-alpha.crt -days 365 -sha256

# Verify
openssl verify -CAfile client-ca.crt tenant-alpha.crt
# Output: tenant-alpha.crt: OK

# Check OU field
openssl x509 -in tenant-alpha.crt -text -noout | grep OU
# Output: Subject: CN = prometheus-tenant-alpha, OU = tenant-alpha, O = MyOrg
```

**For read path (OU field optional):**

```bash
# Generate user key
openssl genrsa -out user.key 2048

# Create CSR (no OU requirement for read path)
openssl req -new -key user.key -out user.csr \
  -subj "/CN=user@example.com/O=MyOrg"

# Sign with client CA
openssl x509 -req -in user.csr \
  -CA client-ca.crt -CAkey client-ca.key -CAcreateserial \
  -out user.crt -days 365 -sha256
```

### Step 4: Create Upstream Client Certificate (Optional)

**For mTLS to backends (Thanos/Loki):**

```bash
# Generate gateway client key
openssl genrsa -out gateway-client.key 2048

# Create CSR
openssl req -new -key gateway-client.key -out gateway-client.csr \
  -subj "/CN=mcoa-gateway/O=MyOrg"

# Sign with your upstream CA (Thanos/Loki CA)
openssl x509 -req -in gateway-client.csr \
  -CA thanos-ca.crt -CAkey thanos-ca.key -CAcreateserial \
  -out gateway-client.crt -days 365
```

### Certificate Files Summary

| File | Type | Location | Purpose |
|------|------|----------|---------|
| `server.crt` | Server cert | Gateway | Gateway's HTTPS certificate |
| `server.key` | Private key | Gateway | Gateway's HTTPS private key |
| `client-ca.crt` | CA cert | Gateway | Verify client certificates |
| `client-ca.key` | CA key | **Secure storage** | Sign new client certs |
| `tenant-*.crt` | Client cert | Clients | Client authentication |
| `tenant-*.key` | Private key | Clients | Client authentication |
| `gateway-client.crt` | Client cert | Gateway | Gateway→Backend mTLS |
| `gateway-client.key` | Private key | Gateway | Gateway→Backend mTLS |
| `thanos-ca.crt` | CA cert | Gateway | Verify Thanos server cert |

### Certificate Rotation

**Automatic rotation (recommended):**

```bash
# Enable certificate watching
--tls.reload-interval=5m \
--metrics.tls.watch-certs=true \
--logs.tls.watch-certs=true
```

**How it works:**
1. Gateway watches certificate files every `reload-interval`
2. When file changes detected, new certificate loaded
3. No restart required
4. Old connections continue, new connections use new cert

**Manual rotation:**

```bash
# 1. Generate new certificates (same filenames)
# 2. Replace old files
cp new-server.crt /etc/mcoa/certs/server.crt
cp new-server.key /etc/mcoa/certs/server.key

# 3. Wait for reload interval or restart
# With --tls.reload-interval=5m, picked up within 5 minutes
```

---

## Testing

### Test Server TLS

```bash
# Test HTTPS connection
openssl s_client -connect localhost:8080 -showcerts

# Check certificate details
echo | openssl s_client -connect localhost:8080 2>/dev/null | openssl x509 -noout -text
```

### Test mTLS Write Path

```bash
# Test with valid client certificate
curl -v -X POST https://localhost:8080/api/metrics/v1/api/v1/receive \
  --cert tenant-alpha.crt \
  --key tenant-alpha.key \
  --cacert server.crt \
  -H "Content-Type: application/x-protobuf" \
  --data-binary @metrics.pb
# Expected: 200 OK (or 400 if data invalid)

# Test without client certificate
curl -v -X POST https://localhost:8080/api/metrics/v1/api/v1/receive \
  --cacert server.crt \
  -H "Content-Type: application/x-protobuf" \
  --data-binary @metrics.pb
# Expected: SSL error or 401 Unauthorized

# Test with invalid client certificate
curl -v -X POST https://localhost:8080/api/metrics/v1/api/v1/receive \
  --cert invalid.crt \
  --key invalid.key \
  --cacert server.crt \
  -H "Content-Type: application/x-protobuf" \
  --data-binary @metrics.pb
# Expected: SSL certificate verification failed
```

### Test Read Path (mTLS)

```bash
# Query with mTLS
curl -G https://localhost:8080/api/metrics/v1/tenant-alpha/api/v1/query \
  --data-urlencode 'query=up' \
  --cert tenant-alpha.crt \
  --key tenant-alpha.key \
  --cacert server.crt
# Expected: 200 OK with query results
```

### Test Read Path (OIDC)

```bash
# OIDC requires browser interaction
# Navigate to: https://localhost:8080/api/metrics/v1/tenant-alpha/api/v1/query?query=up
# Expected: Redirect to OIDC provider login page
```

### Test Rate Limiting

```bash
# Send requests until rate limit hit
for i in {1..1100}; do
  curl -X POST https://localhost:8080/api/metrics/v1/api/v1/receive \
    --cert tenant-alpha.crt \
    --key tenant-alpha.key \
    --cacert server.crt \
    -H "Content-Type: application/x-protobuf" \
    --data-binary @metrics.pb
done
# Expected: First 1000 succeed (200), then 429 Too Many Requests with Retry-After header
```

### Test Health Endpoints

```bash
# Liveness
curl http://localhost:8081/live
# Expected: 200 OK

# Readiness
curl http://localhost:8081/ready
# Expected: 200 OK if all backends healthy
```

### Integration Tests

```bash
# Run full test suite
make test

# Run unit tests only
make test-unit

# Run end-to-end tests (requires Docker)
make test-e2e

# Run interactive test environment
make test-interactive
# Starts: Gateway + Thanos + Loki + OIDC provider in Docker
# Test stays running - Ctrl+C to stop

# Run load tests
make test-load
```

### Build Commands (Makefile)

```bash
# Build binary
make build
# Output: ./mcoa-gateway

# Build with all checks (lint, test, generate)
make all

# Format code
make format

# Run linter
make lint

# Clean build artifacts
make clean

# Build container image
make container
# Creates: quay.io/stolostron/mcoa-gateway:latest

# Generate code (protobuf, OpenAPI client, etc.)
make generate
```

---

## Troubleshooting

### Common Issues

**1. "no client certificate presented"**
```
Problem: Client not sending certificate
Solution: Add --cert and --key to curl command
         Check client has valid certificate
```

**2. "TLS certificate verification failed"**
```
Problem: Client certificate not signed by global CA
Solution: Verify certificate chain:
         openssl verify -CAfile client-ca.crt client.crt
         Re-issue certificate signed by correct CA
```

**3. "tenant not found in certificate OU"**
```
Problem: Write path requires OU field in certificate
Solution: Create certificate with OU field:
         openssl req -subj "/CN=client/OU=tenant-alpha/O=Org"
```

**4. "client authentication requires verification but no client CA file provided"**
```
Problem: --tls.client-auth-type=RequireAndVerifyClientCert but no --tls.client-ca-file
Solution: Provide CA file:
         --tls.client-ca-file=/path/to/client-ca.crt
```

**5. Rate limit "429 Too Many Requests"**
```
Problem: Exceeded tenant rate limit
Solution: Check Retry-After header
         Wait before retrying
         Or increase rate limit in tenants.yaml
```

### Debug Logging

```bash
# Enable debug logging
--log.level=debug

# Watch for authentication events
level=debug msg="authenticated via mTLS" tenant=tenant-alpha subject=client@example.com
level=debug msg="no client certificate presented"
level=debug msg="tenant extracted from certificate" tenant=tenant-alpha

# Watch for rate limiting
level=debug msg="rate limit exceeded" tenant=tenant-alpha endpoint=/api/metrics/v1/api/v1/receive
```

---

## Security Best Practices

### Certificate Management

1. **Protect CA private keys** - Store in secure location, use HSM for production
   ```bash
   chmod 400 client-ca.key
   ```

2. **Use short-lived certificates** - Issue 30-day certs instead of 365-day
   ```bash
   -days 30
   ```

3. **Automate rotation** - Use cert-manager or similar for automatic renewal

4. **Monitor expiry** - Alert before certificates expire
   ```bash
   openssl x509 -in cert.crt -noout -enddate
   ```

### TLS Configuration

1. **Use TLS 1.3** - Disable older versions
   ```bash
   --tls.min-version=VersionTLS13
   ```

2. **Client certificate verification** - Always verify for write path
   ```bash
   --tls.client-auth-type=RequireAndVerifyClientCert
   ```

3. **Proper CA management** - Don't reuse CAs across environments

### Rate Limiting

1. **Set conservative defaults** - Start with lower limits, increase as needed

2. **Use fail-closed for critical tenants** - `failOpen: false`

3. **Monitor rate limit metrics** - Alert on sustained 429 responses

### Network Security

1. **Isolate backend network** - Backends should not be directly accessible

2. **Use mTLS to backends** - Configure `--metrics.tls.*` for upstream connections

3. **Firewall rules** - Only allow necessary ports

---

## License

Apache License 2.0

## Contributing

Contributions welcome! Please open an issue or pull request.

## Support

For issues and questions, please open a GitHub issue.
