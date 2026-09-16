package authentication

const (
	// state is used for OIDC/OpenShift authentication flows
	state = "I love MCOA Gateway"

	// DefaultTenantName is the special tenant name used as a fallback authenticator
	// when a specific tenant is not configured. This allows the gateway to scale
	// to thousands of tenants without requiring individual tenant configurations.
	//
	// When a request for tenant "my-service" arrives and "my-service" is not
	// configured in tenants.yaml, the gateway will fall back to using the
	// authenticator and rate limits configured for this default tenant.
	//
	// The double-underscore prefix makes it clear this is a reserved/special tenant
	// name that users should not use for their own tenants.
	DefaultTenantName = "__mcoa_default__"
)
