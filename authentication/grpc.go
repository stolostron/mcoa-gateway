package authentication

import (
	"context"
	"strings"

	"github.com/go-kit/log"
	grpc_middleware_auth "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	_ "google.golang.org/grpc/encoding/gzip" // Allow GRPC to handle GZipped streams
)

// GRPCMiddlewareFunc is a function type able to return authentication middleware for
// a given tenant. If no middleware is found, the second return value should be false.
type GRPCMiddlewareFunc func(tenant string) (grpc.StreamServerInterceptor, bool)

func WithGRPCAccessToken() grpc.StreamServerInterceptor {
	return grpc_middleware_auth.StreamServerInterceptor(func(ctx context.Context) (context.Context, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Internal, "metadata error")
		}
		rawTokens := md["authorization"]
		if len(rawTokens) == 0 {
			return ctx, status.Error(codes.Unauthenticated, "error no access token")
		}
		rawToken := rawTokens[len(rawTokens)-1]
		token := rawToken[strings.LastIndex(rawToken, " ")+1:]
		return context.WithValue(ctx, accessTokenKey, token), nil
	})
}

// WithGRPCTenantInterceptors creates a single Middleware for all
// provided tenant-middleware sets.
func WithGRPCTenantInterceptors(logger log.Logger, mwFns ...GRPCMiddlewareFunc) grpc.StreamServerInterceptor {
	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		tenant, ok := GetTenant(ss.Context())
		if !ok {
			return status.Error(codes.InvalidArgument, "error finding tenant")
		}

		for _, mwFn := range mwFns {
			if m, ok := mwFn(tenant); ok {
				return m(srv, ss, info, handler)
			}
		}

		return status.Error(codes.PermissionDenied, "tenant not found, have you registered it?")
	}
}
