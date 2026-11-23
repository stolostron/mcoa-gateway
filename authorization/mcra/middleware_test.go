package mcra

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-kit/log"

	"github.com/stolostron/mcoa-gateway/authentication"
)

func TestMiddlewareRewritesAdmittedTenant(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	mw := NewMiddleware(Options{
		TTL:    time.Hour,
		Logger: log.NewNopLogger(),
		now:    func() time.Time { return time.Unix(50, 0) },
		loader: funcLoader(func(ctx context.Context) (grantIndex, error) {
			calls.Add(1)
			if err := tokenNotVisible(ctx); err != nil {
				return grantIndex{}, err
			}
			return userGrant("cluster-a", "cluster-c"), nil
		}),
	})
	got := runMiddleware(t, mw, "user-token", "THANOS-TENANT", "cluster-b|cluster-a", "alice", []string{"g"})
	if got.code != http.StatusNoContent || !got.next {
		t.Fatalf("code=%d next=%t body=%s", got.code, got.next, got.errMsg)
	}
	if got.tenant != "cluster-a" || got.header != "cluster-a" || got.requestHeader != "cluster-a" {
		t.Fatalf("tenant=%q header=%q request=%q", got.tenant, got.header, got.requestHeader)
	}
	again := runMiddleware(t, mw, "user-token", "THANOS-TENANT", "cluster-b|cluster-a", "alice", nil)
	if again.tenant != "cluster-a" || calls.Load() != 1 {
		t.Fatalf("second tenant=%q calls=%d", again.tenant, calls.Load())
	}

	both := runMiddleware(t, mw, "user-token", "THANOS-TENANT", "cluster-c|cluster-a", "alice", nil)
	if both.tenant != "cluster-c|cluster-a" || both.header != "cluster-c|cluster-a" {
		t.Fatalf("tenant=%q header=%q", both.tenant, both.header)
	}
}

func TestMiddlewareFailClosed(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	now := func() time.Time { return time.Unix(1, 0) }
	allowed := funcLoader(func(ctx context.Context) (grantIndex, error) {
		calls.Add(1)
		return userGrant("cluster-z"), nil
	})
	mw := NewMiddleware(Options{Logger: log.NewNopLogger(), loader: allowed, now: now, TTL: time.Hour})
	denied := runMiddleware(t, mw, "user-token", "THANOS-TENANT", "cluster-a|cluster-b", "alice", nil)
	if denied.next || denied.code != http.StatusForbidden || denied.errMsg != "no access to the requested clusters" {
		t.Fatalf("denied = %+v", denied)
	}
	if denied.requestHeader != "cluster-a|cluster-b" {
		t.Fatalf("request header = %q", denied.requestHeader)
	}

	missing := runMiddleware(t, mw, "super-secret-token", "THANOS-TENANT", "cluster-a", "", nil)
	if missing.next || missing.code != http.StatusUnauthorized || missing.errMsg != "subject credential required" {
		t.Fatalf("missing = %+v", missing)
	}
	if missing.requestHeader != "cluster-a" {
		t.Fatalf("missing creds wrote header %q", missing.requestHeader)
	}
	if calls.Load() != 1 {
		t.Fatalf("missing subject called Load, calls=%d", calls.Load())
	}

	logger := &captureLogger{}
	hubDenied := NewMiddleware(Options{
		Logger: logger,
		now:    now,
		TTL:    time.Hour,
		loader: funcLoader(func(ctx context.Context) (grantIndex, error) {
			if err := tokenNotVisible(ctx); err != nil {
				return grantIndex{}, err
			}
			return grantIndex{}, errHubDenied
		}),
	})
	got := runMiddleware(t, hubDenied, "super-secret-token", "X-Scope-OrgID", "cluster-a", "alice", nil)
	if got.next || got.code != http.StatusForbidden || got.errMsg != "cannot evaluate cluster access" {
		t.Fatalf("hub denied = %+v", got)
	}
	if got.requestHeader != "cluster-a" {
		t.Fatalf("hub denied wrote header %q", got.requestHeader)
	}
	logged := fmt.Sprint(logger.got)
	if !strings.Contains(logged, "alice") {
		t.Fatalf("log = %s", logged)
	}
	if strings.Contains(logged, "super-secret-token") {
		t.Fatalf("log contains the bearer token: %s", logged)
	}

	unavailable := NewMiddleware(Options{
		now: now,
		TTL: time.Hour,
		loader: funcLoader(func(ctx context.Context) (grantIndex, error) {
			return grantIndex{}, errHubUnavailable
		}),
	})
	got = runMiddleware(t, unavailable, "user-token", "THANOS-TENANT", "cluster-a", "alice", nil)
	if got.next || got.code != http.StatusServiceUnavailable || got.errMsg != "cannot evaluate cluster access" {
		t.Fatalf("unavailable = %+v", got)
	}
}

func TestMiddlewareRejectsMissingContext(t *testing.T) {
	t.Parallel()

	mw := NewMiddleware(Options{
		Logger: log.NewNopLogger(),
		now:    func() time.Time { return time.Unix(1, 0) },
		loader: funcLoader(func(ctx context.Context) (grantIndex, error) {
			t.Fatal("list called without a tenant")
			return grantIndex{}, nil
		}),
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("THANOS-TENANT", "cluster-a")
	rec := httptest.NewRecorder()
	next := false
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { next = true })).ServeHTTP(rec, req)
	if next || rec.Code != http.StatusBadRequest || prometheusError(t, rec) != "error finding tenant" {
		t.Fatalf("code=%d next=%t body=%s", rec.Code, next, rec.Body.String())
	}
	if req.Header.Get("THANOS-TENANT") != "cluster-a" {
		t.Fatalf("header = %q", req.Header.Get("THANOS-TENANT"))
	}

	ctx := authentication.WithTenantValue(req.Context(), "cluster-a")
	req = httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer user-token")
	req.Header.Set("THANOS-TENANT", "cluster-a")
	rec = httptest.NewRecorder()
	next = false
	mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { next = true })).ServeHTTP(rec, req)
	if next || rec.Code != http.StatusInternalServerError || prometheusError(t, rec) != "tenant header is not in the request context" {
		t.Fatalf("code=%d next=%t body=%s", rec.Code, next, rec.Body.String())
	}
	if req.Header.Get("THANOS-TENANT") != "cluster-a" {
		t.Fatalf("header = %q", req.Header.Get("THANOS-TENANT"))
	}
}

func TestNewMiddlewarePrivateIndexesDoNotShare(t *testing.T) {
	t.Parallel()

	var callsA, callsB atomic.Int32
	now := func() time.Time { return time.Unix(1, 0) }
	a := NewMiddleware(Options{
		Kubeconfig: "same",
		TTL:        time.Hour,
		now:        now,
		Logger:     log.NewNopLogger(),
		loader: funcLoader(func(ctx context.Context) (grantIndex, error) {
			callsA.Add(1)
			return userGrant("cluster-a"), nil
		}),
	})
	b := NewMiddleware(Options{
		Kubeconfig: "same",
		TTL:        time.Hour,
		now:        now,
		Logger:     log.NewNopLogger(),
		loader: funcLoader(func(ctx context.Context) (grantIndex, error) {
			callsB.Add(1)
			return userGrant("cluster-b"), nil
		}),
	})
	gotA := runMiddleware(t, a, "user-token", "THANOS-TENANT", "cluster-a|cluster-b", "alice", nil)
	gotB := runMiddleware(t, b, "user-token", "THANOS-TENANT", "cluster-a|cluster-b", "alice", nil)
	againA := runMiddleware(t, a, "user-token", "THANOS-TENANT", "cluster-a|cluster-b", "alice", nil)
	if gotA.tenant != "cluster-a" || gotB.tenant != "cluster-b" || againA.tenant != "cluster-a" {
		t.Fatalf("a=%q b=%q again=%q", gotA.tenant, gotB.tenant, againA.tenant)
	}
	if callsA.Load() != 1 || callsB.Load() != 1 {
		t.Fatalf("calls a=%d b=%d", callsA.Load(), callsB.Load())
	}
}

func TestDeriveMiddleware(t *testing.T) {
	t.Parallel()

	now := func() time.Time { return time.Unix(1, 0) }
	allowed := func(names ...string) authentication.Middleware {
		t.Helper()
		return NewMiddleware(Options{
			Logger: log.NewNopLogger(),
			Mode:   ModeDerive,
			loader: funcLoader(func(ctx context.Context) (grantIndex, error) {
				if err := tokenNotVisible(ctx); err != nil {
					return grantIndex{}, err
				}
				return userGrant(names...), nil
			}),
			now: now,
			TTL: time.Hour,
		})
	}

	dotted := runDerive(t, allowed("cluster.a", "b"), "THANOS-TENANT", true, "other")
	if dotted.code != http.StatusNoContent || !dotted.next || dotted.tenant != "b|cluster.a" || dotted.header != "b|cluster.a" {
		t.Fatalf("dotted = %+v", dotted)
	}
	if dotted.requestHeader != "b|cluster.a" {
		t.Fatalf("client header was not replaced: %q", dotted.requestHeader)
	}

	missing := runDerive(t, allowed("cluster.a", "b"), "THANOS-TENANT", false, "")
	if missing.code != http.StatusNoContent || !missing.next || missing.tenant != "b|cluster.a" || missing.requestHeader != "b|cluster.a" {
		t.Fatalf("missing header = %+v", missing)
	}

	overridden := runDerive(t, allowed("a", "b"), "THANOS-TENANT", true, "not-allowed|also-no")
	if overridden.tenant != "a|b" || overridden.requestHeader != "a|b" || !overridden.next {
		t.Fatalf("override = %+v", overridden)
	}

	empty := runDerive(t, allowed(), "THANOS-TENANT", true, "cluster-a")
	if empty.next || empty.code != http.StatusForbidden || empty.errMsg != "no access to any cluster" {
		t.Fatalf("empty = %+v", empty)
	}
	if empty.requestHeader != "cluster-a" {
		t.Fatalf("empty allow-list wrote header %q", empty.requestHeader)
	}

	logger := &captureLogger{}
	capped := NewMiddleware(Options{
		Logger:     logger,
		Mode:       ModeDerive,
		MaxTenants: 2,
		now:        now,
		TTL:        time.Hour,
		loader: funcLoader(func(ctx context.Context) (grantIndex, error) {
			return userGrant("secret-cluster", "b", "a"), nil
		}),
	})
	over := runDerive(t, capped, "THANOS-TENANT", true, "client-name")
	if over.next || over.code != http.StatusBadRequest || over.errMsg != "too many tenants (max 2)" {
		t.Fatalf("over max = %+v", over)
	}
	if over.requestHeader != "client-name" {
		t.Fatalf("over max wrote header %q", over.requestHeader)
	}
	logged := fmt.Sprint(logger.got)
	if strings.Contains(logged, "secret-cluster") || strings.Contains(logged, "client-name") {
		t.Fatalf("log names a cluster: %s", logged)
	}
	if !strings.Contains(logged, "3") || !strings.Contains(logged, "2") {
		t.Fatalf("log = %s", logged)
	}

	atCap := runDerive(t, allowed("a", "b"), "X-Scope-OrgID", false, "")
	if atCap.code != http.StatusNoContent || atCap.tenant != "a|b" {
		t.Fatalf("under default cap = %+v", atCap)
	}
}

func TestDeriveMiddlewareDefaultCap(t *testing.T) {
	t.Parallel()

	now := func() time.Time { return time.Unix(1, 0) }
	names := make([]string, 101)
	for i := range names {
		names[i] = fmt.Sprintf("c%03d", i)
	}
	over := NewMiddleware(Options{
		Logger: log.NewNopLogger(),
		Mode:   ModeDerive,
		loader: funcLoader(func(ctx context.Context) (grantIndex, error) {
			return userGrant(names...), nil
		}),
		now: now,
		TTL: time.Hour,
	})
	got := runDerive(t, over, "THANOS-TENANT", false, "")
	if got.next || got.code != http.StatusBadRequest || got.errMsg != "too many tenants (max 100)" {
		t.Fatalf("101 with default cap = %+v", got)
	}
	if got.requestHeader != "" {
		t.Fatalf("default cap wrote header %q", got.requestHeader)
	}

	exact := make([]string, 100)
	copy(exact, names)
	atCap := NewMiddleware(Options{
		Logger:     log.NewNopLogger(),
		Mode:       ModeDerive,
		MaxTenants: -1,
		loader: funcLoader(func(ctx context.Context) (grantIndex, error) {
			return userGrant(exact...), nil
		}),
		now: now,
		TTL: time.Hour,
	})
	got = runDerive(t, atCap, "THANOS-TENANT", false, "")
	if got.code != http.StatusNoContent || !got.next {
		t.Fatalf("100 with negative cap = %+v", got)
	}
	if strings.Count(got.tenant, "|") != 99 || !strings.HasPrefix(got.tenant, "c000|") || !strings.HasSuffix(got.tenant, "|c099") {
		t.Fatalf("joined = %q", got.tenant)
	}
}

func TestDeriveMiddlewareRejectsClientTenant(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	mw := NewMiddleware(Options{
		Logger: log.NewNopLogger(),
		Mode:   ModeDerive,
		now:    func() time.Time { return time.Unix(1, 0) },
		TTL:    time.Hour,
		loader: funcLoader(func(ctx context.Context) (grantIndex, error) {
			calls.Add(1)
			return userGrant("cluster-a"), nil
		}),
	})
	var result httpResult
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result.next = true
		w.WriteHeader(http.StatusNoContent)
	})
	handler := authentication.WithAccessToken()(
		authentication.WithTenantFromHeader("THANOS-TENANT")(mw(next)),
	)
	req := httptest.NewRequest(http.MethodGet, "/query", nil)
	req.Header.Set("Authorization", "Bearer user-token")
	req.Header.Set("THANOS-TENANT", "cluster-a")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	result.code = rec.Code
	result.requestHeader = req.Header.Get("THANOS-TENANT")
	result.errMsg = prometheusError(t, rec)
	if result.next || result.code != http.StatusInternalServerError || result.errMsg != "derive mode received a client tenant" {
		t.Fatalf("client tenant = %+v", result)
	}
	if result.requestHeader != "cluster-a" || calls.Load() != 0 {
		t.Fatalf("header %q calls %d", result.requestHeader, calls.Load())
	}
}

func TestIntersectIgnoresMaxTenants(t *testing.T) {
	t.Parallel()

	names := make([]string, 5)
	for i := range names {
		names[i] = fmt.Sprintf("c%d", i)
	}
	mw := NewMiddleware(Options{
		Logger:     log.NewNopLogger(),
		MaxTenants: 1,
		now:        func() time.Time { return time.Unix(1, 0) },
		TTL:        time.Hour,
		loader: funcLoader(func(ctx context.Context) (grantIndex, error) {
			return userGrant(names...), nil
		}),
	})
	got := runMiddleware(t, mw, "user-token", "THANOS-TENANT", "c3|c1", "alice", nil)
	if got.code != http.StatusNoContent || got.tenant != "c3|c1" {
		t.Fatalf("intersect = %+v", got)
	}
}

func TestNewMiddlewareRejectsUnknownMode(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Fatal("unknown mode did not panic")
		}
	}()
	NewMiddleware(Options{
		Mode:   Mode(99),
		Logger: log.NewNopLogger(),
		loader: funcLoader(func(ctx context.Context) (grantIndex, error) {
			t.Fatal("unknown mode loaded a hub index")
			return grantIndex{}, nil
		}),
	})
}

func TestNewMiddlewarePanicsWithoutHubConfig(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Fatal("missing hub config did not panic")
		}
	}()
	NewMiddleware(Options{
		Kubeconfig: filepath.Join(t.TempDir(), "missing"),
		Logger:     log.NewNopLogger(),
	})
}

func TestReadChainDerive(t *testing.T) {
	t.Parallel()

	now := func() time.Time { return time.Unix(1, 0) }
	pm := authentication.NewProviderManager(log.NewNopLogger(), nil)
	pm.AddMiddleware(authentication.DefaultTenantName, func(next http.Handler) http.Handler {
		return authentication.WithAccessToken()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := authentication.ContextWithIdentity(r.Context(), "alice", nil)
			next.ServeHTTP(w, r.WithContext(ctx))
		}))
	})

	chain := func(mode Mode, max int, names ...string) authentication.Middleware {
		t.Helper()
		return ReadChain(pm, "THANOS-TENANT", Options{
			Logger:     log.NewNopLogger(),
			Mode:       mode,
			MaxTenants: max,
			TTL:        time.Hour,
			now:        now,
			loader: funcLoader(func(ctx context.Context) (grantIndex, error) {
				if err := tokenNotVisible(ctx); err != nil {
					return grantIndex{}, err
				}
				return userGrant(names...), nil
			}),
		})
	}

	dotted := serveChain(t, chain(ModeDerive, 10, "cluster.a"), true, "cluster.a")
	if dotted.code != http.StatusNoContent || dotted.tenant != "cluster.a" || dotted.requestHeader != "cluster.a" {
		t.Fatalf("dotted = %+v", dotted)
	}

	missing := serveChain(t, chain(ModeDerive, 10, "b", "a"), false, "")
	if missing.code != http.StatusNoContent || !missing.next || missing.tenant != "a|b" || missing.requestHeader != "a|b" {
		t.Fatalf("missing header = %+v", missing)
	}

	overridden := serveChain(t, chain(ModeDerive, 10, "b", "a"), true, "nope")
	if overridden.tenant != "a|b" || overridden.requestHeader != "a|b" || !overridden.next {
		t.Fatalf("override = %+v", overridden)
	}

	empty := serveChain(t, chain(ModeDerive, 10), true, "cluster-a")
	if empty.next || empty.code != http.StatusForbidden || empty.errMsg != "no access to any cluster" || empty.requestHeader != "cluster-a" {
		t.Fatalf("empty = %+v", empty)
	}

	over := serveChain(t, chain(ModeDerive, 1, "secret-cluster", "b"), true, "client-name")
	if over.next || over.code != http.StatusBadRequest || over.errMsg != "too many tenants (max 1)" || over.requestHeader != "client-name" {
		t.Fatalf("over max = %+v", over)
	}

	var listed atomic.Int32
	intersect := ReadChain(pm, "THANOS-TENANT", Options{
		Logger: log.NewNopLogger(),
		TTL:    time.Hour,
		now:    now,
		loader: funcLoader(func(ctx context.Context) (grantIndex, error) {
			listed.Add(1)
			if err := tokenNotVisible(ctx); err != nil {
				return grantIndex{}, err
			}
			return userGrant("a", "b"), nil
		}),
	})
	absent := serveChain(t, intersect, false, "")
	if absent.next || absent.code != http.StatusBadRequest || listed.Load() != 0 {
		t.Fatalf("intersect missing = %+v calls=%d", absent, listed.Load())
	}
	kept := serveChain(t, intersect, true, "b|a")
	if kept.code != http.StatusNoContent || kept.tenant != "b|a" || listed.Load() != 1 {
		t.Fatalf("intersect = %+v calls=%d", kept, listed.Load())
	}
}

func TestHeaderChainRequiresClientHeader(t *testing.T) {
	t.Parallel()

	pm := authentication.NewProviderManager(log.NewNopLogger(), nil)
	var called bool
	pm.AddMiddleware(authentication.DefaultTenantName, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			next.ServeHTTP(w, r)
		})
	})
	mw := HeaderChain(pm, "THANOS-TENANT")

	missing := serveChain(t, mw, false, "")
	if missing.next || missing.code != http.StatusBadRequest || called {
		t.Fatalf("missing = %+v called=%t", missing, called)
	}
	if !strings.Contains(missing.errMsg, "THANOS-TENANT") {
		t.Fatalf("missing error = %q", missing.errMsg)
	}

	got := serveChain(t, mw, true, "team-a")
	if got.code != http.StatusNoContent || !got.next || !called || got.tenant != "team-a" {
		t.Fatalf("header chain = %+v called=%t", got, called)
	}
	if got.errMsg == "subject credential required" {
		t.Fatal("HeaderChain called Load")
	}
}

func TestChainsPanicOnBadArgs(t *testing.T) {
	t.Parallel()

	pm := authentication.NewProviderManager(log.NewNopLogger(), nil)
	mustPanic := func(want string, fn func()) {
		t.Helper()
		defer func() {
			got := recover()
			if got == nil || !strings.Contains(fmt.Sprint(got), want) {
				t.Fatalf("panic = %v, want %q", got, want)
			}
		}()
		fn()
	}
	mustPanic("nil provider manager", func() { ReadChain(nil, "THANOS-TENANT", Options{}) })
	mustPanic("empty tenant header", func() { ReadChain(pm, "", Options{Mode: ModeDerive}) })
	mustPanic("unknown mode", func() {
		ReadChain(pm, "THANOS-TENANT", Options{
			Mode: Mode(99),
			loader: funcLoader(func(ctx context.Context) (grantIndex, error) {
				t.Fatal("unknown mode loaded a hub index")
				return grantIndex{}, nil
			}),
		})
	})
	mustPanic("nil provider manager", func() { HeaderChain(nil, "THANOS-TENANT") })
	mustPanic("empty tenant header", func() { HeaderChain(pm, "") })
}

type httpResult struct {
	code          int
	errMsg        string
	next          bool
	tenant        string
	header        string
	requestHeader string
}

func runMiddleware(t *testing.T, mw authentication.Middleware, token, header, tenant, subject string, groups []string) httpResult {
	t.Helper()
	var result httpResult
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result.next = true
		result.tenant, _ = authentication.GetTenant(r.Context())
		result.header = r.Header.Get(header)
		w.WriteHeader(http.StatusNoContent)
	})
	handler := authentication.WithAccessToken()(
		authentication.WithTenantFromHeader(header)(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if subject != "" || groups != nil {
					r = r.WithContext(authentication.ContextWithIdentity(r.Context(), subject, groups))
				}
				mw(next).ServeHTTP(w, r)
			}),
		),
	)
	req := httptest.NewRequest(http.MethodGet, "/query", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set(header, tenant)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	result.code = rec.Code
	result.requestHeader = req.Header.Get(header)
	if rec.Code != http.StatusNoContent {
		result.errMsg = prometheusError(t, rec)
	}
	return result
}

func serveChain(t *testing.T, mw authentication.Middleware, setHeader bool, clientValue string) httpResult {
	t.Helper()
	const header = "THANOS-TENANT"
	var result httpResult
	req := httptest.NewRequest(http.MethodGet, "/query", nil)
	req.Header.Set("Authorization", "Bearer user-token")
	if setHeader {
		req.Header.Set(header, clientValue)
	}
	rec := httptest.NewRecorder()
	mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result.next = true
		result.tenant, _ = authentication.GetTenant(r.Context())
		result.header = r.Header.Get(header)
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec, req)
	result.code = rec.Code
	result.requestHeader = req.Header.Get(header)
	if rec.Code != http.StatusNoContent {
		result.errMsg = prometheusError(t, rec)
	}
	return result
}

func runDerive(t *testing.T, mw authentication.Middleware, header string, setHeader bool, clientValue string) httpResult {
	t.Helper()
	var result httpResult
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result.next = true
		result.tenant, _ = authentication.GetTenant(r.Context())
		result.header = r.Header.Get(header)
		w.WriteHeader(http.StatusNoContent)
	})
	handler := authentication.WithAccessToken()(
		authentication.WithTenantHeaderName(header)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := authentication.ContextWithIdentity(r.Context(), "alice", nil)
			mw(next).ServeHTTP(w, r.WithContext(ctx))
		})),
	)
	req := httptest.NewRequest(http.MethodGet, "/query", nil)
	req.Header.Set("Authorization", "Bearer user-token")
	if setHeader {
		req.Header.Add(header, clientValue)
		req.Header.Add(header, "second-client-value")
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	result.code = rec.Code
	result.requestHeader = req.Header.Get(header)
	if rec.Code != http.StatusNoContent {
		result.errMsg = prometheusError(t, rec)
	}
	if setHeader && result.next && len(req.Header.Values(header)) != 1 {
		t.Fatalf("header values = %#v", req.Header.Values(header))
	}
	return result
}

func prometheusError(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("status %d body %q: %v", rec.Code, rec.Body.String(), err)
	}
	return body["error"]
}

func tokenNotVisible(ctx context.Context) error {
	token, ok := authentication.GetAccessToken(ctx)
	if ok && token != "" {
		return fmt.Errorf("loader saw token %q", token)
	}
	return nil
}

func userGrant(names ...string) grantIndex {
	set := newClusterSet(names)
	if set.len() == 0 {
		return grantIndex{}
	}
	return grantIndex{byUser: map[string]clusterSet{"alice": set}}
}

type captureLogger struct {
	got []any
}

func (c *captureLogger) Log(keyvals ...any) error {
	c.got = append(c.got, keyvals...)
	return nil
}
