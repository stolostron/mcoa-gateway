package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
)

type fakeBackend struct {
	server       *httptest.Server
	requestCount atomic.Int64
	lastBody     []byte
	lastPath     string
	mu           sync.Mutex
}

func newFakeBackend(t *testing.T) *fakeBackend {
	t.Helper()
	fb := &fakeBackend{}
	fb.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("fake backend: reading body: %v", err)
		}
		defer r.Body.Close()
		fb.mu.Lock()
		fb.lastBody = body
		fb.lastPath = r.URL.Path
		fb.mu.Unlock()
		fb.requestCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fb.server.Close)
	return fb
}

func (fb *fakeBackend) url() string {
	return fb.server.URL
}

func (fb *fakeBackend) count() int64 {
	return fb.requestCount.Load()
}

func (fb *fakeBackend) body() []byte {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	out := make([]byte, len(fb.lastBody))
	copy(out, fb.lastBody)
	return out
}

func (fb *fakeBackend) path() string {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	return fb.lastPath
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse URL %q: %v", raw, err)
	}
	return u
}

func TestFanout_SendsToAllEndpoints(t *testing.T) {
	backends := make([]*fakeBackend, 3)
	endpoints := make([]*url.URL, 3)
	for i := range backends {
		backends[i] = newFakeBackend(t)
		endpoints[i] = mustParseURL(t, backends[i].url())
	}

	client := &http.Client{}
	handler := FanoutRequestToEndpoints(client, endpoints, "/api/v1/items", log.NewNopLogger(), NewFanoutMetrics(prometheus.NewRegistry()))

	payload := []byte(`{"event":"fanout-test"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/items", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	deadline := time.After(2 * time.Second)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		allReceived := true
		for _, b := range backends {
			if b.count() < 1 {
				allReceived = false
				break
			}
		}
		if allReceived {
			break
		}
		select {
		case <-deadline:
			for i, b := range backends {
				if b.count() == 0 {
					t.Errorf("backend %d never received a request", i)
				}
			}
			t.FailNow()
		case <-tick.C:
		}
	}

	for i, b := range backends {
		if got := b.body(); !bytes.Equal(got, payload) {
			t.Errorf("backend %d: body = %q, want %q", i, got, payload)
		}
		if got := b.path(); got != "/api/v1/items" {
			t.Errorf("backend %d: path = %q, want %q", i, got, "/api/v1/items")
		}
	}
}

func TestFanout_UsesConfiguredRoutePath(t *testing.T) {
	backend := newFakeBackend(t)
	endpoints := []*url.URL{mustParseURL(t, backend.url())}

	client := &http.Client{}
	const routePath = "/api/v1/items"
	handler := FanoutRequestToEndpoints(client, endpoints, routePath, log.NewNopLogger(), NewFanoutMetrics(prometheus.NewRegistry()))

	for _, requestPath := range []string{"/incoming/one", "/incoming/two"} {
		req := httptest.NewRequest(http.MethodPost, requestPath, bytes.NewReader([]byte(`[]`)))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		waitForBackends(t, []*fakeBackend{backend}, backend.count())

		if got := backend.path(); got != routePath {
			t.Errorf("request to %s: backend received path %q, want %q", requestPath, got, routePath)
		}
	}
}

func TestFanout_EmptyEndpoints(t *testing.T) {
	client := &http.Client{}
	handler := FanoutRequestToEndpoints(client, nil, "/api/v1/items", log.NewNopLogger(), NewFanoutMetrics(prometheus.NewRegistry()))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/items", bytes.NewReader([]byte(`[]`)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("empty endpoints: got status %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func waitForBackends(t *testing.T, backends []*fakeBackend, wantCount int64) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		allReady := true
		for _, b := range backends {
			if b.count() < wantCount {
				allReady = false
				break
			}
		}
		if allReady {
			return
		}
		select {
		case <-deadline:
			for i, b := range backends {
				if b.count() < wantCount {
					t.Errorf("backend %d: got %d requests, want at least %d", i, b.count(), wantCount)
				}
			}
			t.FailNow()
		case <-tick.C:
		}
	}
}
