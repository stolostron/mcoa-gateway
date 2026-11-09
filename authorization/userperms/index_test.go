package userperms

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type funcLister func(context.Context, credential) (clusterSet, error)

func (f funcLister) List(ctx context.Context, cred credential) (clusterSet, error) {
	return f(ctx, cred)
}

func TestAccessIndexFreshness(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_000, 0)
	var calls atomic.Int32
	idx := newAccessIndex(30*time.Second, func() time.Time { return now }, funcLister(func(ctx context.Context, cred credential) (clusterSet, error) {
		calls.Add(1)
		if cred.token == "other" {
			return newClusterSet([]string{"cluster-b"}), nil
		}
		return newClusterSet([]string{"cluster-a"}), nil
	}))
	cred := credential{kind: credBearer, token: "tok"}
	set, err := idx.clusterSet(context.Background(), cred)
	if err != nil || !set.has("cluster-a") || set.len() != 1 {
		t.Fatalf("set = %#v, err = %v", set.names, err)
	}
	now = now.Add(29 * time.Second)
	if _, err := idx.clusterSet(context.Background(), cred); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("fresh entry listed again: %d", calls.Load())
	}
	now = now.Add(time.Second)
	if _, err := idx.clusterSet(context.Background(), cred); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("expired entry was reused: %d", calls.Load())
	}
	if _, err := idx.clusterSet(context.Background(), credential{kind: credBearer, token: "other"}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Fatal("a second credential reused the first cluster set")
	}
}

func TestAccessIndexDoesNotCacheErrors(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	fail := true
	idx := newAccessIndex(time.Hour, func() time.Time { return time.Unix(1, 0) }, funcLister(func(ctx context.Context, cred credential) (clusterSet, error) {
		calls.Add(1)
		if fail {
			return clusterSet{}, errHubUnavailable
		}
		return newClusterSet(nil), nil
	}))
	cred := credential{kind: credBearer, token: "tok"}
	if _, err := idx.clusterSet(context.Background(), cred); !errors.Is(err, errHubUnavailable) {
		t.Fatalf("err = %v", err)
	}
	fail = false
	set, err := idx.clusterSet(context.Background(), cred)
	if err != nil {
		t.Fatal(err)
	}
	if set.len() != 0 || calls.Load() != 2 {
		t.Fatalf("len=%d calls=%d", set.len(), calls.Load())
	}
	if _, err := idx.clusterSet(context.Background(), cred); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatal("empty cluster set was not reused")
	}
}

func TestAccessIndexSingleflight(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var calls atomic.Int32
		idx := newAccessIndex(time.Hour, func() time.Time { return time.Unix(1, 0) }, funcLister(func(ctx context.Context, cred credential) (clusterSet, error) {
			calls.Add(1)
			<-release
			return newClusterSet([]string{"cluster-a"}), nil
		}))
		cred := credential{kind: credBearer, token: "tok"}
		errc := make(chan error, 2)
		for range 2 {
			go func() {
				set, err := idx.clusterSet(context.Background(), cred)
				if err != nil || !set.has("cluster-a") {
					errc <- errors.New("leader or waiter missed cluster-a")
					return
				}
				errc <- nil
			}()
		}
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatalf("lists = %d, want 1", calls.Load())
		}
		close(release)
		synctest.Wait()
		for range 2 {
			if err := <-errc; err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestAccessIndexWaiterCancelDoesNotDropResult(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var calls atomic.Int32
		idx := newAccessIndex(time.Hour, func() time.Time { return time.Unix(1, 0) }, funcLister(func(ctx context.Context, cred credential) (clusterSet, error) {
			calls.Add(1)
			<-release
			return newClusterSet([]string{"cluster-a"}), nil
		}))
		cred := credential{kind: credBearer, token: "tok"}
		leaderErr := make(chan error, 1)
		go func() {
			_, err := idx.clusterSet(context.Background(), cred)
			leaderErr <- err
		}()
		synctest.Wait()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := idx.clusterSet(ctx, cred)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waiter err = %v", err)
		}
		close(release)
		synctest.Wait()
		if err := <-leaderErr; err != nil {
			t.Fatal(err)
		}
		if _, err := idx.clusterSet(context.Background(), cred); err != nil {
			t.Fatal(err)
		}
		if calls.Load() != 1 {
			t.Fatalf("lists = %d, want 1", calls.Load())
		}
	})
}

func TestAccessIndexPanicUnblocksWaiter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var calls atomic.Int32
		idx := newAccessIndex(time.Hour, func() time.Time { return time.Unix(1, 0) }, funcLister(func(ctx context.Context, cred credential) (clusterSet, error) {
			n := calls.Add(1)
			<-release
			if n == 1 {
				panic("boom")
			}
			return newClusterSet([]string{"cluster-a"}), nil
		}))
		cred := credential{kind: credBearer, token: "tok"}
		errc := make(chan error, 2)
		for range 2 {
			go func() {
				_, err := idx.clusterSet(context.Background(), cred)
				errc <- err
			}()
		}
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatalf("lists = %d, want 1", calls.Load())
		}
		close(release)
		synctest.Wait()
		for range 2 {
			err := <-errc
			if err == nil || !strings.Contains(err.Error(), "panicked") {
				t.Fatalf("err = %v", err)
			}
		}
		set, err := idx.clusterSet(context.Background(), cred)
		if err != nil || !set.has("cluster-a") {
			t.Fatalf("set = %#v, err = %v", set.names, err)
		}
		if calls.Load() != 2 {
			t.Fatalf("panic was cached, lists = %d", calls.Load())
		}
	})
}

func TestAccessIndexEvictsExpiredThenEarliest(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_000, 0)
	var calls atomic.Int32
	idx := newAccessIndex(time.Hour, func() time.Time { return now }, funcLister(func(ctx context.Context, cred credential) (clusterSet, error) {
		calls.Add(1)
		return newClusterSet([]string{cred.token}), nil
	}))
	ctx := context.Background()
	for i := range maxEntries {
		now = time.Unix(1_000, int64(i))
		cred := credential{kind: credBearer, token: strconv.Itoa(i)}
		if _, err := idx.clusterSet(ctx, cred); err != nil {
			t.Fatal(err)
		}
	}
	now = time.Unix(1_000, int64(maxEntries))
	if _, err := idx.clusterSet(ctx, credential{kind: credBearer, token: "new"}); err != nil {
		t.Fatal(err)
	}
	before := calls.Load()
	if _, err := idx.clusterSet(ctx, credential{kind: credBearer, token: "0"}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != before+1 {
		t.Fatal("earliest entry was kept past the cap")
	}
	if _, err := idx.clusterSet(ctx, credential{kind: credBearer, token: "new"}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != before+1 {
		t.Fatal("the entry just stored was evicted")
	}

	now = time.Unix(10_000, 0)
	idx = newAccessIndex(time.Second, func() time.Time { return now }, funcLister(func(ctx context.Context, cred credential) (clusterSet, error) {
		calls.Add(1)
		return newClusterSet([]string{cred.token}), nil
	}))
	for i := range maxEntries {
		cred := credential{kind: credBearer, token: "old-" + strconv.Itoa(i)}
		if _, err := idx.clusterSet(ctx, cred); err != nil {
			t.Fatal(err)
		}
	}
	now = now.Add(2 * time.Second)
	if _, err := idx.clusterSet(ctx, credential{kind: credBearer, token: "fresh"}); err != nil {
		t.Fatal(err)
	}
	before = calls.Load()
	if _, err := idx.clusterSet(ctx, credential{kind: credBearer, token: "old-1"}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != before+1 {
		t.Fatal("expired entry survived eviction")
	}
	if _, err := idx.clusterSet(ctx, credential{kind: credBearer, token: "fresh"}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != before+1 {
		t.Fatal("fresh entry was evicted with the expired ones")
	}
}
