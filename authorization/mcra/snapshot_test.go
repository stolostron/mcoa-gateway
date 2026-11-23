package mcra

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type funcLoader func(context.Context) (grantIndex, error)

func (f funcLoader) Load(ctx context.Context) (grantIndex, error) {
	return f(ctx)
}

func TestSnapshotTwoSubjectsOneLoad(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_000, 0)
	var calls atomic.Int32
	idx := grantIndexFrom([]parsedAssignment{
		{subject: subjectRef{kind: subjectKindUser, name: "alice"}, placements: []placementRef{{namespace: "sets", name: "app"}}},
		{subject: subjectRef{kind: subjectKindUser, name: "bob"}, placements: []placementRef{{namespace: "sets", name: "plat"}}},
	}, map[placementRef]clusterSet{
		{namespace: "sets", name: "app"}:  newClusterSet([]string{"cluster-a"}),
		{namespace: "sets", name: "plat"}: newClusterSet([]string{"cluster-b"}),
	})
	snap := newSnapshot(30*time.Second, func() time.Time { return now }, funcLoader(func(ctx context.Context) (grantIndex, error) {
		calls.Add(1)
		return idx, nil
	}))
	first, err := snap.grants(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(29 * time.Second)
	second, err := snap.grants(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("loads = %d, want 1", calls.Load())
	}
	assertClusters(t, first, "alice", nil, "cluster-a")
	assertClusters(t, second, "bob", nil, "cluster-b")

	now = now.Add(time.Second)
	if _, err := snap.grants(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("expired snapshot was reused: %d", calls.Load())
	}
}

func TestSnapshotDoesNotCacheErrors(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	fail := true
	snap := newSnapshot(time.Hour, func() time.Time { return time.Unix(1, 0) }, funcLoader(func(ctx context.Context) (grantIndex, error) {
		calls.Add(1)
		if fail {
			return grantIndex{}, errHubUnavailable
		}
		return grantIndex{}, nil
	}))
	if _, err := snap.grants(context.Background()); !errors.Is(err, errHubUnavailable) {
		t.Fatalf("err = %v", err)
	}
	fail = false
	idx, err := snap.grants(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if idx.clusters("alice", nil).len() != 0 || calls.Load() != 2 {
		t.Fatalf("len=%d calls=%d", idx.clusters("alice", nil).len(), calls.Load())
	}
	if _, err := snap.grants(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatal("empty snapshot was not reused")
	}
}

func TestSnapshotSingleflight(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var calls atomic.Int32
		snap := newSnapshot(time.Hour, func() time.Time { return time.Unix(1, 0) }, funcLoader(func(ctx context.Context) (grantIndex, error) {
			calls.Add(1)
			<-release
			return grantIndex{byUser: map[string]clusterSet{"alice": newClusterSet([]string{"cluster-a"})}}, nil
		}))
		errc := make(chan error, 2)
		for range 2 {
			go func() {
				idx, err := snap.grants(context.Background())
				if err != nil || !idx.clusters("alice", nil).has("cluster-a") {
					errc <- errors.New("leader or waiter missed cluster-a")
					return
				}
				errc <- nil
			}()
		}
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatalf("loads = %d, want 1", calls.Load())
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

func TestSnapshotWaiterCancelDoesNotDropResult(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var calls atomic.Int32
		snap := newSnapshot(time.Hour, func() time.Time { return time.Unix(1, 0) }, funcLoader(func(ctx context.Context) (grantIndex, error) {
			calls.Add(1)
			<-release
			return grantIndex{byUser: map[string]clusterSet{"alice": newClusterSet([]string{"cluster-a"})}}, nil
		}))
		leaderErr := make(chan error, 1)
		go func() {
			_, err := snap.grants(context.Background())
			leaderErr <- err
		}()
		synctest.Wait()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := snap.grants(ctx)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waiter err = %v", err)
		}
		close(release)
		synctest.Wait()
		if err := <-leaderErr; err != nil {
			t.Fatal(err)
		}
		if _, err := snap.grants(context.Background()); err != nil {
			t.Fatal(err)
		}
		if calls.Load() != 1 {
			t.Fatalf("loads = %d, want 1", calls.Load())
		}
	})
}

func TestSnapshotPanicUnblocksWaiter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var calls atomic.Int32
		snap := newSnapshot(time.Hour, func() time.Time { return time.Unix(1, 0) }, funcLoader(func(ctx context.Context) (grantIndex, error) {
			n := calls.Add(1)
			<-release
			if n == 1 {
				panic("boom")
			}
			return grantIndex{byUser: map[string]clusterSet{"alice": newClusterSet([]string{"cluster-a"})}}, nil
		}))
		errc := make(chan error, 2)
		for range 2 {
			go func() {
				_, err := snap.grants(context.Background())
				errc <- err
			}()
		}
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatalf("loads = %d, want 1", calls.Load())
		}
		close(release)
		synctest.Wait()
		for range 2 {
			err := <-errc
			if err == nil || !strings.Contains(err.Error(), "panicked") {
				t.Fatalf("err = %v", err)
			}
		}
		idx, err := snap.grants(context.Background())
		if err != nil || !idx.clusters("alice", nil).has("cluster-a") {
			t.Fatalf("index err = %v", err)
		}
		if calls.Load() != 2 {
			t.Fatalf("panic was cached, loads = %d", calls.Load())
		}
	})
}
