package throttle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestOpts(t *testing.T, slots int) Options {
	t.Helper()
	return Options{
		Dir:        t.TempDir(),
		Slots:      slots,
		StaleAfter: 60 * time.Second,
	}
}

func TestAcquireUpToNSucceedsThenFails(t *testing.T) {
	opts := newTestOpts(t, 2)
	ctx := context.Background()

	l1, err := Acquire(ctx, opts)
	if err != nil {
		t.Fatalf("first Acquire failed: %v", err)
	}
	defer l1.Release()

	l2, err := Acquire(ctx, opts)
	if err != nil {
		t.Fatalf("second Acquire failed: %v", err)
	}
	defer l2.Release()

	// Third (non-blocking) acquire must fail with ErrNoSlot.
	l3, err := Acquire(ctx, opts)
	if err == nil {
		l3.Release()
		t.Fatalf("expected ErrNoSlot on N+1 acquire, got success")
	}
	if !errors.Is(err, ErrNoSlot) {
		t.Fatalf("expected ErrNoSlot, got %v", err)
	}
}

func TestReleaseFreesSlot(t *testing.T) {
	opts := newTestOpts(t, 1)
	ctx := context.Background()

	l1, err := Acquire(ctx, opts)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}

	// Second should fail while l1 is held.
	if l2, err := Acquire(ctx, opts); err == nil {
		l2.Release()
		l1.Release()
		t.Fatal("expected ErrNoSlot while slot is held")
	}

	if err := l1.Release(); err != nil {
		t.Fatalf("Release failed: %v", err)
	}

	// After release, acquiring should succeed.
	l2, err := Acquire(ctx, opts)
	if err != nil {
		t.Fatalf("Acquire after Release failed: %v", err)
	}
	l2.Release()
}

func TestReleaseIsIdempotent(t *testing.T) {
	opts := newTestOpts(t, 1)
	l, err := Acquire(context.Background(), opts)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("first Release failed: %v", err)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("second Release should be a no-op, got %v", err)
	}
}

func TestStaleSlotIsReclaimed(t *testing.T) {
	dir := t.TempDir()
	opts := Options{
		Dir:        dir,
		Slots:      1,
		StaleAfter: 50 * time.Millisecond,
	}

	// Plant a stale slot file directly: simulate a crashed prior process.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dir, "slot-0.lock")
	if err := os.WriteFile(stale, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Age the file beyond StaleAfter.
	old := time.Now().Add(-1 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}

	l, err := Acquire(context.Background(), opts)
	if err != nil {
		t.Fatalf("expected stale slot to be reclaimed, got %v", err)
	}
	defer l.Release()
}

func TestFreshSlotIsNotReclaimed(t *testing.T) {
	dir := t.TempDir()
	opts := Options{
		Dir:        dir,
		Slots:      1,
		StaleAfter: 10 * time.Second,
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(dir, "slot-0.lock")
	if err := os.WriteFile(fresh, []byte("fresh"), 0o600); err != nil {
		t.Fatal(err)
	}
	// mtime is now — must NOT be reclaimed.

	l, err := Acquire(context.Background(), opts)
	if err == nil {
		l.Release()
		t.Fatal("expected fresh slot file to block acquire")
	}
	if !errors.Is(err, ErrNoSlot) {
		t.Fatalf("expected ErrNoSlot, got %v", err)
	}
}

func TestLiveLeaseHeartbeatPreventsStaleReclaim(t *testing.T) {
	opts := newTestOpts(t, 1)
	opts.StaleAfter = 75 * time.Millisecond

	l, err := Acquire(context.Background(), opts)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	defer l.Release()

	// Wait longer than StaleAfter. A live lease should refresh its mtime, so
	// another process must still see the slot as occupied instead of reclaiming it.
	time.Sleep(180 * time.Millisecond)
	l2, err := Acquire(context.Background(), opts)
	if err == nil {
		l2.Release()
		t.Fatal("expected live heartbeat to prevent stale reclaim")
	}
	if !errors.Is(err, ErrNoSlot) {
		t.Fatalf("expected ErrNoSlot, got %v", err)
	}
}

func TestAcquireNReturnsAvailable(t *testing.T) {
	opts := newTestOpts(t, 3)

	// Pre-acquire one to leave 2 free.
	held, err := Acquire(context.Background(), opts)
	if err != nil {
		t.Fatalf("pre-Acquire failed: %v", err)
	}
	defer held.Release()

	leases, err := AcquireN(context.Background(), 5, opts)
	if err != nil {
		t.Fatalf("AcquireN failed: %v", err)
	}
	defer ReleaseAll(leases)

	if len(leases) != 2 {
		t.Fatalf("AcquireN got %d leases, want 2 (3 slots - 1 held)", len(leases))
	}
}

func TestEffectiveParallelNeverBelowOne(t *testing.T) {
	opts := newTestOpts(t, 2)

	// Saturate.
	l1, err := Acquire(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	defer l1.Release()
	l2, err := Acquire(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Release()

	// Even with zero available globally, EffectiveParallel must allow at
	// least 1 worker — extraction correctness mandates serial fallback.
	n, leases, _ := EffectiveParallel(context.Background(), 4, opts)
	defer ReleaseAll(leases)
	if n < 1 {
		t.Fatalf("EffectiveParallel must return >=1, got %d", n)
	}
}

func TestEffectiveParallelReducedWhenSlotsScarce(t *testing.T) {
	opts := newTestOpts(t, 2)

	n, leases, _ := EffectiveParallel(context.Background(), 8, opts)
	defer ReleaseAll(leases)
	if n > 2 {
		t.Fatalf("EffectiveParallel must not exceed global slots (2), got %d", n)
	}
	if n < 1 {
		t.Fatalf("EffectiveParallel must be >=1, got %d", n)
	}
}

func TestEffectiveParallelHonorsRequested(t *testing.T) {
	opts := newTestOpts(t, 8)

	n, leases, _ := EffectiveParallel(context.Background(), 3, opts)
	defer ReleaseAll(leases)
	if n != 3 {
		t.Fatalf("EffectiveParallel(3) with 8 free slots must return 3, got %d", n)
	}
}

func TestEffectiveParallelFallsBackOnErrorDir(t *testing.T) {
	// Point at a path that cannot be created (under an existing regular file).
	tmp := t.TempDir()
	blocker := filepath.Join(tmp, "blocker")
	if err := os.WriteFile(blocker, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	opts := Options{
		Dir:        filepath.Join(blocker, "throttle"), // mkdir under a file -> error
		Slots:      4,
		StaleAfter: time.Minute,
	}

	n, leases, _ := EffectiveParallel(context.Background(), 4, opts)
	defer ReleaseAll(leases)
	if n < 1 {
		t.Fatalf("on unexpected throttle error must fall back to >=1, got %d", n)
	}
}
