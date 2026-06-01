// Package throttle provides a cross-process semaphore used to bound the
// total number of concurrent heavy-cost password probes across all running
// smart-extract instances.
//
// Slots are represented by lock files in a shared directory. Acquiring a
// slot is an atomic O_CREATE|O_EXCL file creation; releasing removes the
// file. Crashed holders are recovered via mtime-based stale reclamation.
//
// The package uses only the standard library so it builds on macOS, Linux,
// and Windows.
package throttle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ErrNoSlot is returned by Acquire when no slot is currently available.
var ErrNoSlot = errors.New("throttle: no slot available")

// Options configures a throttle.
type Options struct {
	// Dir is the lock directory. It is created if it does not exist.
	Dir string
	// Slots is the global concurrency cap. Values < 1 are treated as 1.
	Slots int
	// StaleAfter is the mtime age beyond which an existing slot file is
	// considered orphaned and may be reclaimed. Zero disables reclamation.
	StaleAfter time.Duration
}

// Lease represents a single acquired slot.
type Lease struct {
	path     string
	mu       sync.Mutex
	released bool
	stop     chan struct{}
}

// Release frees the slot. Safe to call multiple times.
func (l *Lease) Release() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released {
		return nil
	}
	l.released = true
	if l.stop != nil {
		close(l.stop)
		l.stop = nil
	}
	if l.path == "" {
		return nil
	}
	err := os.Remove(l.path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Acquire attempts to take a slot. It is non-blocking: if all slots are
// held by live holders, it returns ErrNoSlot immediately.
func Acquire(ctx context.Context, opts Options) (*Lease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	slots := opts.Slots
	if slots < 1 {
		slots = 1
	}
	if opts.Dir == "" {
		return nil, fmt.Errorf("throttle: Options.Dir is required")
	}
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("throttle: mkdir %s: %w", opts.Dir, err)
	}

	for i := 0; i < slots; i++ {
		path := filepath.Join(opts.Dir, fmt.Sprintf("slot-%d.lock", i))
		if lease, ok := tryClaim(path, opts.StaleAfter); ok {
			return lease, nil
		}
		if opts.StaleAfter > 0 && isStale(path, opts.StaleAfter) {
			if err := os.Remove(path); err == nil {
				if lease, ok := tryClaim(path, opts.StaleAfter); ok {
					return lease, nil
				}
			}
		}
	}
	return nil, ErrNoSlot
}

// AcquireN tries to take up to n slots without blocking. The returned
// slice may be shorter than n if fewer slots are currently available.
// The error is non-nil only on unexpected filesystem failure; an empty
// result with nil error means no slots were available.
func AcquireN(ctx context.Context, n int, opts Options) ([]*Lease, error) {
	if n < 1 {
		return nil, nil
	}
	out := make([]*Lease, 0, n)
	for i := 0; i < n; i++ {
		l, err := Acquire(ctx, opts)
		if err != nil {
			if errors.Is(err, ErrNoSlot) {
				return out, nil
			}
			ReleaseAll(out)
			return nil, err
		}
		out = append(out, l)
	}
	return out, nil
}

// EffectiveParallel returns the number of probe workers the caller should
// launch given a requested parallelism and the current global slot
// availability. It also returns leases that must be released by the
// caller. The returned count is always >= 1 — if no slots can be acquired
// (saturated or throttle error), the caller still gets to run at least one
// serial worker for extraction correctness, but with no lease attached.
func EffectiveParallel(ctx context.Context, requested int, opts Options) (int, []*Lease, error) {
	if requested < 1 {
		requested = 1
	}
	leases, err := AcquireN(ctx, requested, opts)
	if err != nil {
		return 1, nil, err
	}
	if len(leases) < 1 {
		return 1, nil, nil
	}
	return len(leases), leases, nil
}

// ReleaseAll releases every lease in the slice, ignoring nil entries and
// individual release errors.
func ReleaseAll(leases []*Lease) {
	for _, l := range leases {
		if l == nil {
			continue
		}
		_ = l.Release()
	}
}

// DefaultDir returns a sensible default lock directory under the user's
// cache dir, falling back to TempDir.
func DefaultDir() string {
	if cache, err := os.UserCacheDir(); err == nil && cache != "" {
		return filepath.Join(cache, "smart-extract", "throttle")
	}
	return filepath.Join(os.TempDir(), "smart-extract", "throttle")
}

func tryClaim(path string, staleAfter time.Duration) (*Lease, bool) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, false
	}
	// We close immediately — the presence of the file is the lock. A holder
	// heartbeat refreshes mtime so long-running extractions are not mistaken
	// for crashed processes.
	_ = f.Close()
	lease := &Lease{path: path}
	if staleAfter > 0 {
		lease.stop = make(chan struct{})
		go heartbeat(path, staleAfter, lease.stop)
	}
	return lease, true
}

func heartbeat(path string, staleAfter time.Duration, stop <-chan struct{}) {
	interval := staleAfter / 3
	if interval < 50*time.Millisecond {
		interval = 50 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			now := time.Now()
			_ = os.Chtimes(path, now, now)
		}
	}
}

func isStale(path string, threshold time.Duration) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return time.Since(info.ModTime()) > threshold
}
