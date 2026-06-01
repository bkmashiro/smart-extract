package extractor

import (
	"context"
	"testing"
	"time"

	"github.com/bkmashiro/smart-extract/internal/budget"
	"github.com/bkmashiro/smart-extract/internal/throttle"
)

func TestAcquireProbeBudgetUnconfiguredReturnsBudgeted(t *testing.T) {
	opts := RecursiveExtractOptions{
		BudgetProfile:     budget.ProfileNormal,
		MaxParallelProbes: 4,
		// ThrottleDir intentionally empty — throttling disabled.
	}
	af := ArchiveFormat{Format: "zip", Strategy: ProbeParallel}

	n, release := acquireProbeBudget(opts, af, 1*1024*1024)
	defer release()

	want := budgetedMaxParallel(opts, af, 1*1024*1024)
	if n != want {
		t.Fatalf("unconfigured throttle must return budgetedMaxParallel=%d, got %d", want, n)
	}
	if n < 1 {
		t.Fatalf("n must be >=1, got %d", n)
	}
}

func TestAcquireProbeBudgetReducedWhenGlobalSlotsSaturated(t *testing.T) {
	throttleDir := t.TempDir()
	opts := RecursiveExtractOptions{
		BudgetProfile:      budget.ProfileNormal,
		MaxParallelProbes:  4,
		ThrottleDir:        throttleDir,
		ThrottleSlots:      1,
		ThrottleStaleAfter: time.Minute,
	}
	af := ArchiveFormat{Format: "zip", Strategy: ProbeParallel}

	// Saturate the global throttle from "another process".
	held, err := throttle.Acquire(context.Background(), throttle.Options{
		Dir:        throttleDir,
		Slots:      1,
		StaleAfter: time.Minute,
	})
	if err != nil {
		t.Fatalf("test setup: pre-acquire failed: %v", err)
	}
	defer held.Release()

	n, release := acquireProbeBudget(opts, af, 1*1024*1024)
	defer release()

	if n != 1 {
		t.Fatalf("saturated throttle must clamp parallelism to 1, got %d", n)
	}
}

func TestAcquireProbeBudgetReleasesSlots(t *testing.T) {
	throttleDir := t.TempDir()
	opts := RecursiveExtractOptions{
		BudgetProfile:      budget.ProfileNormal,
		MaxParallelProbes:  2,
		ThrottleDir:        throttleDir,
		ThrottleSlots:      2,
		ThrottleStaleAfter: time.Minute,
	}
	af := ArchiveFormat{Format: "zip", Strategy: ProbeParallel}

	n, release := acquireProbeBudget(opts, af, 1*1024*1024)
	if n < 1 {
		t.Fatalf("first call: n must be >=1, got %d", n)
	}
	release()

	// After release, a fresh acquisition should still get >=1 slot.
	n2, release2 := acquireProbeBudget(opts, af, 1*1024*1024)
	defer release2()
	if n2 < 1 {
		t.Fatalf("after release: n must be >=1, got %d", n2)
	}
}

func TestAcquireProbeBudgetBoundedByLocalBudget(t *testing.T) {
	// Even when the global throttle has many slots, the local budget
	// (e.g. expensive format) still forces serial probes.
	throttleDir := t.TempDir()
	opts := RecursiveExtractOptions{
		BudgetProfile:      budget.ProfileAggressive,
		MaxParallelProbes:  8,
		ThrottleDir:        throttleDir,
		ThrottleSlots:      8,
		ThrottleStaleAfter: time.Minute,
	}
	af := ArchiveFormat{Format: "tar-compressed", Strategy: ProbeSerial}

	n, release := acquireProbeBudget(opts, af, 100*1024*1024)
	defer release()

	if n != 1 {
		t.Fatalf("expensive format must yield 1 worker regardless of global slots, got %d", n)
	}
}
