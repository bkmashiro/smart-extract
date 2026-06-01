package extractor

import (
	"testing"

	"github.com/bkmashiro/smart-extract/internal/budget"
)

func TestBudgetedMaxParallelCheapVsExpensive(t *testing.T) {
	opts := RecursiveExtractOptions{
		BudgetProfile:     budget.ProfileNormal,
		MaxParallelProbes: 4,
	}
	cheap := budgetedMaxParallel(opts, ArchiveFormat{Format: "zip", Strategy: ProbeParallel}, 1*1024*1024)
	expensive := budgetedMaxParallel(opts, ArchiveFormat{Format: "7z-solid", Strategy: ProbeSerial}, 1*1024*1024)
	if expensive != 1 {
		t.Fatalf("expensive format must yield MaxParallelProbes=1, got %d", expensive)
	}
	if cheap < 2 {
		t.Fatalf("cheap format with MaxParallelProbes=4 should permit >=2 workers, got %d", cheap)
	}
}

func TestBudgetedMaxParallelOverridesRawMaxParallelForExpensive(t *testing.T) {
	// Even if the user configured 8 parallel probes, expensive formats
	// must serialize.
	opts := RecursiveExtractOptions{
		BudgetProfile:     budget.ProfileAggressive,
		MaxParallelProbes: 8,
	}
	got := budgetedMaxParallel(opts, ArchiveFormat{Format: "tar-compressed", Strategy: ProbeSerial}, 100*1024*1024)
	if got != 1 {
		t.Fatalf("expensive format must serialize regardless of config, got %d", got)
	}
}

func TestBudgetedMaxParallelEmptyProfileTreatedAsNormal(t *testing.T) {
	// Backwards compat: zero-value (unset) BudgetProfile should still yield
	// a positive, reasonable parallelism for cheap formats.
	opts := RecursiveExtractOptions{
		MaxParallelProbes: 4,
	}
	got := budgetedMaxParallel(opts, ArchiveFormat{Format: "zip", Strategy: ProbeParallel}, 1*1024*1024)
	if got < 1 {
		t.Fatalf("MaxParallelProbes must be >=1, got %d", got)
	}
}

func TestChildOptionsCarrySuccessfulParentPassword(t *testing.T) {
	original := RecursiveExtractOptions{ParentPassword: "outer"}
	child := childOptionsWithParentPassword(original, "inner-success")
	if child.ParentPassword != "inner-success" {
		t.Fatalf("child ParentPassword = %q, want inner-success", child.ParentPassword)
	}
	if original.ParentPassword != "outer" {
		t.Fatalf("original ParentPassword mutated to %q", original.ParentPassword)
	}
}
