package candidates

import (
	"context"
	"testing"

	"github.com/bkmashiro/smart-extract/internal/store"
)

func TestBuildInsertsHashDBAfterExactAndBeforeFilename(t *testing.T) {
	source := &fakeSource{
		exact:            map[string]string{"[site] RJ123456 password=inline.zip": "exact-pass"},
		sessionPasswords: []string{"session-pass"},
		topPasswords:     []store.PasswordStat{{Password: "dict-pass", TotalUses: 3}},
	}

	got, err := Build(context.Background(), Request{
		ArchivePath:       "/downloads/[site] RJ123456 password=inline.zip",
		ArchiveKey:        "[site] RJ123456 password=inline.zip",
		ParentPassword:    "parent-pass",
		HashDBPasswords:   []string{"hashdb-pass-1", "hashdb-pass-2"},
		FallbackPasswords: []string{"fallback-pass"},
		DictionaryLimit:   10,
	}, source)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	want := []Candidate{
		{Password: "parent-pass", Source: SourceParent},
		{Password: "exact-pass", Source: SourceExact},
		{Password: "hashdb-pass-1", Source: SourceHashDB},
		{Password: "hashdb-pass-2", Source: SourceHashDB},
		{Password: "inline", Source: SourceFilename},
		{Password: "session-pass", Source: SourceSession},
		{Password: "dict-pass", Source: SourceDictionary},
		{Password: "", Source: SourceEmpty},
		{Password: "fallback-pass", Source: SourceFallback},
	}
	assertCandidates(t, got, want)
}

func TestBuildDedupesHashDBAgainstEarlierSources(t *testing.T) {
	source := &fakeSource{
		exact: map[string]string{"file.zip": "exact-pass"},
	}

	got, err := Build(context.Background(), Request{
		ArchivePath:     "/downloads/file.zip",
		ArchiveKey:      "file.zip",
		ParentPassword:  "parent-pass",
		HashDBPasswords: []string{"parent-pass", "exact-pass", "fresh-pass"},
		DictionaryLimit: 10,
	}, source)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// Only "fresh-pass" should appear under SourceHashDB; the duplicates are
	// retained under their earlier sources.
	var hashdb []Candidate
	for _, c := range got {
		if c.Source == SourceHashDB {
			hashdb = append(hashdb, c)
		}
	}
	if len(hashdb) != 1 || hashdb[0].Password != "fresh-pass" {
		t.Fatalf("hashdb candidates = %v, want [fresh-pass]", hashdb)
	}

	if got[0].Source != SourceParent || got[0].Password != "parent-pass" {
		t.Fatalf("got[0] = %+v, want parent/parent-pass", got[0])
	}
	if got[1].Source != SourceExact || got[1].Password != "exact-pass" {
		t.Fatalf("got[1] = %+v, want exact/exact-pass", got[1])
	}
}

func TestBuildPreservesHashDBOrder(t *testing.T) {
	got, err := Build(context.Background(), Request{
		ArchivePath:     "/downloads/x.zip",
		ArchiveKey:      "x.zip",
		HashDBPasswords: []string{"a", "b", "c"},
	}, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var hashdb []string
	for _, c := range got {
		if c.Source == SourceHashDB {
			hashdb = append(hashdb, c.Password)
		}
	}
	want := []string{"a", "b", "c"}
	if len(hashdb) != len(want) {
		t.Fatalf("hashdb = %v, want %v", hashdb, want)
	}
	for i := range want {
		if hashdb[i] != want[i] {
			t.Fatalf("hashdb[%d] = %q, want %q", i, hashdb[i], want[i])
		}
	}
}
