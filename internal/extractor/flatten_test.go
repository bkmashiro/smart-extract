package extractor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFlattenSingleFolder_DeepChain(t *testing.T) {
	// archive/a/b/c/file.txt → archive/file.txt
	dir := t.TempDir()
	deep := filepath.Join(dir, "a", "b", "c")
	if err := os.MkdirAll(deep, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "file.txt"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := FlattenSingleFolder(dir); err != nil {
		t.Fatal(err)
	}

	// file.txt should be at top level
	if _, err := os.Stat(filepath.Join(dir, "file.txt")); err != nil {
		t.Errorf("expected file.txt at top level: %v", err)
	}
	// No intermediate dirs should remain
	for _, name := range []string{"a", "b", "c"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			t.Errorf("intermediate dir %q should not exist at top level", name)
		}
	}
}

func TestFlattenSingleFolder_SameName(t *testing.T) {
	// archive/archive/file.txt → archive/file.txt
	dir := t.TempDir()
	base := filepath.Base(dir)
	inner := filepath.Join(dir, base)
	if err := os.MkdirAll(inner, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inner, "file.txt"), []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := FlattenSingleFolder(dir); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(dir, "file.txt")); err != nil {
		t.Errorf("expected file.txt at top level: %v", err)
	}
}

func TestFlattenSingleFolder_DeepSameName(t *testing.T) {
	// archive/archive/archive/file.txt → archive/file.txt
	dir := t.TempDir()
	base := filepath.Base(dir)
	deep := filepath.Join(dir, base, base)
	if err := os.MkdirAll(deep, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "file.txt"), []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := FlattenSingleFolder(dir); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(filepath.Join(dir, "file.txt")); err != nil {
		t.Errorf("expected file.txt at top level: %v", err)
	}
}

func TestFlattenSingleFolder_NoFlattenWithFiles(t *testing.T) {
	// archive/subdir/inner.txt + archive/top.txt → no change
	dir := t.TempDir()
	sub := filepath.Join(dir, "subdir")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "inner.txt"), []byte("a"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "top.txt"), []byte("b"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := FlattenSingleFolder(dir); err != nil {
		t.Fatal(err)
	}

	// subdir should still exist (mixed content = no flatten)
	if _, err := os.Stat(filepath.Join(dir, "subdir", "inner.txt")); err != nil {
		t.Error("subdir/inner.txt should still exist — mixed content shouldn't flatten")
	}
	if _, err := os.Stat(filepath.Join(dir, "top.txt")); err != nil {
		t.Error("top.txt should still exist")
	}
}

func TestFlattenSingleFolder_NoFlattenMultipleDirs(t *testing.T) {
	// archive/dir1/ + archive/dir2/ → no change
	dir := t.TempDir()
	for _, name := range []string{"dir1", "dir2"} {
		sub := filepath.Join(dir, name)
		if err := os.MkdirAll(sub, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sub, "f.txt"), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	if err := FlattenSingleFolder(dir); err != nil {
		t.Fatal(err)
	}

	// Both dirs should still exist
	for _, name := range []string{"dir1", "dir2"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s should still exist", name)
		}
	}
}
