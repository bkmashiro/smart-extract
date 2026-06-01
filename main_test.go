package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bkmashiro/smart-extract/cmd"
	"github.com/bkmashiro/smart-extract/internal/config"
)

// newTestDeps returns runDeps with captured stdout/stderr and no-op
// wait/console hooks. The two buffers it returns are the same ones wired
// into deps so callers can assert on them.
func newTestDeps() (runDeps, *bytes.Buffer, *bytes.Buffer) {
	var stdout, stderr bytes.Buffer
	deps := runDeps{
		stdout:          &stdout,
		stderr:          &stderr,
		allocConsole:    func() {},
		waitForKeypress: func(string) {},
		extract: func(path string, opts cmd.ExtractOptions) error {
			return nil
		},
		explain: func(path string, w io.Writer) error {
			return nil
		},
	}
	return deps, &stdout, &stderr
}

// setupTempConfig initializes the config package against a fresh temp dir
// so tests do not touch the real config.yaml. It returns the temp dir.
func setupTempConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	config.Init(dir)
	config.ReloadAll()
	return dir
}

func TestRunHashDBPublicKeyPrintsHexKey(t *testing.T) {
	dir := setupTempConfig(t)
	keyPath := filepath.Join(dir, "contrib.key.json")

	deps, stdout, stderr := newTestDeps()
	code := run([]string{"--hashdb-public-key", keyPath}, deps)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	out := strings.TrimSpace(stdout.String())
	// Ed25519 public key is 32 bytes → 64 hex chars.
	if len(out) != 64 {
		t.Fatalf("expected 64-char hex public key, got %q", out)
	}
	if _, err := hex.DecodeString(out); err != nil {
		t.Fatalf("output is not hex: %v (%q)", err, out)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("expected key file at %s, err=%v", keyPath, err)
	}

	// Second invocation should re-load the same key and print the same hex.
	deps2, stdout2, _ := newTestDeps()
	if code := run([]string{"--hashdb-public-key", keyPath}, deps2); code != 0 {
		t.Fatalf("second run exit code = %d", code)
	}
	if strings.TrimSpace(stdout2.String()) != out {
		t.Fatalf("public key not stable: %q vs %q", stdout2.String(), out)
	}
}

func TestRunHashDBListSourcesPrintsLocalAndHTTPSources(t *testing.T) {
	dir := setupTempConfig(t)
	cacheDir := filepath.Join(dir, "hashdb-cache")

	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	cfg.HashDB.Mode = "lookup"
	cfg.HashDB.Sources = []config.HashDBSource{
		{
			Name:      "local-bundle",
			Type:      "bundle",
			Path:      filepath.Join(dir, "local.bundle.json"),
			PublicKey: "aa",
		},
		{
			Name:      "mirror-bundle",
			Type:      "bundle",
			URL:       "https://example.com/hashdb/shared.bundle.json",
			CacheDir:  cacheDir,
			PublicKey: "bb",
		},
	}
	if err := config.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	config.ReloadAll()

	deps, stdout, stderr := newTestDeps()
	code := run([]string{"--hashdb-list-sources"}, deps)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"local-bundle", "mirror-bundle", "bundle"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
	// HTTP source has no cache dir on disk yet → "missing".
	if !strings.Contains(out, "missing") {
		t.Fatalf("expected cache state 'missing' for HTTP source, got:\n%s", out)
	}
	// HTTP source URL should be surfaced as the source location.
	if !strings.Contains(out, "https://example.com/hashdb/shared.bundle.json") {
		t.Fatalf("expected URL in output, got:\n%s", out)
	}
}

func TestRunHashDBClearCacheRemovesNamedCache(t *testing.T) {
	dir := setupTempConfig(t)
	cacheDir := filepath.Join(dir, "hashdb-cache")

	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	cfg.HashDB.Mode = "lookup"
	cfg.HashDB.Sources = []config.HashDBSource{
		{Name: "mirror-keep", Type: "bundle", URL: "https://example.com/keep.bundle.json", CacheDir: cacheDir},
		{Name: "mirror-drop", Type: "bundle", URL: "https://example.com/drop.bundle.json", CacheDir: cacheDir},
	}
	if err := config.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	config.ReloadAll()

	// Pre-create both cache roots with marker files so we can verify which
	// one gets removed.
	keepRoot, err := resolveHashDBCacheRootForTest(t, "mirror-keep")
	if err != nil {
		t.Fatalf("resolve keep root: %v", err)
	}
	dropRoot, err := resolveHashDBCacheRootForTest(t, "mirror-drop")
	if err != nil {
		t.Fatalf("resolve drop root: %v", err)
	}
	for _, root := range []string{keepRoot, dropRoot} {
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", root, err)
		}
		if err := os.WriteFile(filepath.Join(root, "marker"), []byte("x"), 0o644); err != nil {
			t.Fatalf("write marker in %s: %v", root, err)
		}
	}

	deps, stdout, stderr := newTestDeps()
	code := run([]string{"--hashdb-clear-cache", "mirror-drop"}, deps)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "mirror-drop") {
		t.Fatalf("expected source name in output, got:\n%s", out)
	}
	if _, err := os.Stat(dropRoot); !os.IsNotExist(err) {
		t.Fatalf("drop cache should be gone, stat err=%v", err)
	}
	if _, err := os.Stat(keepRoot); err != nil {
		t.Fatalf("keep cache should be untouched, err=%v", err)
	}
}

func TestRunHashDBClearCacheMissingArgReturnsNonZero(t *testing.T) {
	setupTempConfig(t)

	deps, stdout, stderr := newTestDeps()
	code := run([]string{"--hashdb-clear-cache"}, deps)
	if code == 0 {
		t.Fatalf("expected non-zero exit code; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	errOut := stderr.String()
	if errOut == "" {
		t.Fatalf("expected error message on stderr, got empty")
	}
	if !strings.Contains(errOut, "--hashdb-clear-cache") {
		t.Fatalf("expected usage hint mentioning --hashdb-clear-cache in stderr, got: %q", errOut)
	}
}

func TestRunHashDBDisableAndEnableSourceFlipsConfig(t *testing.T) {
	setupTempConfig(t)

	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	cfg.HashDB.Mode = "lookup"
	cfg.HashDB.Sources = []config.HashDBSource{
		{Name: "mirror-a", Type: "bundle", URL: "https://example.com/a.bundle.json"},
		{Name: "mirror-b", Type: "bundle", URL: "https://example.com/b.bundle.json", Disabled: true},
	}
	if err := config.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	config.ReloadAll()

	deps, stdout, stderr := newTestDeps()
	if code := run([]string{"--hashdb-disable-source", "mirror-a"}, deps); code != 0 {
		t.Fatalf("disable exit=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "mirror-a") {
		t.Fatalf("expected source name in stdout, got: %s", stdout.String())
	}

	config.ReloadAll()
	cfg, err = config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig after disable: %v", err)
	}
	if !cfg.HashDB.Sources[0].Disabled {
		t.Fatalf("mirror-a should be disabled, got %+v", cfg.HashDB.Sources[0])
	}

	deps2, stdout2, stderr2 := newTestDeps()
	if code := run([]string{"--hashdb-enable-source", "mirror-b"}, deps2); code != 0 {
		t.Fatalf("enable exit=%d stderr=%s", code, stderr2.String())
	}
	if !strings.Contains(stdout2.String(), "mirror-b") {
		t.Fatalf("expected source name in stdout, got: %s", stdout2.String())
	}

	config.ReloadAll()
	cfg, err = config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig after enable: %v", err)
	}
	if cfg.HashDB.Sources[1].Disabled {
		t.Fatalf("mirror-b should be enabled, got %+v", cfg.HashDB.Sources[1])
	}
}

func TestRunDebugLogWritesToFileAndPassesLoggerToExtraction(t *testing.T) {
	setupTempConfig(t)
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "sample.zip")
	if err := os.WriteFile(archivePath, []byte("not-real-zip"), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	logPath := filepath.Join(dir, "debug.log")

	deps, stdout, stderr := newTestDeps()
	var gotPath string
	var wroteDebug bool
	deps.extract = func(path string, opts cmd.ExtractOptions) error {
		gotPath = path
		if opts.DebugLog == nil {
			t.Fatalf("DebugLog is nil")
		}
		_, _ = opts.DebugLog.Write([]byte("debug-line\n"))
		wroteDebug = true
		return nil
	}

	if code := run([]string{"--debug-log", logPath, archivePath}, deps); code != 0 {
		t.Fatalf("exit code=%d stderr=%s", code, stderr.String())
	}
	if gotPath != archivePath {
		t.Fatalf("extract path=%q, want %q", gotPath, archivePath)
	}
	if !wroteDebug {
		t.Fatalf("extract hook did not write debug output")
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read debug log: %v", err)
	}
	if !strings.Contains(string(data), "debug-line") {
		t.Fatalf("debug log missing hook output: %q", string(data))
	}
	if !strings.Contains(stdout.String(), logPath) {
		t.Fatalf("stdout should mention debug log path, got: %q", stdout.String())
	}
}

func TestRunExplainDispatchesToExplainHook(t *testing.T) {
	setupTempConfig(t)
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "password=secret.zip")
	if err := os.WriteFile(archivePath, []byte("fake"), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	deps, stdout, stderr := newTestDeps()
	var gotPath string
	deps.explain = func(path string, w io.Writer) error {
		gotPath = path
		_, _ = fmt.Fprintln(w, "explain-ok")
		return nil
	}

	if code := run([]string{"--explain", archivePath}, deps); code != 0 {
		t.Fatalf("exit code=%d stderr=%s", code, stderr.String())
	}
	if gotPath != archivePath {
		t.Fatalf("explain path=%q, want %q", gotPath, archivePath)
	}
	if !strings.Contains(stdout.String(), "explain-ok") {
		t.Fatalf("stdout missing explain output: %q", stdout.String())
	}
}

func TestRunExplainMissingArgReturnsNonZero(t *testing.T) {
	setupTempConfig(t)
	deps, _, stderr := newTestDeps()
	if code := run([]string{"--explain"}, deps); code == 0 {
		t.Fatalf("expected non-zero exit")
	}
	if !strings.Contains(stderr.String(), "--explain") {
		t.Fatalf("expected usage in stderr, got %q", stderr.String())
	}
}

func TestRunHashDBDisableSourceMissingArgReturnsNonZero(t *testing.T) {
	setupTempConfig(t)

	deps, _, stderr := newTestDeps()
	code := run([]string{"--hashdb-disable-source"}, deps)
	if code == 0 {
		t.Fatalf("expected non-zero exit, stderr=%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "--hashdb-disable-source") {
		t.Fatalf("expected usage hint in stderr, got: %q", stderr.String())
	}
}

func TestRunHashDBEnableSourceMissingNameReturnsNonZero(t *testing.T) {
	setupTempConfig(t)

	deps, _, stderr := newTestDeps()
	code := run([]string{"--hashdb-enable-source", "does-not-exist"}, deps)
	if code == 0 {
		t.Fatalf("expected non-zero exit, stderr=%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "does-not-exist") {
		t.Fatalf("expected source name in stderr, got: %q", stderr.String())
	}
}

// resolveHashDBCacheRootForTest reads the configured source by name and
// computes the same cache root the cmd helpers would derive. It indirectly
// exercises cmd.HashDBListSources to avoid duplicating cache-root logic in
// tests.
func resolveHashDBCacheRootForTest(t *testing.T, name string) (string, error) {
	t.Helper()
	// Reuse the list helper to recover the canonical cache path.
	deps, stdout, _ := newTestDeps()
	if code := run([]string{"--hashdb-list-sources"}, deps); code != 0 {
		t.Fatalf("list-sources exit=%d", code)
	}
	out := stdout.String()
	// Lines look like:
	//   - <name> (...)
	//       cache: <path> (missing|present)
	lines := strings.Split(out, "\n")
	wantHeader := "- " + name + " "
	for i, line := range lines {
		if !strings.HasPrefix(strings.TrimSpace(line), wantHeader) &&
			!strings.HasPrefix(strings.TrimSpace(line), "- "+name+"(") {
			continue
		}
		for j := i + 1; j < len(lines); j++ {
			trimmed := strings.TrimSpace(lines[j])
			if strings.HasPrefix(trimmed, "- ") {
				break
			}
			if strings.HasPrefix(trimmed, "cache:") {
				rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "cache:"))
				if idx := strings.LastIndex(rest, " ("); idx >= 0 {
					return rest[:idx], nil
				}
				return rest, nil
			}
		}
	}
	t.Fatalf("did not find cache line for %q in:\n%s", name, out)
	return "", nil
}
