package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bkmashiro/smart-extract/cmd"
	"github.com/bkmashiro/smart-extract/internal/config"
	"github.com/bkmashiro/smart-extract/internal/hashdb"
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
		doctor: func(w io.Writer) error {
			return nil
		},
		explainJSON: func(path string, w io.Writer) error {
			return nil
		},
		doctorJSON: func(w io.Writer) error {
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

func TestRunDoctorDispatchesToDoctorHook(t *testing.T) {
	setupTempConfig(t)
	deps, stdout, stderr := newTestDeps()
	called := false
	deps.doctor = func(w io.Writer) error {
		called = true
		_, _ = fmt.Fprintln(w, "doctor-ok")
		return nil
	}
	if code := run([]string{"--doctor"}, deps); code != 0 {
		t.Fatalf("exit code=%d stderr=%s", code, stderr.String())
	}
	if !called {
		t.Fatalf("doctor hook was not called")
	}
	if !strings.Contains(stdout.String(), "doctor-ok") {
		t.Fatalf("stdout missing doctor output: %q", stdout.String())
	}
}

func TestRunDoctorHookErrorReturnsNonZero(t *testing.T) {
	setupTempConfig(t)
	deps, _, stderr := newTestDeps()
	deps.doctor = func(w io.Writer) error {
		return fmt.Errorf("doctor boom")
	}
	if code := run([]string{"--doctor"}, deps); code == 0 {
		t.Fatalf("expected non-zero exit")
	}
	if !strings.Contains(stderr.String(), "doctor boom") {
		t.Fatalf("stderr missing hook error: %q", stderr.String())
	}
}

func TestRunExplainJSONDispatchesToExplainJSONHook(t *testing.T) {
	setupTempConfig(t)
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "password=secret.zip")
	if err := os.WriteFile(archivePath, []byte("fake"), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	deps, stdout, stderr := newTestDeps()
	var gotPath string
	textCalled := false
	deps.explain = func(path string, w io.Writer) error {
		textCalled = true
		return nil
	}
	deps.explainJSON = func(path string, w io.Writer) error {
		gotPath = path
		_, _ = fmt.Fprint(w, `{"command":"explain"}`)
		return nil
	}

	if code := run([]string{"--explain-json", archivePath}, deps); code != 0 {
		t.Fatalf("exit code=%d stderr=%s", code, stderr.String())
	}
	if textCalled {
		t.Fatalf("--explain-json must not invoke the text explain hook")
	}
	if gotPath != archivePath {
		t.Fatalf("explainJSON path=%q, want %q", gotPath, archivePath)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(stdout.String()), &got); err != nil {
		t.Fatalf("stdout not valid JSON: %v; out=%q", err, stdout.String())
	}
	if got["command"] != "explain" {
		t.Fatalf("expected command=explain in JSON output, got %v", got)
	}
}

func TestRunExplainJSONMissingArgReturnsNonZero(t *testing.T) {
	setupTempConfig(t)
	deps, _, stderr := newTestDeps()
	if code := run([]string{"--explain-json"}, deps); code == 0 {
		t.Fatalf("expected non-zero exit")
	}
	if !strings.Contains(stderr.String(), "--explain-json") {
		t.Fatalf("expected usage hint in stderr, got %q", stderr.String())
	}
}

func TestRunDoctorJSONDispatchesToDoctorJSONHook(t *testing.T) {
	setupTempConfig(t)
	deps, stdout, stderr := newTestDeps()
	textCalled := false
	jsonCalled := false
	deps.doctor = func(w io.Writer) error {
		textCalled = true
		return nil
	}
	deps.doctorJSON = func(w io.Writer) error {
		jsonCalled = true
		_, _ = fmt.Fprint(w, `{"command":"doctor"}`)
		return nil
	}
	if code := run([]string{"--doctor-json"}, deps); code != 0 {
		t.Fatalf("exit code=%d stderr=%s", code, stderr.String())
	}
	if textCalled {
		t.Fatalf("--doctor-json must not invoke the text doctor hook")
	}
	if !jsonCalled {
		t.Fatalf("doctorJSON hook was not called")
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(stdout.String()), &got); err != nil {
		t.Fatalf("stdout not valid JSON: %v; out=%q", err, stdout.String())
	}
	if got["command"] != "doctor" {
		t.Fatalf("expected command=doctor in JSON output, got %v", got)
	}
}

func TestRunDoctorJSONHookErrorReturnsNonZero(t *testing.T) {
	setupTempConfig(t)
	deps, _, stderr := newTestDeps()
	deps.doctorJSON = func(w io.Writer) error {
		return fmt.Errorf("doctor-json boom")
	}
	if code := run([]string{"--doctor-json"}, deps); code == 0 {
		t.Fatalf("expected non-zero exit")
	}
	if !strings.Contains(stderr.String(), "doctor-json boom") {
		t.Fatalf("stderr missing hook error: %q", stderr.String())
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

func writeMainSignedBundle(t *testing.T, dir, archivePath string, passwords []string) (string, string) {
	t.Helper()
	f, err := os.Open(archivePath)
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	digest := hashdb.ArchiveHash(f)
	f.Close()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	var recs []hashdb.Record
	for _, pw := range passwords {
		r, err := hashdb.BuildRecord(digest, pw, "test")
		if err != nil {
			t.Fatalf("BuildRecord: %v", err)
		}
		recs = append(recs, r)
	}
	signed, err := hashdb.SignBundle(hashdb.Bundle{Source: "test", Records: recs}, priv)
	if err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	data, err := hashdb.MarshalSignedBundle(signed)
	if err != nil {
		t.Fatalf("MarshalSignedBundle: %v", err)
	}
	p := filepath.Join(dir, "main-bundle.json")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return p, hex.EncodeToString(pub)
}

func TestRunHashDBVerifySourceNamedLocalBundle(t *testing.T) {
	dir := setupTempConfig(t)
	archive := filepath.Join(dir, "archive.bin")
	if err := os.WriteFile(archive, []byte("main-verify"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	bundlePath, pubHex := writeMainSignedBundle(t, dir, archive, []string{"p1", "p2"})

	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	cfg.HashDB.Mode = "lookup"
	cfg.HashDB.Sources = []config.HashDBSource{
		{Name: "local", Type: "bundle", Path: bundlePath, PublicKey: pubHex},
	}
	if err := config.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	config.ReloadAll()

	deps, stdout, stderr := newTestDeps()
	code := run([]string{"--hashdb-verify-source", "local"}, deps)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "local") {
		t.Fatalf("stdout missing source name: %s", out)
	}
	if !strings.Contains(out, "ok") {
		t.Fatalf("stdout missing ok status: %s", out)
	}
	if !strings.Contains(out, "records=2") {
		t.Fatalf("stdout missing records count: %s", out)
	}
}

func TestRunHashDBVerifySourceAllReturnsNonZeroWhenMissingCache(t *testing.T) {
	dir := setupTempConfig(t)
	cacheDir := filepath.Join(dir, "hashdb-cache")
	archive := filepath.Join(dir, "archive.bin")
	if err := os.WriteFile(archive, []byte("main-verify-all"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	bundlePath, pubHex := writeMainSignedBundle(t, dir, archive, []string{"p"})

	cfg, err := config.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	cfg.HashDB.Mode = "lookup"
	cfg.HashDB.Sources = []config.HashDBSource{
		{Name: "local", Type: "bundle", Path: bundlePath, PublicKey: pubHex},
		{Name: "mirror", Type: "bundle", URL: "https://example.invalid/x.bundle.json", CacheDir: cacheDir},
	}
	if err := config.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	config.ReloadAll()

	deps, stdout, stderr := newTestDeps()
	code := run([]string{"--hashdb-verify-source", "--all"}, deps)
	if code == 0 {
		t.Fatalf("expected non-zero exit, stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "local") || !strings.Contains(out, "mirror") {
		t.Fatalf("expected both names in stdout: %s", out)
	}
	if !strings.Contains(out, "missing_cache") {
		t.Fatalf("expected missing_cache in stdout: %s", out)
	}
	if !strings.Contains(out, "ok") {
		t.Fatalf("expected ok marker for local source in stdout: %s", out)
	}
}

func TestRunHashDBVerifySourceMissingArgReturnsNonZero(t *testing.T) {
	setupTempConfig(t)
	deps, _, stderr := newTestDeps()
	if code := run([]string{"--hashdb-verify-source"}, deps); code == 0 {
		t.Fatalf("expected non-zero exit")
	}
	if !strings.Contains(stderr.String(), "--hashdb-verify-source") {
		t.Fatalf("expected usage hint in stderr, got: %q", stderr.String())
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
