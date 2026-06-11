package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bkmashiro/smart-extract/internal/config"
)

func TestLocalHelperListenAddrRequiresLoopbackHTTP(t *testing.T) {
	got, err := localHelperListenAddr("http://127.0.0.1:17321")
	if err != nil {
		t.Fatalf("localHelperListenAddr loopback: %v", err)
	}
	if got != "127.0.0.1:17321" {
		t.Fatalf("addr = %q, want 127.0.0.1:17321", got)
	}
	for _, endpoint := range []string{"https://127.0.0.1:17321", "http://0.0.0.0:17321", "http://example.com:17321", "http://127.0.0.1"} {
		if _, err := localHelperListenAddr(endpoint); err == nil {
			t.Fatalf("localHelperListenAddr(%q) succeeded, want error", endpoint)
		}
	}
}

func TestResolveLocalHelperTokenCreatesAndReusesTokenFile(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "helper.token")
	token, path, err := resolveLocalHelperToken(config.LocalHelperConfig{TokenPath: tokenPath})
	if err != nil {
		t.Fatalf("resolveLocalHelperToken create: %v", err)
	}
	if path != tokenPath || len(token) < 32 {
		t.Fatalf("token/path = %q/%q", token, path)
	}
	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatalf("stat token: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("token file mode = %v, want 0600", info.Mode().Perm())
	}

	again, path, err := resolveLocalHelperToken(config.LocalHelperConfig{TokenPath: tokenPath})
	if err != nil {
		t.Fatalf("resolveLocalHelperToken reuse: %v", err)
	}
	if again != token || path != tokenPath {
		t.Fatalf("reused token/path = %q/%q, want %q/%q", again, path, token, tokenPath)
	}
}

func TestResolveLocalHelperTokenPrefersInlineConfig(t *testing.T) {
	token, path, err := resolveLocalHelperToken(config.LocalHelperConfig{Token: " inline-token \n"})
	if err != nil {
		t.Fatalf("resolveLocalHelperToken inline: %v", err)
	}
	if token != "inline-token" || path != "" || strings.Contains(token, "\n") {
		t.Fatalf("token/path = %q/%q", token, path)
	}
}
