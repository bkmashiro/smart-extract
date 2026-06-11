package cmd

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bkmashiro/smart-extract/internal/config"
	"github.com/bkmashiro/smart-extract/internal/helper"
)

// ServeLocalHelper starts the loopback-only candidate handoff service. It is a
// blocking call intended for `smart-extract.exe --serve-helper`.
func ServeLocalHelper(w io.Writer) error {
	if w == nil {
		w = io.Discard
	}
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("加载配置失败: %w", err)
	}
	token, tokenPath, err := resolveLocalHelperToken(cfg.LocalHelper)
	if err != nil {
		return err
	}
	addr, err := localHelperListenAddr(cfg.LocalHelper.Endpoint)
	if err != nil {
		return err
	}
	store := helper.NewMemoryStore(30 * time.Minute)
	server := &http.Server{
		Addr:              addr,
		Handler:           helper.NewHandler(store, helper.Options{BearerToken: token}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	if tokenPath != "" {
		fmt.Fprintf(w, "local helper token: %s\n", tokenPath)
	}
	fmt.Fprintf(w, "local helper listening: http://%s\n", addr)
	return server.ListenAndServe()
}

func resolveLocalHelperToken(cfg config.LocalHelperConfig) (token, tokenPath string, err error) {
	if strings.TrimSpace(cfg.Token) != "" {
		return strings.TrimSpace(cfg.Token), "", nil
	}
	tokenPath = strings.TrimSpace(cfg.TokenPath)
	if tokenPath == "" {
		tokenPath = defaultLocalHelperTokenPath()
	}
	if data, readErr := os.ReadFile(tokenPath); readErr == nil {
		if token = strings.TrimSpace(string(data)); token != "" {
			return token, tokenPath, nil
		}
	} else if !os.IsNotExist(readErr) {
		return "", tokenPath, fmt.Errorf("读取 local helper token 失败: %w", readErr)
	}
	token, err = generateLocalHelperToken()
	if err != nil {
		return "", tokenPath, err
	}
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
		return "", tokenPath, fmt.Errorf("创建 local helper token 目录失败: %w", err)
	}
	if err := os.WriteFile(tokenPath, []byte(token+"\n"), 0o600); err != nil {
		return "", tokenPath, fmt.Errorf("写入 local helper token 失败: %w", err)
	}
	return token, tokenPath, nil
}

func defaultLocalHelperTokenPath() string {
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "smart-extract", "local-helper.token")
	}
	return filepath.Join(os.TempDir(), "smart-extract-local-helper.token")
}

func generateLocalHelperToken() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("生成 local helper token 失败: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func localHelperListenAddr(endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		endpoint = helper.DefaultEndpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || u.Host == "" {
		return "", fmt.Errorf("local helper endpoint 必须是 http://127.0.0.1:port")
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil || port == "" {
		return "", fmt.Errorf("local helper endpoint 必须包含端口: %s", endpoint)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("local helper 只能绑定 loopback 地址: %s", host)
	}
	return net.JoinHostPort(ip.String(), port), nil
}
