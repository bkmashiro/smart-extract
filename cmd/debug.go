package cmd

import (
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type debugLogger struct {
	mu sync.Mutex
	w  io.Writer
}

func newDebugLogger(w io.Writer) *debugLogger {
	if w == nil {
		return nil
	}
	return &debugLogger{w: w}
}

func (l *debugLogger) Logf(format string, args ...interface{}) {
	if l == nil || l.w == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	line := fmt.Sprintf(format, args...)
	line = sanitizeDebugLine(line)
	fmt.Fprintf(l.w, "%s %s", ts, line)
	if !strings.HasSuffix(line, "\n") {
		fmt.Fprintln(l.w)
	}
}

var debugSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(password|passwd|pass|pwd)[=_-][^\s/\\]+`),
	regexp.MustCompile(`(?i)密码[=_-]?[^\s/\\]+`),
}

func sanitizeDebugLine(s string) string {
	out := s
	out = debugSecretPatterns[0].ReplaceAllString(out, "$1=[redacted]")
	out = debugSecretPatterns[1].ReplaceAllString(out, "密码=[redacted]")
	return out
}

func debugProfileName(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "light":
		return "light"
	case "aggressive":
		return "aggressive"
	default:
		return "normal"
	}
}

func sortedCountSummary(counts map[string]int) string {
	if len(counts) == 0 {
		return ""
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", key, counts[key]))
	}
	return strings.Join(parts, " ")
}
