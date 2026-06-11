package helper

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const SchemaVersion = 1

// Options configures the loopback helper HTTP protocol.
type Options struct {
	BearerToken string
}

// CandidateBundle is the stable /v1/candidates request body accepted from
// local browser/QR helpers. Candidate values are local-only password guesses.
type CandidateBundle struct {
	SchemaVersion   int                 `json:"schema_version"`
	Source          string              `json:"source,omitempty"`
	PageURL         string              `json:"page_url,omitempty"`
	ArchiveURL      string              `json:"archive_url,omitempty"`
	ArchiveFilename string              `json:"archive_filename,omitempty"`
	ObservedAt      time.Time           `json:"observed_at,omitempty"`
	Candidates      []CandidatePassword `json:"candidates"`
}

type CandidatePassword struct {
	Value  string  `json:"value"`
	Source string  `json:"source,omitempty"`
	Reason string  `json:"reason,omitempty"`
	Score  float64 `json:"score,omitempty"`
}

type CandidateResponse struct {
	SchemaVersion int       `json:"schema_version"`
	Accepted      int       `json:"accepted"`
	Stored        int       `json:"stored"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type PasswordsResponse struct {
	SchemaVersion int                 `json:"schema_version"`
	Passwords     []CandidatePassword `json:"passwords"`
}

type LookupQuery struct {
	File string
	URL  string
}

type Store interface {
	Add(bundle CandidateBundle) (CandidateResponse, error)
	Lookup(query LookupQuery) ([]CandidatePassword, error)
}

type MemoryStore struct {
	mu      sync.Mutex
	ttl     time.Duration
	bundles []storedBundle
}

type storedBundle struct {
	bundle    CandidateBundle
	expiresAt time.Time
}

func NewMemoryStore(ttl time.Duration) *MemoryStore {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	return &MemoryStore{ttl: ttl}
}

func (s *MemoryStore) Add(bundle CandidateBundle) (CandidateResponse, error) {
	now := time.Now()
	if bundle.ObservedAt.IsZero() {
		bundle.ObservedAt = now
	}
	bundle.SchemaVersion = SchemaVersion
	bundle.Candidates = cleanCandidates(bundle.Candidates)
	expiresAt := now.Add(s.ttl)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	if len(bundle.Candidates) > 0 {
		s.bundles = append(s.bundles, storedBundle{bundle: bundle, expiresAt: expiresAt})
	}
	return CandidateResponse{
		SchemaVersion: SchemaVersion,
		Accepted:      len(bundle.Candidates),
		Stored:        len(bundle.Candidates),
		ExpiresAt:     expiresAt,
	}, nil
}

func (s *MemoryStore) Lookup(query LookupQuery) ([]CandidatePassword, error) {
	now := time.Now()
	fileKey := normalizeFileKey(query.File)
	urlKey := normalizeURLKey(query.URL)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)

	seen := make(map[string]struct{})
	var out []CandidatePassword
	for i := len(s.bundles) - 1; i >= 0; i-- {
		bundle := s.bundles[i].bundle
		if !bundleMatches(bundle, fileKey, urlKey) {
			continue
		}
		for _, candidate := range bundle.Candidates {
			if _, ok := seen[candidate.Value]; ok {
				continue
			}
			seen[candidate.Value] = struct{}{}
			candidate.Source = helperSource(candidate.Source)
			out = append(out, candidate)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Score > out[j].Score
	})
	return out, nil
}

func (s *MemoryStore) pruneLocked(now time.Time) {
	kept := s.bundles[:0]
	for _, b := range s.bundles {
		if now.Before(b.expiresAt) {
			kept = append(kept, b)
		}
	}
	s.bundles = kept
}

func NewHandler(store Store, opts Options) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/candidates", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, opts.BearerToken) {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var bundle CandidateBundle
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&bundle); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid json")
			return
		}
		if bundle.SchemaVersion != 0 && bundle.SchemaVersion != SchemaVersion {
			writeJSONError(w, http.StatusBadRequest, "unsupported schema_version")
			return
		}
		resp, err := store.Add(bundle)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "store failed")
			return
		}
		writeJSON(w, http.StatusAccepted, resp)
	})
	mux.HandleFunc("/v1/passwords", func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r, opts.BearerToken) {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		passwords, err := store.Lookup(LookupQuery{File: r.URL.Query().Get("file"), URL: r.URL.Query().Get("url")})
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "lookup failed")
			return
		}
		writeJSON(w, http.StatusOK, PasswordsResponse{SchemaVersion: SchemaVersion, Passwords: passwords})
	})
	return mux
}

func authorized(r *http.Request, token string) bool {
	if token == "" {
		return true
	}
	got := strings.TrimSpace(r.Header.Get("Authorization"))
	want := "Bearer " + token
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func cleanCandidates(in []CandidatePassword) []CandidatePassword {
	seen := make(map[string]struct{})
	var out []CandidatePassword
	for _, candidate := range in {
		candidate.Value = strings.TrimSpace(candidate.Value)
		candidate.Source = strings.TrimSpace(candidate.Source)
		candidate.Reason = strings.TrimSpace(candidate.Reason)
		if !acceptableCandidate(candidate.Value) {
			continue
		}
		if _, ok := seen[candidate.Value]; ok {
			continue
		}
		seen[candidate.Value] = struct{}{}
		out = append(out, candidate)
	}
	return out
}

func acceptableCandidate(value string) bool {
	if value == "" || len([]rune(value)) > 256 {
		return false
	}
	switch strings.ToLower(value) {
	case "copy", "复制", "下載", "下载", "password", "pass", "pwd", "密码", "解压密码":
		return false
	}
	return true
}

func bundleMatches(bundle CandidateBundle, fileKey, urlKey string) bool {
	if fileKey != "" {
		if normalizeFileKey(bundle.ArchiveFilename) == fileKey {
			return true
		}
		if normalizeFileKey(urlBasename(bundle.ArchiveURL)) == fileKey {
			return true
		}
	}
	if urlKey != "" && normalizeURLKey(bundle.ArchiveURL) == urlKey {
		return true
	}
	return false
}

func normalizeFileKey(file string) string {
	file = strings.TrimSpace(file)
	if file == "" {
		return ""
	}
	if decoded, err := url.QueryUnescape(file); err == nil {
		file = decoded
	}
	file = filepath.Base(file)
	return strings.ToLower(file)
}

func normalizeURLKey(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	u.Fragment = ""
	return strings.ToLower(u.String())
}

func urlBasename(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return raw
	}
	return filepath.Base(u.Path)
}

func helperSource(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return "helper"
	}
	if strings.HasPrefix(source, "helper:") {
		return source
	}
	return "helper:" + source
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"schema_version": SchemaVersion, "error": message})
}
