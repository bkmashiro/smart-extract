package helper

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCandidateProtocolStoresAndMatchesByArchiveFilename(t *testing.T) {
	store := NewMemoryStore(10 * time.Minute)
	handler := NewHandler(store, Options{BearerToken: "test-token"})

	postBody := `{
		"schema_version": 1,
		"source": "boltqr",
		"page_url": "https://example.test/post/1",
		"archive_url": "https://files.example.test/downloads/Demo%20Pack.zip",
		"archive_filename": "Demo Pack.zip",
		"candidates": [
			{"value":" page-secret ","source":"page_text","reason":"near_qr","score":0.8},
			{"value":"page-secret","source":"copy_button","reason":"duplicate","score":0.4},
			{"value":"复制","source":"button_text","reason":"ui_junk","score":0.9},
			{"value":"backup-secret","source":"title","reason":"near_download","score":0.5}
		]
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/candidates", strings.NewReader(postBody))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST status = %d body=%s", rec.Code, rec.Body.String())
	}
	var accepted CandidateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &accepted); err != nil {
		t.Fatalf("decode POST response: %v", err)
	}
	if accepted.SchemaVersion != 1 || accepted.Accepted != 2 || accepted.Stored != 2 {
		t.Fatalf("POST response = %+v, want schema=1 accepted=2 stored=2", accepted)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/passwords?file=demo+pack.zip", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d body=%s", rec.Code, rec.Body.String())
	}
	var got PasswordsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode GET response: %v", err)
	}
	if got.SchemaVersion != 1 {
		t.Fatalf("schema_version = %d, want 1", got.SchemaVersion)
	}
	if len(got.Passwords) != 2 {
		t.Fatalf("password count = %d, want 2: %+v", len(got.Passwords), got.Passwords)
	}
	if got.Passwords[0].Value != "page-secret" || got.Passwords[0].Source != "helper:page_text" {
		t.Fatalf("password[0] = %+v, want trimmed/deduped page-secret from page_text", got.Passwords[0])
	}
	if got.Passwords[1].Value != "backup-secret" {
		t.Fatalf("password[1] = %+v, want backup-secret", got.Passwords[1])
	}
}

func TestCandidateProtocolRequiresBearerToken(t *testing.T) {
	handler := NewHandler(NewMemoryStore(time.Minute), Options{BearerToken: "test-token"})

	for _, tc := range []struct {
		name string
		req  *http.Request
	}{
		{"post", httptest.NewRequest(http.MethodPost, "/v1/candidates", bytes.NewBufferString(`{"schema_version":1}`))},
		{"get", httptest.NewRequest(http.MethodGet, "/v1/passwords?file=a.zip", nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, tc.req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d body=%s, want 401", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestCandidateProtocolMatchesByURLAndExpiresOldBundles(t *testing.T) {
	store := NewMemoryStore(20 * time.Millisecond)
	handler := NewHandler(store, Options{BearerToken: "test-token"})

	req := httptest.NewRequest(http.MethodPost, "/v1/candidates", strings.NewReader(`{
		"schema_version":1,
		"source":"boltqr",
		"archive_url":"https://files.example.test/a/secret.7z?download=1",
		"candidates":[{"value":"url-secret","source":"qr_url","score":0.6}]
	}`))
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST status = %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/passwords?url=https%3A%2F%2Ffiles.example.test%2Fa%2Fsecret.7z%3Fdownload%3D1", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d body=%s", rec.Code, rec.Body.String())
	}
	var got PasswordsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode GET response: %v", err)
	}
	if len(got.Passwords) != 1 || got.Passwords[0].Value != "url-secret" {
		t.Fatalf("passwords before expiry = %+v, want url-secret", got.Passwords)
	}

	time.Sleep(35 * time.Millisecond)
	req = httptest.NewRequest(http.MethodGet, "/v1/passwords?file=secret.7z", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET after expiry status = %d body=%s", rec.Code, rec.Body.String())
	}
	got = PasswordsResponse{}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode GET after expiry: %v", err)
	}
	if len(got.Passwords) != 0 {
		t.Fatalf("passwords after expiry = %+v, want none", got.Passwords)
	}
}
