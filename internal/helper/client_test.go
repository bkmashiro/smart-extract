package helper

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientLookupPasswordsUsesStableQueryAndBearerToken(t *testing.T) {
	store := NewMemoryStore(time.Minute)
	_, err := store.Add(CandidateBundle{
		SchemaVersion:   1,
		Source:          "boltqr",
		ArchiveFilename: "demo.zip",
		Candidates:      []CandidatePassword{{Value: "client-secret", Source: "page_text", Score: 0.7}},
	})
	if err != nil {
		t.Fatalf("seed store: %v", err)
	}
	server := httptest.NewServer(NewHandler(store, Options{BearerToken: "test-token"}))
	defer server.Close()

	client := Client{Endpoint: server.URL, BearerToken: "test-token", HTTPClient: server.Client()}
	got, err := client.LookupPasswords(context.Background(), LookupQuery{File: "demo.zip"})
	if err != nil {
		t.Fatalf("LookupPasswords: %v", err)
	}
	if len(got) != 1 || got[0].Value != "client-secret" || got[0].Source != "helper:page_text" {
		t.Fatalf("passwords = %+v, want client-secret", got)
	}
}

func TestClientLookupPasswordsTreatsMissingHelperAsEmpty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	server.Close()

	client := Client{Endpoint: server.URL, BearerToken: "test-token", Timeout: 50 * time.Millisecond}
	got, err := client.LookupPasswords(context.Background(), LookupQuery{File: "demo.zip"})
	if err != nil {
		t.Fatalf("LookupPasswords should soft-fail when helper is unreachable: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("passwords = %+v, want empty", got)
	}
}
