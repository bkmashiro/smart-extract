package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const DefaultEndpoint = "http://127.0.0.1:17321"

type Client struct {
	Endpoint    string
	BearerToken string
	HTTPClient  *http.Client
	Timeout     time.Duration
}

func (c Client) LookupPasswords(ctx context.Context, query LookupQuery) ([]CandidatePassword, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(c.Endpoint), "/")
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	u, err := url.Parse(endpoint + "/v1/passwords")
	if err != nil {
		return nil, err
	}
	q := u.Query()
	if strings.TrimSpace(query.File) != "" {
		q.Set("file", query.File)
	}
	if strings.TrimSpace(query.URL) != "" {
		q.Set("url", query.URL)
	}
	u.RawQuery = q.Encode()

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	if c.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.BearerToken)
	}

	hc := c.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("helper lookup status %d", resp.StatusCode)
	}
	var decoded PasswordsResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return nil, err
	}
	if decoded.SchemaVersion != SchemaVersion {
		return nil, errors.New("helper lookup unsupported schema_version")
	}
	return decoded.Passwords, nil
}
