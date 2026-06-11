# Local helper password candidate protocol v1

Smart Extract exposes an optional loopback-only helper for browser/QR tools such as BoltQR.
The interface is versioned as `schema_version: 1`; keep this contract stable and add new optional fields instead of changing existing ones.

## Security defaults

- Bind only to loopback, default endpoint: `http://127.0.0.1:17321`.
- Every request should include a standard bearer-token `Authorization` header.
- `smart-extract.exe --serve-helper` creates/reuses a local token file when `local_helper.token` is not configured inline.
- Candidate values stay local; they are not uploaded to HashDB or any remote source.

## POST /v1/candidates

Stores a short-lived bundle of broad password candidates collected from a page/QR context.
The helper trims, deduplicates, drops empty/extreme candidates, and filters UI-label-only junk.

Request:

```json
{
  "schema_version": 1,
  "source": "boltqr",
  "page_url": "https://example.test/post/1",
  "archive_url": "https://files.example.test/downloads/Demo%20Pack.zip",
  "archive_filename": "Demo Pack.zip",
  "observed_at": "2026-06-11T12:00:00Z",
  "candidates": [
    {
      "value": "page-secret",
      "source": "page_text",
      "reason": "near_qr",
      "score": 0.8
    }
  ]
}
```

Response `202 Accepted`:

```json
{
  "schema_version": 1,
  "accepted": 1,
  "stored": 1,
  "expires_at": "2026-06-11T12:30:00Z"
}
```

## GET /v1/passwords

Returns matching local helper candidates for the extractor. Query by filename and/or URL:

```text
GET /v1/passwords?file=Demo%20Pack.zip
GET /v1/passwords?url=https%3A%2F%2Ffiles.example.test%2Fdownloads%2FDemo%2520Pack.zip
```

Response `200 OK`:

```json
{
  "schema_version": 1,
  "passwords": [
    {
      "value": "page-secret",
      "source": "helper:page_text",
      "reason": "near_qr",
      "score": 0.8
    }
  ]
}
```

## Candidate ordering inside extraction

When `local_helper.mode: lookup` is enabled, helper candidates are queried with a sub-second timeout and are optional. If the helper is not running, extraction silently continues.

Ordering is:

1. parent recursive password
2. exact local SQLite cache
3. local helper candidates
4. HashDB candidates
5. filename hints
6. session/pattern/dictionary/static candidates
7. empty password and fallback passwords

## Config example

```yaml
local_helper:
  mode: lookup
  endpoint: http://127.0.0.1:17321
  token_path: /path/to/local-helper.token
```

Run the service:

```bash
smart-extract.exe --serve-helper
```


