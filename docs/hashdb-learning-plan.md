# HashDB and Learning System Implementation Plan

> **For Hermes:** Use test-driven-development for production code changes. Keep the first implementation slice small: local crypto primitives and documented source format before network lookup.

**Goal:** Replace ad-hoc password learning with a local-first learning system and an optional decentralized HashDB subscription model.

**Architecture:** Local learning remains authoritative and private by default. Successful extractions append raw filename-password observations into SQLite, then delayed summarizers derive pattern rules. Optional HashDB sources are signed, static, sharded repositories whose records contain archive-bound encrypted passwords, so transport and hosting can be untrusted.

**Tech Stack:** Go 1.21+, SQLite for local learning storage in a later phase, standard-library cryptography for HashDB primitives, static HTTP/file sources for decentralized distribution.

---

## Product Principles

1. **No surprise network or sharing.** HashDB lookup and contribution are opt-in.
2. **Local first.** Exact cache, session context, and local pattern learning work without internet.
3. **Raw observations are preserved.** A successful extraction is an observation, not immediately a durable rule.
4. **Derived rules are batch-built.** Shared-password filename sets can reveal patterns that single-step learning cannot.
5. **Community data is untrusted until verified locally.** A HashDB candidate only becomes local knowledge after the archive actually extracts.
6. **The server should not need plaintext passwords.** HashDB records encrypt the password with a key derived from the archive hash.
7. **Distribution is decentralized.** Official HashDB is one signed source; users can add community, private, file://, HTTPS, mirror, or later IPFS/torrent-like sources.

---

## Phase 1: Document and Implement HashDB Crypto Core — **Implemented**

**Objective:** Add the local cryptographic primitive used by all future HashDB sources.

**Files:**
- Create: `internal/hashdb/crypto.go`
- Test: `internal/hashdb/crypto_test.go`
- Document: `docs/hashdb-learning-plan.md`

**Behavior:**
- `ArchiveHash(data)` returns SHA-256 of archive bytes.
- `RecordID(archiveHash)` returns a deterministic lookup key derived from the archive hash and a domain-separated label.
- `EncryptPassword(archiveHash, password)` returns nonce+ciphertext using AES-GCM with a key derived via HMAC-SHA256 domain separation.
- `DecryptPassword(archiveHash, nonce, ciphertext)` recovers the password only with the same archive hash.
- Decryption with another archive hash fails.

**Verification:**
- Run `go test ./internal/hashdb -v`.
- Run `go test ./...`.

---

## Phase 2: SQLite Learning Store — **Implemented**

**Objective:** Introduce append-only raw observations and migration from `learned.yaml` without replacing the current extractor path yet.

**Files:**
- Create: `internal/store/schema.go`
- Create: `internal/store/sqlite.go`
- Create: `internal/store/migrate.go`
- Test: `internal/store/*_test.go`

**Tables:**
- `archive_cache`: exact archive signature/hash/name cache.
- `password_observation`: append-only raw archive filename/password observations.
- `pattern_rule`: derived batch rules.
- `password_dict`: local password popularity, with random-password anti-promotion.
- `session_context`: recent same-root/same-directory successes.
- `preferences`: budget, privacy, and UI choices.

**Migration:**
- Read existing `learned.yaml` if present.
- Import `exact`, `person_stats`, `person_filenames`, `password_hit_count`, and preferences.
- Do not delete YAML automatically.
- Mark migration version in SQLite.

---

## Phase 3: Candidate Builder — **Implemented**

**Objective:** Generate password candidates from local sources in a deterministic, explainable order.

**Candidate order:**
1. Parent password from recursive context.
2. Local exact cache.
3. Filename/parent-directory explicit extraction.
4. Session and sibling context.
5. Batch-derived `pattern_rule` hits.
6. Online Thompson/pattern stats.
7. Local dictionary top-K.
8. Empty password.
9. Config fallback passwords.

**Rules:**
- Deduplicate by password.
- Preserve source labels for learning and debugging.
- Respect cost budget candidate caps.

---

## Phase 4: Batch Summarizer — **Implemented**

**Objective:** Convert raw observations into stronger pattern rules.

**Algorithm:**
1. Group observations by password.
2. Extract filename tokens, shape signatures, parent-directory signals, and n-gram centroids.
3. Compute support and purity for candidate rules.
4. Promote only rules meeting thresholds, e.g. `support >= 3` and `confidence >= 0.7`.
5. Avoid promoting high-entropy one-off random passwords into global dictionary.

**Triggering:**
- After N new observations.
- After a time interval.
- On manual command such as `smart-extract --learn`.

---

## Phase 5: Cost-Aware Probe and Parallelism — **Implemented locally**

**Objective:** Make automatic attempts fast and bounded.

**Budget tiers:**
- `light`: small candidate cap and wall-clock budget.
- `normal`: default.
- `aggressive`: more attempts for users who prefer success over speed.

**Probe tiers:**
- L0: cheap header/list probe only where format supports password validation.
- L1: smallest-entry test where list is visible but content is encrypted.
- L2: full extraction/test, strictly budgeted.

**Parallelism:**
- Auto by `runtime.NumCPU()` and archive/probe cost.
- Limit L2 on large archives and HDD-like storage.
- Use a Windows named semaphore later to avoid Explorer multi-process overload.

---

## Phase 6: Decentralized HashDB Sources — **Implemented for local file and static HTTP sources**

**Objective:** Add optional signed static sources that can be hosted anywhere.

**Record model:**
- `archive_hash = SHA256(archive bytes)` stays local.
- `record_id = H("smart-extract hashdb record id v1" || archive_hash)`.
- `key = HMAC-SHA256(archive_hash, "smart-extract hashdb password key v1")`.
- `ciphertext = AEAD_Encrypt(key, password)`.

**Source model:**
- Single-file signed bundles are supported for small/private sources.
- `manifest.json` + signed shard files are supported for sharded file sources.
- Static `http://`/`https://` bundle URLs are downloaded once into a local cache before lookup.
- Static sharded `manifest_url` sources cache the manifest plus only the matching shard for the archive record-id prefix.
- Shards are addressed by record-id prefix.
- Client validates source Ed25519 signatures and shard hashes.
- Query loads only the matching local shard rather than the whole source.

**Distribution:**
- `https://` and `file://` first.
- Mirrors and content-addressed cache next.
- Optional IPFS/torrent-like snapshot distribution later.

**Trust:**
- Official source is just one source.
- Users can subscribe to third-party or private sources by URL + public key.
- Bad sources cannot execute code; they only provide candidates.
- Candidates do not become local facts unless extraction succeeds.

---

## Phase 7: Contribution Flow — **Implemented for local bundle/sharded sinks**

**Objective:** Allow users to contribute encrypted records without leaking plaintext passwords to the service.

**Default:** off.

**Modes:**
- `off`: no contribution.
- `ask`: prompt before appending a successful non-empty password to a configured local sink.
- `auto`: advanced opt-in; append successful non-empty passwords silently.

**Contribution target:**
- Local private signed bundle.
- Local private sharded source.
- Official/third-party submit APIs are future work.

---

## Implemented Config Shape

Defaults are private and offline: no lookup and no contribution unless explicitly configured.

```yaml
hashdb:
  mode: lookup                  # off | lookup
  sources:
    - name: private-bundle
      type: bundle
      path: ./hashdb/private.bundle.json
      public_key: "<hex ed25519 public key>"
    - name: private-shards
      type: sharded
      base_dir: ./hashdb/private
      public_key: "<hex ed25519 public key>"
    - name: mirror-bundle
      type: bundle
      url: https://example.com/hashdb/private.bundle.json.gz
      compression: gzip
      sha256: "<hex sha256 of downloaded .gz bytes>"
      cache_dir: ./hashdb/cache
      public_key: "<hex ed25519 public key>"
    - name: mirror-shards
      type: sharded
      manifest_url: https://example.com/hashdb/manifest.json
      cache_dir: ./hashdb/cache
      public_key: "<hex ed25519 public key>"

  contribute: ask               # off | ask | auto
  contribution:
    type: sharded               # sharded | bundle
    base_dir: ./hashdb/private
    # path: ./hashdb/private.bundle.json   # for type: bundle
    key_path: ./hashdb/private/signing.key.json
    source: local-private
    shard_prefix_length: 2
```

Successful top-level and nested extractions go through the same success callback. When `contribute: ask` is configured, the callback confirms before appending an encrypted archive-bound record to the configured local sink; cancel/skip leaves HashDB untouched while extraction and local SQLite learning still succeed. When `contribute: auto` is configured, the same append happens silently. Contribution failures are warnings only; extraction and local SQLite learning still succeed.

Static HTTP mirror sources may serve gzip-compressed bundles or shards. Bundle sources use `compression: gzip` and optional `sha256` in `hashdb.sources[]`; sharded manifests put `compression: "gzip"` on individual shards and keep `sha256` bound to the compressed mirror bytes. The local cache stores decompressed canonical signed bundle/shard files for lookup.

---

Source and cache management is implemented: `--hashdb-list-sources` prints each configured source with its resolved HTTP cache directory and existence, `--hashdb-disable-source <name>` / `--hashdb-enable-source <name>` flip the source's `disabled` flag while preserving source order and fields, and `--hashdb-clear-cache <name>` / `--hashdb-clear-cache --all` removes HTTP source cache roots (with dedup) without touching local-only bundle/sharded sources.

Debug observability is implemented via `--debug-log <log.txt> <archive> [archive...]`. The log records extraction progress, candidate source counts, budget profile/limits, HashDB source skip/lookup/error summaries, and success/failure markers while avoiding plaintext password values and redacting filename password hints such as `password=...`, `pwd-...`, and `密码...`.

## Remaining Work

- Optional zstd/IPFS/torrent-like snapshot distribution later; gzip-compressed static HTTP bundles/shards are implemented.

---

## Acceptance Criteria

- Existing extraction behavior remains working at every phase.
- Tests cover each new module before production code is added.
- No network request happens unless HashDB lookup is explicitly enabled.
- No plaintext password is sent to a HashDB source.
- HashDB data never pollutes local learning until a local extraction verifies it.
- Recursive extraction and flattening remain compatible with the candidate pipeline.
