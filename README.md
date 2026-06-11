# smart-extract (智能解压)

A Windows tool that adds a right-click context menu entry to intelligently extract password-protected archives.

## Features

- Right-click any `.zip`, `.rar`, `.7z`, `.tar.gz`, etc. → "智能解压" menu
- Multi-select files supported (Windows calls the exe once per file, in parallel)
- Local-first password learning backed by SQLite (`learning.db`):
  exact archive cache, raw password observations, derived pattern rules,
  session/sibling context, and a local password dictionary.
- Deterministic candidate builder ordering parent-recursive → exact cache →
  local helper (QR/browser page candidates) → HashDB → filename/parent
  extraction → session context → pattern rules → online stats → local
  dictionary → empty → config fallback.
- Cost budget profiles (`light` / `normal` / `aggressive`) and bounded
  parallelism for fast, predictable probing, including a cross-process
  lock-file throttle so Explorer multi-select launches do not each consume
  the full local probe budget.
- Optional **local-only** HashDB lookup and contribution: signed bundles and
  sharded directories on disk. No network access by default; plaintext
  passwords are never written to bundle/shard files (records are AES-GCM
  encrypted with keys derived from the archive hash).
- Recursive extraction (nested archives) and automatic single-folder
  flattening (e.g., `output/output/files` → `output/files`).
- ML features: n-gram person identification, Thompson Sampling, auto-clustering hints
- Native Windows dialogs (via zenity) for unknown passwords
- Named Windows mutex to prevent duplicate dialogs

## Installation

1. Download or build `smart-extract.exe`
2. Place it anywhere (e.g., `C:\Tools\smart-extract\`)
3. Edit `config.yaml` next to the exe (copy from the example)
4. Run as Administrator: `smart-extract.exe --install`

## Build

```powershell
GOOS=windows GOARCH=amd64 go build -ldflags="-H windowsgui" -o smart-extract.exe .
```

Or on Windows:
```
go build -ldflags="-H windowsgui" -o smart-extract.exe .
```

## Usage

```
smart-extract.exe --install     Install right-click menu
smart-extract.exe --uninstall   Remove right-click menu
smart-extract.exe --hashdb-public-key ./hashdb/private/signing.key.json
smart-extract.exe --doctor
smart-extract.exe --doctor-json
smart-extract.exe --serve-helper
smart-extract.exe --debug-log .\smart-extract-debug.log <archive>
smart-extract.exe --explain <archive>
smart-extract.exe --explain-json <archive>
smart-extract.exe <archive>     Extract an archive (called by Explorer)
```

## Configuration

### config.yaml

```yaml
sevenzip_path: ""  # auto-detected if empty

# Optional. Defaults: normal budget, auto parallelism.
probe_budget_profile: normal     # light | normal | aggressive
max_parallel_probes: 0           # 0 = auto (runtime.NumCPU based)

people:
  alice:
    patterns: ["alice_\\d+", "ALI"]
    match_mode: pattern   # "pattern" or "always_try"
    priority: 0
    passwords: ["alice123", "alice2024"]

fallback_passwords:
  - "123456"
  - ""

# Optional BoltQR/browser page-candidate handoff. See docs/local-helper-protocol-v1.md.
local_helper:
  mode: off        # off | lookup
  endpoint: http://127.0.0.1:17321
  token_path: ./local-helper.token

# Optional. HashDB is off by default and never touches the network.
hashdb:
  mode: off              # off | lookup
  sources: []            # see examples below
  contribute: off        # off | ask | auto
```

#### HashDB lookup from a local signed bundle and a local sharded source

```yaml
hashdb:
  mode: lookup
  sources:
    - name: shared-bundle
      type: bundle
      path: ./hashdb/shared.bundle.json
      public_key: "<hex ed25519 public key>"
    - name: team-shards
      type: sharded
      base_dir: ./hashdb/team
      public_key: "<hex ed25519 public key>"
```

#### HashDB lookup from static HTTP sources with local cache

Network lookup is still opt-in: set `hashdb.mode: lookup` and configure an
HTTP/HTTPS source. The first lookup downloads the signed bundle, or the sharded
manifest plus only the matching shard, into `cache_dir`; later lookups reuse the
cached files. Bundle URLs can optionally declare `compression: gzip` and
`sha256`; the checksum is verified over the downloaded bytes before the
decompressed canonical bundle is cached. Sharded manifests can also mark an
individual shard with `"compression":"gzip"`; the shard checksum covers the
compressed mirror bytes, and the cache stores the decompressed signed shard.

```yaml
hashdb:
  mode: lookup
  sources:
    - name: mirror-bundle
      type: bundle
      url: https://example.com/hashdb/shared.bundle.json.gz
      compression: gzip
      sha256: "<hex sha256 of downloaded .gz bytes>"
      cache_dir: ./hashdb/cache
      public_key: "<hex ed25519 public key>"
    - name: mirror-shards
      type: sharded
      manifest_url: https://example.com/hashdb/manifest.json
      cache_dir: ./hashdb/cache
      public_key: "<hex ed25519 public key>"
```

#### Contribute successful extractions to a private local sharded source

```yaml
hashdb:
  mode: lookup
  contribute: ask              # ask before each local contribution; use auto for silent opt-in
  contribution:
    type: sharded             # or "bundle"
    base_dir: ./hashdb/private
    key_path: ./hashdb/private/signing.key.json
    source: my-private-source
    shard_prefix_length: 2
```

Contribution is opt-in. `off` is the default. `ask` shows a confirmation dialog
before appending each successful non-empty password to the configured local
bundle/sharded sink; cancel/skip leaves HashDB untouched while normal SQLite
learning still succeeds. `auto` is advanced opt-in and appends silently. Bundle
and shard files only contain encrypted records; the plaintext password never
appears on disk in these files. Use
`smart-extract.exe --hashdb-public-key ./hashdb/private/signing.key.json` to
print the hex public key to paste into a matching `hashdb.sources[].public_key`
entry.

To avoid manual YAML edits, add the local contribution target back as a lookup
source with one of these commands. They enable `hashdb.mode: lookup`, load or
create the signing key, and upsert `hashdb.sources[]` by source name:

```powershell
smart-extract.exe --hashdb-add-sharded-source my-private-source ./hashdb/private ./hashdb/private/signing.key.json
smart-extract.exe --hashdb-add-bundle-source my-private-bundle ./hashdb/private.bundle.json ./hashdb/private/signing.key.json
```

Inspect configured sources and manage the per-source HTTP cache without
editing `config.yaml` by hand:

```powershell
smart-extract.exe --hashdb-list-sources
smart-extract.exe --hashdb-disable-source mirror-bundle
smart-extract.exe --hashdb-enable-source mirror-bundle
smart-extract.exe --hashdb-clear-cache mirror-bundle
smart-extract.exe --hashdb-clear-cache --all
smart-extract.exe --hashdb-verify-source mirror-bundle
smart-extract.exe --hashdb-verify-source --all
```

`--hashdb-list-sources` prints each source's name, type, location and (for
HTTP sources) the resolved cache directory plus whether it exists.
`--hashdb-disable-source <name>` and `--hashdb-enable-source <name>` flip the
configured source's `disabled` flag without changing ordering or other fields.
`--hashdb-clear-cache <name>` removes the cache root of a single HTTP source;
`--all` removes every HTTP source cache root (duplicates are removed once).
Local bundle/sharded sources have no cache to clear and the named form
rejects them with an explicit error.
`--hashdb-verify-source <name>` performs an offline structural and signature
check against one configured source; `--all` checks every source in order.
Local bundle/sharded sources are read from disk and signed-bundle/manifest
integrity is verified; HTTP sources verify only the existing cached bundle
or manifest+shards without downloading, reporting `missing_cache` when no
cache is present. The named form exits non-zero on any failure; `--all`
exits non-zero if any source reports `error` or `missing_cache`.

### Debug logs

For dogfooding and bug reports, run an extraction with a diagnostic log:

```powershell
smart-extract.exe --debug-log .\smart-extract-debug.log .\archive.zip
```

The log records high-level extraction progress, candidate counts by source
(`exact`, `hashdb`, `filename`, `session`, `pattern`, `dictionary`, `fallback`,
etc.), active/disabled HashDB source lookups, cache/download errors surfaced by
those lookups, and success/failure markers. It intentionally logs counts and
source labels rather than plaintext password values; filename-style password
hints such as `password=...` / `pwd-...` / `密码...` are redacted in log lines.

For a safer dry-run style diagnosis that does not extract, prompt, learn,
contribute, or delete files, use:

```powershell
smart-extract.exe --doctor
smart-extract.exe --explain .\archive.zip
```

`--doctor` checks config loading, 7-Zip detection, local learning store access,
and configured HashDB source/cache status without downloading HTTP mirrors.
`--explain` prints the budget profile, candidate limit, total candidate count,
candidate counts by source, and configured HashDB source status. It follows the
same top-level candidate construction path as extraction, including optional
HashDB lookup when `hashdb.mode: lookup` is configured, but it never prints raw
candidate password values.

### Local learning store

- `learning.db` (SQLite, next to the exe) is the authoritative local
  learning store: exact cache, raw observations, pattern rules, session
  context, and the local password dictionary.
- `learned.yaml` is legacy. If present, it is migrated into `learning.db`
  on first run and is no longer the source of truth.

## Requirements

- Windows 10/11
- [7-Zip](https://www.7-zip.org/) installed (auto-detected in Program Files or PATH)
- Administrator rights for `--install`/`--uninstall`
