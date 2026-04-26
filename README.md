# smart-extract (智能解压)

A Windows tool that adds a right-click context menu entry to intelligently extract password-protected archives.

## Features

- Right-click any `.zip`, `.rar`, `.7z`, `.tar.gz`, etc. → "智能解压" menu
- Multi-select files supported (Windows calls the exe once per file, in parallel)
- Smart password system with 3-tier priority:
  1. **Exact cache** (`learned.yaml`): remembers specific filenames → passwords
  2. **Person profiles** (`config.yaml`): pattern/regex matching per person, Thompson Sampling ordering
  3. **Fallback list** (`config.yaml`): global password list
- Recursive extraction (nested archives)
- Automatic single-folder flattening (e.g., `output/output/files` → `output/files`)
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
smart-extract.exe <archive>     Extract an archive (called by Explorer)
```

## Configuration

### config.yaml

```yaml
sevenzip_path: ""  # auto-detected if empty

people:
  alice:
    patterns: ["alice_\\d+", "ALI"]
    match_mode: pattern   # "pattern" or "always_try"
    priority: 0
    passwords: ["alice123", "alice2024"]

fallback_passwords:
  - "123456"
  - ""
```

### learned.yaml (auto-managed)

```yaml
exact:
  "secretfile.zip": "pass123"

person_stats:
  alice:
    "alice123": {alpha: 14, beta: 1}

person_filenames:
  alice:
    - "alice_2024_01"
```

## Requirements

- Windows 10/11
- [7-Zip](https://www.7-zip.org/) installed (auto-detected in Program Files or PATH)
- Administrator rights for `--install`/`--uninstall`
