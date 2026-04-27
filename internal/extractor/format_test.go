package extractor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsZipMagic(t *testing.T) {
	tests := []struct {
		name  string
		magic []byte
		want  bool
	}{
		{"valid zip", []byte{'P', 'K', 0x03, 0x04, 0, 0}, true},
		{"too short", []byte{'P', 'K'}, false},
		{"wrong magic", []byte{'R', 'a', 'r', '!'}, false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isZipMagic(tt.magic); got != tt.want {
				t.Errorf("isZipMagic() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsRarMagic(t *testing.T) {
	tests := []struct {
		name  string
		magic []byte
		want  bool
	}{
		{"valid rar", []byte{'R', 'a', 'r', '!', 0x1a, 0x07, 0x00}, true},
		{"too short", []byte{'R', 'a', 'r'}, false},
		{"wrong magic", []byte{'P', 'K', 0x03, 0x04, 0, 0}, false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRarMagic(tt.magic); got != tt.want {
				t.Errorf("isRarMagic() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIs7zMagic(t *testing.T) {
	tests := []struct {
		name  string
		magic []byte
		want  bool
	}{
		{"valid 7z", []byte{'7', 'z', 0xbc, 0xaf, 0x27, 0x1c, 0, 0}, true},
		{"too short", []byte{'7', 'z'}, false},
		{"wrong magic", []byte{'P', 'K', 0x03, 0x04, 0, 0}, false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := is7zMagic(tt.magic); got != tt.want {
				t.Errorf("is7zMagic() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetectFormat_ByExtension(t *testing.T) {
	// Create temp files with specific extensions (no magic bytes)
	dir := t.TempDir()

	tests := []struct {
		filename string
		wantFmt  string
		wantStrt ProbeStrategy
	}{
		{"test.zip", "zip", ProbeParallel},
		{"test.rar", "rar", ProbeParallel},
		{"test.7z", "7z", ProbeParallel}, // no 7z binary, can't detect solid
		{"test.tar.gz", "tar-compressed", ProbeSerial},
		{"test.tar.bz2", "tar-compressed", ProbeSerial},
		{"test.tar.xz", "tar-compressed", ProbeSerial},
		{"test.gz", "tar-compressed", ProbeSerial},
		{"test.unknown", "unknown", ProbeSerial},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			path := filepath.Join(dir, tt.filename)
			os.WriteFile(path, []byte("dummy content"), 0644)

			af := DetectFormat(path, "")
			if af.Format != tt.wantFmt {
				t.Errorf("format = %q, want %q", af.Format, tt.wantFmt)
			}
			if af.Strategy != tt.wantStrt {
				t.Errorf("strategy = %v, want %v", af.Strategy, tt.wantStrt)
			}
		})
	}
}

func TestDetectFormat_ByMagic(t *testing.T) {
	dir := t.TempDir()

	// Create a file with ZIP magic but .dat extension
	path := filepath.Join(dir, "test.dat")
	data := []byte{'P', 'K', 0x03, 0x04, 0, 0, 0, 0}
	os.WriteFile(path, data, 0644)

	// Unknown extension but ZIP magic — falls to "unknown" since we match extension first
	// Actually, .dat won't match any known extension, so it hits default → unknown
	af := DetectFormat(path, "")
	// The switch checks magic OR ext, so isZipMagic will match
	if af.Format != "zip" {
		t.Errorf("expected zip from magic bytes, got %q", af.Format)
	}
	if af.Strategy != ProbeParallel {
		t.Errorf("expected parallel, got %v", af.Strategy)
	}
}

func TestDetectFormat_MultiPart(t *testing.T) {
	dir := t.TempDir()

	path := filepath.Join(dir, "test.zip.001")
	os.WriteFile(path, []byte("dummy"), 0644)

	af := DetectFormat(path, "")
	if af.Format != "zip" {
		t.Errorf("expected zip for .zip.001, got %q", af.Format)
	}
}

func TestProbeStrategyString(t *testing.T) {
	if ProbeParallel.String() != "parallel" {
		t.Errorf("expected 'parallel', got %q", ProbeParallel.String())
	}
	if ProbeSerial.String() != "serial" {
		t.Errorf("expected 'serial', got %q", ProbeSerial.String())
	}
}
