package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/bkmashiro/smart-extract/internal/config"
	"github.com/bkmashiro/smart-extract/internal/extractor"
)

// doctorResult is the deterministic, password-redacted summary that backs
// both the text and JSON doctor reports. Each subsystem reports its own
// status independently so a partial failure (e.g. missing 7z) does not
// suppress the rest.
type doctorResult struct {
	Command        string         `json:"command"`
	Config         doctorStatus   `json:"config"`
	SevenZip       doctorSevenZip `json:"sevenzip"`
	LegacyLearning doctorStatus   `json:"legacy_learning"`
	LearningStore  doctorLearning `json:"learning_store"`
	HashDB         doctorHashDB   `json:"hashdb"`
}

type doctorStatus struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type doctorSevenZip struct {
	Status string `json:"status"`
	Path   string `json:"path,omitempty"`
	Error  string `json:"error,omitempty"`
}

type doctorLearning struct {
	Status string `json:"status"`
	Path   string `json:"path,omitempty"`
	Error  string `json:"error,omitempty"`
}

type doctorHashDB struct {
	Mode       string               `json:"mode"`
	Configured int                  `json:"configured"`
	Active     int                  `json:"active"`
	Disabled   int                  `json:"disabled"`
	Sources    []doctorHashDBSource `json:"sources"`
	Error      string               `json:"error,omitempty"`
}

type doctorHashDBSource struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	State       string `json:"state"`
	Location    string `json:"location,omitempty"`
	CachePath   string `json:"cache_path,omitempty"`
	CacheExists bool   `json:"cache_exists"`
}

// Doctor prints a safe environment/configuration diagnostic report. It does not
// extract archives, prompt for passwords, download HashDB HTTP sources, write
// learning observations, or append HashDB contributions.
func Doctor(w io.Writer) error {
	if w == nil {
		w = io.Discard
	}
	result, cfgErr := buildDoctorResult()
	writeDoctorText(result, w)
	if cfgErr != nil {
		return cfgErr
	}
	return nil
}

// DoctorJSON writes the same diagnostic data as Doctor in a deterministic,
// indented JSON form suitable for bug reports and automation. It enforces
// the same safety contract: no extraction, prompting, HTTP downloads,
// learning, or contribution. Source names, paths, and error strings are
// password-redacted.
func DoctorJSON(w io.Writer) error {
	if w == nil {
		w = io.Discard
	}
	result, cfgErr := buildDoctorResult()
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if encErr := enc.Encode(result); encErr != nil {
		return encErr
	}
	if cfgErr != nil {
		return cfgErr
	}
	return nil
}

// buildDoctorResult performs all read-only checks and returns the populated
// result plus an optional fatal error (currently only a config-load failure).
// Even when cfgErr is non-nil the result is partially populated so callers
// can still emit a meaningful report.
func buildDoctorResult() (doctorResult, error) {
	result := doctorResult{Command: "doctor"}

	cfg, err := config.LoadConfig()
	if err != nil {
		result.Config = doctorStatus{Status: "error", Error: sanitizeDebugLine(err.Error())}
		return result, fmt.Errorf("加载配置失败: %w", err)
	}
	result.Config = doctorStatus{Status: "ok"}

	if path, err := extractor.FindSevenZip(cfg.SevenZipPath); err != nil {
		result.SevenZip = doctorSevenZip{Status: "error", Error: sanitizeDebugLine(err.Error())}
	} else {
		result.SevenZip = doctorSevenZip{Status: "ok", Path: sanitizeDebugLine(path)}
	}

	learned, err := config.LoadLearned()
	if err != nil {
		result.LegacyLearning = doctorStatus{Status: "error", Error: sanitizeDebugLine(err.Error())}
		learned = &config.Learned{}
	} else {
		result.LegacyLearning = doctorStatus{Status: "ok"}
	}
	storePath := sanitizeDebugLine(config.LearningStorePath())
	if st, err := openLearningStore(learned); err != nil {
		result.LearningStore = doctorLearning{Status: "error", Path: storePath, Error: sanitizeDebugLine(err.Error())}
	} else {
		_ = st.Close()
		result.LearningStore = doctorLearning{Status: "ok", Path: storePath}
	}

	summaries, err := HashDBListSources()
	if err != nil {
		result.HashDB = doctorHashDB{
			Mode:    normalizedDoctorHashDBMode(cfg.HashDB.Mode),
			Error:   sanitizeDebugLine(err.Error()),
			Sources: []doctorHashDBSource{},
		}
		return result, nil
	}
	active, disabled := 0, 0
	sources := make([]doctorHashDBSource, 0, len(summaries))
	for _, src := range summaries {
		state := "active"
		if src.Disabled {
			disabled++
			state = "disabled"
		} else {
			active++
		}
		entry := doctorHashDBSource{
			Name:        sanitizeDebugLine(src.Name),
			Type:        sanitizeDebugLine(src.Type),
			State:       state,
			Location:    sanitizeDebugLine(src.Location),
			CachePath:   sanitizeDebugLine(src.CachePath),
			CacheExists: src.CacheExists,
		}
		sources = append(sources, entry)
	}
	result.HashDB = doctorHashDB{
		Mode:       normalizedDoctorHashDBMode(cfg.HashDB.Mode),
		Configured: len(summaries),
		Active:     active,
		Disabled:   disabled,
		Sources:    sources,
	}
	return result, nil
}

func writeDoctorText(r doctorResult, w io.Writer) {
	fmt.Fprintln(w, "Smart Extract doctor")
	if r.Config.Status == "error" {
		fmt.Fprintf(w, "config: error %s\n", r.Config.Error)
		return
	}
	fmt.Fprintln(w, "config: ok")

	if r.SevenZip.Status == "error" {
		fmt.Fprintf(w, "7zip: error %s\n", r.SevenZip.Error)
	} else {
		fmt.Fprintf(w, "7zip: ok %s\n", r.SevenZip.Path)
	}

	if r.LegacyLearning.Status == "error" {
		fmt.Fprintf(w, "legacy_learning: error %s\n", r.LegacyLearning.Error)
	} else {
		fmt.Fprintln(w, "legacy_learning: ok")
	}
	if r.LearningStore.Status == "error" {
		fmt.Fprintf(w, "learning_store: error path=%s err=%s\n", r.LearningStore.Path, r.LearningStore.Error)
	} else {
		fmt.Fprintf(w, "learning_store: ok path=%s\n", r.LearningStore.Path)
	}

	if r.HashDB.Error != "" {
		fmt.Fprintf(w, "hashdb: error %s\n", r.HashDB.Error)
		return
	}
	fmt.Fprintf(w, "hashdb: mode=%s configured=%d active=%d disabled=%d\n",
		r.HashDB.Mode, r.HashDB.Configured, r.HashDB.Active, r.HashDB.Disabled)
	for _, src := range r.HashDB.Sources {
		fmt.Fprintf(w, "  - %s type=%s state=%s\n", src.Name, src.Type, src.State)
		if src.Location != "" {
			fmt.Fprintf(w, "    location: %s\n", src.Location)
		}
		if src.CachePath != "" {
			cacheState := "missing"
			if src.CacheExists {
				cacheState = "present"
			}
			fmt.Fprintf(w, "    cache: %s (%s)\n", src.CachePath, cacheState)
		}
	}
}

func normalizedDoctorHashDBMode(mode string) string {
	if strings.EqualFold(strings.TrimSpace(mode), "lookup") {
		return "lookup"
	}
	return "off"
}
