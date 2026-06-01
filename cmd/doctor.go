package cmd

import (
	"fmt"
	"io"
	"strings"

	"github.com/bkmashiro/smart-extract/internal/config"
	"github.com/bkmashiro/smart-extract/internal/extractor"
)

// Doctor prints a safe environment/configuration diagnostic report. It does not
// extract archives, prompt for passwords, download HashDB HTTP sources, write
// learning observations, or append HashDB contributions.
func Doctor(w io.Writer) error {
	if w == nil {
		w = io.Discard
	}
	fmt.Fprintln(w, "Smart Extract doctor")

	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Fprintf(w, "config: error %v\n", err)
		return fmt.Errorf("加载配置失败: %w", err)
	}
	fmt.Fprintln(w, "config: ok")

	if path, err := extractor.FindSevenZip(cfg.SevenZipPath); err != nil {
		fmt.Fprintf(w, "7zip: error %v\n", err)
	} else {
		fmt.Fprintf(w, "7zip: ok %s\n", sanitizeDebugLine(path))
	}

	learned, err := config.LoadLearned()
	if err != nil {
		fmt.Fprintf(w, "legacy_learning: error %v\n", err)
		learned = &config.Learned{}
	} else {
		fmt.Fprintln(w, "legacy_learning: ok")
	}
	if st, err := openLearningStore(learned); err != nil {
		fmt.Fprintf(w, "learning_store: error path=%s err=%v\n", sanitizeDebugLine(config.LearningStorePath()), err)
	} else {
		_ = st.Close()
		fmt.Fprintf(w, "learning_store: ok path=%s\n", sanitizeDebugLine(config.LearningStorePath()))
	}

	summaries, err := HashDBListSources()
	if err != nil {
		fmt.Fprintf(w, "hashdb: error %v\n", err)
		return nil
	}
	active, disabled := 0, 0
	for _, src := range summaries {
		if src.Disabled {
			disabled++
		} else {
			active++
		}
	}
	fmt.Fprintf(w, "hashdb: mode=%s configured=%d active=%d disabled=%d\n", normalizedDoctorHashDBMode(cfg.HashDB.Mode), len(summaries), active, disabled)
	for _, src := range summaries {
		state := "active"
		if src.Disabled {
			state = "disabled"
		}
		fmt.Fprintf(w, "  - %s type=%s state=%s\n", sanitizeDebugLine(src.Name), sanitizeDebugLine(src.Type), state)
		if src.Location != "" {
			fmt.Fprintf(w, "    location: %s\n", sanitizeDebugLine(src.Location))
		}
		if src.CachePath != "" {
			cacheState := "missing"
			if src.CacheExists {
				cacheState = "present"
			}
			fmt.Fprintf(w, "    cache: %s (%s)\n", sanitizeDebugLine(src.CachePath), cacheState)
		}
	}
	return nil
}

func normalizedDoctorHashDBMode(mode string) string {
	if strings.EqualFold(strings.TrimSpace(mode), "lookup") {
		return "lookup"
	}
	return "off"
}
