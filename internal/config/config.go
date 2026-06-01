package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"
)

// Config represents config.yaml
type Config struct {
	SevenZipPath       string             `yaml:"sevenzip_path"`
	BandizipPath       string             `yaml:"bandizip_path,omitempty"`
	MaxParallelProbes  int                `yaml:"max_parallel_probes,omitempty"`
	ProbeBudgetProfile string             `yaml:"probe_budget_profile,omitempty"`
	People             map[string]*Person `yaml:"people"`
	FallbackPasswords  []string           `yaml:"fallback_passwords"`
}

// Person represents a person's profile in config.yaml
type Person struct {
	Patterns  []string `yaml:"patterns"`
	MatchMode string   `yaml:"match_mode"` // "pattern" or "always_try"
	Priority  int      `yaml:"priority"`
	Passwords []string `yaml:"passwords"`
}

// Preferences stores user preferences in learned.yaml
type Preferences struct {
	DeleteAfterExtract  bool `yaml:"delete_after_extract"`
	DeletePreferenceSet bool `yaml:"delete_preference_set"`
}

// Learned represents learned.yaml
type Learned struct {
	Exact            map[string]string                `yaml:"exact"`
	PersonStats      map[string]map[string]*BetaStats `yaml:"person_stats"`
	PersonFilenames  map[string][]string              `yaml:"person_filenames"`
	PasswordHitCount map[string]int                   `yaml:"password_hit_count,omitempty"`
	Preferences      Preferences                      `yaml:"preferences"`
}

// BetaStats stores Thompson Sampling parameters
type BetaStats struct {
	Alpha float64 `yaml:"alpha"`
	Beta  float64 `yaml:"beta"`
}

var (
	mu          sync.Mutex
	configPath  string
	learnedPath string
	cfg         *Config
	learned     *Learned
)

// Init sets the base directory (next to the exe)
func Init(baseDir string) {
	configPath = filepath.Join(baseDir, "config.yaml")
	learnedPath = filepath.Join(baseDir, "learned.yaml")
}

// LearningStorePath returns the SQLite learning database path next to learned.yaml.
func LearningStorePath() string {
	baseDir := filepath.Dir(learnedPath)
	if baseDir == "." || baseDir == "" {
		baseDir = "."
	}
	return filepath.Join(baseDir, "learning.db")
}

// LoadConfig loads config.yaml, creating defaults if missing
func LoadConfig() (*Config, error) {
	mu.Lock()
	defer mu.Unlock()

	if cfg != nil {
		return cfg, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			cfg = defaultConfig()
			return cfg, nil
		}
		return nil, fmt.Errorf("reading config.yaml: %w", err)
	}

	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		// If YAML is corrupted (e.g. concurrent write from another process),
		// use defaults rather than failing the entire extraction.
		fmt.Fprintf(os.Stderr, "警告：config.yaml 解析失败，使用默认配置: %v\n", err)
		cfg = defaultConfig()
		return cfg, nil
	}
	if c.People == nil {
		c.People = make(map[string]*Person)
	}
	cfg = &c
	return cfg, nil
}

// SaveConfig writes config.yaml
func SaveConfig(c *Config) error {
	mu.Lock()
	defer mu.Unlock()

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("writing config.yaml: %w", err)
	}
	cfg = c
	return nil
}

// LoadLearned loads learned.yaml, creating empty if missing
func LoadLearned() (*Learned, error) {
	mu.Lock()
	defer mu.Unlock()

	if learned != nil {
		return learned, nil
	}

	data, err := os.ReadFile(learnedPath)
	if err != nil {
		if os.IsNotExist(err) {
			learned = emptyLearned()
			return learned, nil
		}
		return nil, fmt.Errorf("reading learned.yaml: %w", err)
	}

	// If the file is empty or contains only whitespace (e.g. truncated by
	// a concurrent write from another process), treat as empty.
	if len(bytes.TrimSpace(data)) == 0 {
		learned = emptyLearned()
		return learned, nil
	}

	var l Learned
	if err := yaml.Unmarshal(data, &l); err != nil {
		// YAML corrupted — likely another process was writing at the same
		// time.  Use empty defaults so extraction can proceed.
		fmt.Fprintf(os.Stderr, "警告：learned.yaml 解析失败，使用空数据: %v\n", err)
		learned = emptyLearned()
		return learned, nil
	}
	if l.Exact == nil {
		l.Exact = make(map[string]string)
	}
	if l.PersonStats == nil {
		l.PersonStats = make(map[string]map[string]*BetaStats)
	}
	if l.PersonFilenames == nil {
		l.PersonFilenames = make(map[string][]string)
	}
	if l.PasswordHitCount == nil {
		l.PasswordHitCount = make(map[string]int)
	}
	learned = &l
	return learned, nil
}

// SaveLearned writes learned.yaml using atomic write (temp file + rename)
// to avoid corruption when multiple processes save concurrently.
func SaveLearned(l *Learned) error {
	mu.Lock()
	defer mu.Unlock()

	data, err := yaml.Marshal(l)
	if err != nil {
		return fmt.Errorf("marshaling learned: %w", err)
	}

	// Write to a temp file first, then rename for atomicity.
	tmpPath := learnedPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("writing learned.yaml.tmp: %w", err)
	}
	if err := os.Rename(tmpPath, learnedPath); err != nil {
		// Rename can fail on some Windows configurations; fall back to
		// direct write.
		if err2 := os.WriteFile(learnedPath, data, 0644); err2 != nil {
			return fmt.Errorf("writing learned.yaml: %w", err2)
		}
	}

	learned = l
	return nil
}

// ReloadAll clears cached configs so they reload from disk
func ReloadAll() {
	mu.Lock()
	defer mu.Unlock()
	cfg = nil
	learned = nil
}

func defaultConfig() *Config {
	return &Config{
		SevenZipPath: "",
		People:       make(map[string]*Person),
		FallbackPasswords: []string{
			"123456",
			"password",
			"",
		},
	}
}

func emptyLearned() *Learned {
	return &Learned{
		Exact:            make(map[string]string),
		PersonStats:      make(map[string]map[string]*BetaStats),
		PersonFilenames:  make(map[string][]string),
		PasswordHitCount: make(map[string]int),
	}
}

// GetOrCreateStats returns the BetaStats for a (person, password) pair, creating if missing
func GetOrCreateStats(l *Learned, person, password string) *BetaStats {
	if l.PersonStats[person] == nil {
		l.PersonStats[person] = make(map[string]*BetaStats)
	}
	if l.PersonStats[person][password] == nil {
		l.PersonStats[person][password] = &BetaStats{Alpha: 1, Beta: 1}
	}
	return l.PersonStats[person][password]
}

// RecordSuccess increments alpha for (person, password)
func RecordSuccess(person, password string) error {
	l, err := LoadLearned()
	if err != nil {
		return err
	}
	stats := GetOrCreateStats(l, person, password)
	stats.Alpha++
	return SaveLearned(l)
}

// RecordFailure increments beta for (person, password)
func RecordFailure(person, password string) error {
	l, err := LoadLearned()
	if err != nil {
		return err
	}
	stats := GetOrCreateStats(l, person, password)
	stats.Beta++
	return SaveLearned(l)
}

// AddPersonFilename adds a filename to a person's known filenames
func AddPersonFilename(person, filename string) error {
	l, err := LoadLearned()
	if err != nil {
		return err
	}
	for _, f := range l.PersonFilenames[person] {
		if f == filename {
			return nil
		}
	}
	l.PersonFilenames[person] = append(l.PersonFilenames[person], filename)
	return SaveLearned(l)
}

// AddPersonPassword adds a password to a person's list in config.yaml if not already there
func AddPersonPassword(personName, password string) error {
	c, err := LoadConfig()
	if err != nil {
		return err
	}
	p, ok := c.People[personName]
	if !ok {
		return fmt.Errorf("person %q not found", personName)
	}
	for _, pw := range p.Passwords {
		if pw == password {
			return nil
		}
	}
	p.Passwords = append(p.Passwords, password)
	return SaveConfig(c)
}

// AddPerson creates a new person entry in config.yaml
func AddPerson(name string, patterns []string, passwords []string, matchMode string) error {
	c, err := LoadConfig()
	if err != nil {
		return err
	}
	if c.People == nil {
		c.People = make(map[string]*Person)
	}
	c.People[name] = &Person{
		Patterns:  patterns,
		MatchMode: matchMode,
		Priority:  len(c.People),
		Passwords: passwords,
	}
	return SaveConfig(c)
}

// SaveDeletePreference saves the user's delete-after-extract preference
func SaveDeletePreference(deleteAfterExtract bool) error {
	l, err := LoadLearned()
	if err != nil {
		return err
	}
	l.Preferences.DeleteAfterExtract = deleteAfterExtract
	l.Preferences.DeletePreferenceSet = true
	return SaveLearned(l)
}

// ResetPreferences clears the preferences so dialogs show again next time
func ResetPreferences() error {
	l, err := LoadLearned()
	if err != nil {
		return err
	}
	l.Preferences = Preferences{}
	return SaveLearned(l)
}

// SaveExactCache saves a filename→password mapping
func SaveExactCache(filename, password string) error {
	l, err := LoadLearned()
	if err != nil {
		return err
	}
	l.Exact[filename] = password
	return SaveLearned(l)
}

// FindPersonByPassword scans config.yaml people passwords AND learned.yaml
// person_stats to find a person who has used this exact password.
// Returns "" if no person is found.
func FindPersonByPassword(password string) string {
	c, err := LoadConfig()
	if err != nil {
		return ""
	}
	// Check config.yaml people passwords
	for name, person := range c.People {
		for _, pw := range person.Passwords {
			if pw == password {
				return name
			}
		}
	}
	// Check learned.yaml person_stats (passwords learned through usage)
	l, err := LoadLearned()
	if err != nil {
		return ""
	}
	for personName, stats := range l.PersonStats {
		if _, ok := stats[password]; ok {
			return personName
		}
	}
	return ""
}

// IncrementPasswordHitCount increments the hit counter for a password in learned.yaml
// and returns the new count.
func IncrementPasswordHitCount(password string) (int, error) {
	l, err := LoadLearned()
	if err != nil {
		return 0, err
	}
	if l.PasswordHitCount == nil {
		l.PasswordHitCount = make(map[string]int)
	}
	l.PasswordHitCount[password]++
	count := l.PasswordHitCount[password]
	return count, SaveLearned(l)
}

// GetPasswordHitCount returns the current hit count for a password.
func GetPasswordHitCount(password string) int {
	l, err := LoadLearned()
	if err != nil {
		return 0
	}
	if l.PasswordHitCount == nil {
		return 0
	}
	return l.PasswordHitCount[password]
}

// ClearPasswordHitCount removes the hit counter for a password (after it's assigned to a person).
func ClearPasswordHitCount(password string) error {
	l, err := LoadLearned()
	if err != nil {
		return err
	}
	if l.PasswordHitCount != nil {
		delete(l.PasswordHitCount, password)
	}
	return SaveLearned(l)
}
