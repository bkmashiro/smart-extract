package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"
)

// Config represents config.yaml
type Config struct {
	SevenZipPath      string             `yaml:"sevenzip_path"`
	MaxParallelProbes int                `yaml:"max_parallel_probes,omitempty"`
	People            map[string]*Person `yaml:"people"`
	FallbackPasswords []string           `yaml:"fallback_passwords"`
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
	Exact           map[string]string                     `yaml:"exact"`
	PersonStats     map[string]map[string]*BetaStats      `yaml:"person_stats"`
	PersonFilenames map[string][]string                   `yaml:"person_filenames"`
	Preferences     Preferences                           `yaml:"preferences"`
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
		return nil, fmt.Errorf("parsing config.yaml: %w", err)
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

	var l Learned
	if err := yaml.Unmarshal(data, &l); err != nil {
		return nil, fmt.Errorf("parsing learned.yaml: %w", err)
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
	learned = &l
	return learned, nil
}

// SaveLearned writes learned.yaml
func SaveLearned(l *Learned) error {
	mu.Lock()
	defer mu.Unlock()

	data, err := yaml.Marshal(l)
	if err != nil {
		return fmt.Errorf("marshaling learned: %w", err)
	}
	if err := os.WriteFile(learnedPath, data, 0644); err != nil {
		return fmt.Errorf("writing learned.yaml: %w", err)
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
		Exact:           make(map[string]string),
		PersonStats:     make(map[string]map[string]*BetaStats),
		PersonFilenames: make(map[string][]string),
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
