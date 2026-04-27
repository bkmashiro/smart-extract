package config

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// setupTestDir creates a temporary directory and initializes config paths.
// Returns the temp dir path and a cleanup function.
func setupTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// Reset cached state
	mu.Lock()
	cfg = nil
	learned = nil
	mu.Unlock()
	Init(dir)
	return dir
}

func TestPreferences_DefaultUnset(t *testing.T) {
	setupTestDir(t)

	l, err := LoadLearned()
	if err != nil {
		t.Fatalf("LoadLearned failed: %v", err)
	}
	if l.Preferences.DeletePreferenceSet {
		t.Error("expected DeletePreferenceSet to be false by default")
	}
	if l.Preferences.DeleteAfterExtract {
		t.Error("expected DeleteAfterExtract to be false by default")
	}
}

func TestSaveDeletePreference_True(t *testing.T) {
	dir := setupTestDir(t)

	err := SaveDeletePreference(true)
	if err != nil {
		t.Fatalf("SaveDeletePreference(true) failed: %v", err)
	}

	// Reset cache and reload from disk
	ReloadAll()
	l, err := LoadLearned()
	if err != nil {
		t.Fatalf("LoadLearned failed: %v", err)
	}

	if !l.Preferences.DeletePreferenceSet {
		t.Error("expected DeletePreferenceSet to be true after saving")
	}
	if !l.Preferences.DeleteAfterExtract {
		t.Error("expected DeleteAfterExtract to be true after saving true")
	}

	// Verify the YAML file on disk
	data, err := os.ReadFile(filepath.Join(dir, "learned.yaml"))
	if err != nil {
		t.Fatalf("reading learned.yaml: %v", err)
	}
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		t.Fatalf("parsing learned.yaml: %v", err)
	}
	prefs, ok := raw["preferences"].(map[string]interface{})
	if !ok {
		t.Fatalf("preferences key not found or wrong type in learned.yaml")
	}
	if prefs["delete_after_extract"] != true {
		t.Errorf("expected delete_after_extract=true in YAML, got %v", prefs["delete_after_extract"])
	}
	if prefs["delete_preference_set"] != true {
		t.Errorf("expected delete_preference_set=true in YAML, got %v", prefs["delete_preference_set"])
	}
}

func TestSaveDeletePreference_False(t *testing.T) {
	setupTestDir(t)

	err := SaveDeletePreference(false)
	if err != nil {
		t.Fatalf("SaveDeletePreference(false) failed: %v", err)
	}

	ReloadAll()
	l, err := LoadLearned()
	if err != nil {
		t.Fatalf("LoadLearned failed: %v", err)
	}

	if !l.Preferences.DeletePreferenceSet {
		t.Error("expected DeletePreferenceSet to be true after saving")
	}
	if l.Preferences.DeleteAfterExtract {
		t.Error("expected DeleteAfterExtract to be false after saving false")
	}
}

func TestResetPreferences(t *testing.T) {
	setupTestDir(t)

	// Set a preference first
	if err := SaveDeletePreference(true); err != nil {
		t.Fatalf("SaveDeletePreference failed: %v", err)
	}

	// Verify it was set
	ReloadAll()
	l, err := LoadLearned()
	if err != nil {
		t.Fatalf("LoadLearned failed: %v", err)
	}
	if !l.Preferences.DeletePreferenceSet {
		t.Fatal("preference should be set before reset")
	}

	// Reset
	ReloadAll()
	if err := ResetPreferences(); err != nil {
		t.Fatalf("ResetPreferences failed: %v", err)
	}

	// Verify it was cleared
	ReloadAll()
	l, err = LoadLearned()
	if err != nil {
		t.Fatalf("LoadLearned failed: %v", err)
	}
	if l.Preferences.DeletePreferenceSet {
		t.Error("expected DeletePreferenceSet to be false after reset")
	}
	if l.Preferences.DeleteAfterExtract {
		t.Error("expected DeleteAfterExtract to be false after reset")
	}
}

func TestPreferenceStateMachine(t *testing.T) {
	// Tests the full state machine:
	// 1. Initial state: preference not set
	// 2. After first dialog: preference saved
	// 3. Subsequent calls: no dialog needed, use saved preference
	// 4. After reset: back to initial state

	setupTestDir(t)

	// State 1: unset
	l, _ := LoadLearned()
	if l.Preferences.DeletePreferenceSet {
		t.Error("state 1: should be unset")
	}

	// State 2: simulate dialog -> user says "yes, delete"
	ReloadAll()
	SaveDeletePreference(true)

	// State 3: on subsequent extraction, preference is already set
	ReloadAll()
	l, _ = LoadLearned()
	if !l.Preferences.DeletePreferenceSet {
		t.Error("state 3: should be set")
	}
	if !l.Preferences.DeleteAfterExtract {
		t.Error("state 3: should be true (delete)")
	}

	// State 4: reset via --reset-prefs
	ReloadAll()
	ResetPreferences()

	ReloadAll()
	l, _ = LoadLearned()
	if l.Preferences.DeletePreferenceSet {
		t.Error("state 4: should be unset after reset")
	}
}

func TestPreferences_PreservesOtherData(t *testing.T) {
	// Ensure saving preferences doesn't wipe out other learned data
	setupTestDir(t)

	// Save some exact cache data first
	if err := SaveExactCache("test.zip", "mypassword"); err != nil {
		t.Fatalf("SaveExactCache failed: %v", err)
	}

	// Now save a preference
	ReloadAll()
	if err := SaveDeletePreference(true); err != nil {
		t.Fatalf("SaveDeletePreference failed: %v", err)
	}

	// Verify exact cache is preserved
	ReloadAll()
	l, err := LoadLearned()
	if err != nil {
		t.Fatalf("LoadLearned failed: %v", err)
	}
	if l.Exact["test.zip"] != "mypassword" {
		t.Errorf("exact cache was lost: got %q", l.Exact["test.zip"])
	}
	if !l.Preferences.DeleteAfterExtract {
		t.Error("preference was not saved")
	}
}
