//go:build !windows

package ui

import "fmt"

// AllocConsole is a no-op on non-Windows platforms
func AllocConsole() {}

// WaitForKeypress prints message and waits for input on non-Windows
func WaitForKeypress(msg string) {
	if msg == "" {
		msg = "Press Enter to close..."
	}
	fmt.Println(msg)
	var buf [1]byte
	fmt.Scanf("%c", &buf[0])
}

// AskPassword stub for non-Windows
func AskPassword(archiveName string) (string, error) {
	return "", fmt.Errorf("not supported on this platform")
}

// DialogResult holds the result of the password dialog
type DialogResult struct {
	Password   string
	Action     string
	PersonName string
	Pattern    string
}

// AskNewPasswordAttribution stub for non-Windows
func AskNewPasswordAttribution(archiveName string) (*DialogResult, error) {
	return &DialogResult{Action: "cache"}, nil
}

// SuggestCreatePerson stub for non-Windows
func SuggestCreatePerson(password string, hitCount int) (*DialogResult, error) {
	return &DialogResult{Action: "cache"}, nil
}

// AskDeletePreference stub for non-Windows
func AskDeletePreference() (bool, error) {
	return false, nil
}

// ConfirmPerson stub for non-Windows
func ConfirmPerson(archiveName, personName string, confidence float64) (bool, error) {
	return false, nil
}

// AskHashDBContribution stub for non-Windows: never prompts, never accepts.
func AskHashDBContribution(archiveName string) (bool, error) {
	return false, nil
}
