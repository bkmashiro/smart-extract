//go:build windows

package ui

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/ncruces/zenity"
	"golang.org/x/sys/windows"
)

const mutexName = "Global\\SmartExtractDialog"

// DialogResult holds the result of the password dialog
type DialogResult struct {
	Password   string
	Action     string // "cache", "person:<name>", "new_person:<name>:<pattern>"
	PersonName string
	Pattern    string
}

// AcquireMutex acquires the named mutex so only one dialog shows at a time.
// Returns the mutex handle; call ReleaseMutex(handle) when done.
func AcquireMutex() (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(mutexName)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateMutex(nil, false, name)
	if err != nil {
		return 0, fmt.Errorf("creating mutex: %w", err)
	}
	// Wait for the mutex (timeout 30s)
	event, err := windows.WaitForSingleObject(handle, 30000)
	if err != nil {
		windows.CloseHandle(handle)
		return 0, fmt.Errorf("waiting for mutex: %w", err)
	}
	if event == uint32(windows.WAIT_TIMEOUT) {
		windows.CloseHandle(handle)
		return 0, fmt.Errorf("timed out waiting for dialog mutex")
	}
	return handle, nil
}

// ReleaseMutexHandle releases a previously acquired mutex
func ReleaseMutexHandle(handle windows.Handle) {
	windows.ReleaseMutex(handle)
	windows.CloseHandle(handle)
}

// AskPassword shows a native Windows input dialog asking for a password.
// Returns the entered password or an error if cancelled.
func AskPassword(archiveName string) (string, error) {
	handle, err := AcquireMutex()
	if err != nil {
		return "", err
	}
	defer ReleaseMutexHandle(handle)

	password, err := zenity.Entry(
		fmt.Sprintf("无法解压 %s，请输入密码：", archiveName),
		zenity.Title("智能解压 - 需要密码"),
		zenity.HideText(),
	)
	if err != nil {
		if err == zenity.ErrCanceled {
			return "", fmt.Errorf("用户取消")
		}
		return "", err
	}
	return password, nil
}

// AskNewPasswordAttribution shows a simplified dialog for a genuinely new password.
// Only two options: "新建人物" or "仅记住文件名" (no "已有人物" dropdown).
// Returns a DialogResult indicating the user's choice.
func AskNewPasswordAttribution(archiveName string) (*DialogResult, error) {
	handle, err := AcquireMutex()
	if err != nil {
		return nil, err
	}
	defer ReleaseMutexHandle(handle)

	items := []string{"仅记住文件名", "新建人物"}

	chosen, err := zenity.List(
		fmt.Sprintf("这是一个新密码。要创建一个人物来记住它吗？\n文件: %s", archiveName),
		items,
		zenity.Title("智能解压 - 新密码"),
	)
	if err != nil {
		if err == zenity.ErrCanceled {
			return &DialogResult{Action: "cache"}, nil
		}
		return nil, err
	}

	result := &DialogResult{}

	switch chosen {
	case "仅记住文件名":
		result.Action = "cache"

	case "新建人物":
		// Ask for person name
		name, err := zenity.Entry(
			"请输入新人物名称：",
			zenity.Title("智能解压 - 新建人物"),
		)
		if err != nil || name == "" {
			result.Action = "cache"
			return result, nil
		}
		// Ask for optional regex pattern
		pattern, err := zenity.Entry(
			"请输入文件名匹配模式（正则表达式，可留空）：",
			zenity.Title("智能解压 - 匹配模式"),
		)
		if err != nil {
			pattern = ""
		}
		result.Action = "new_person"
		result.PersonName = name
		result.Pattern = pattern
	}

	return result, nil
}

// SuggestCreatePerson shows a dialog suggesting the user create a person
// because a password has been used multiple times via exact filename cache.
// Returns a DialogResult: "new_person" or "cache" (dismiss).
func SuggestCreatePerson(password string, hitCount int) (*DialogResult, error) {
	handle, err := AcquireMutex()
	if err != nil {
		return nil, err
	}
	defer ReleaseMutexHandle(handle)

	items := []string{"仅记住文件名", "新建人物"}

	chosen, err := zenity.List(
		fmt.Sprintf("这个密码已经用了%d次了，要建个人物吗？", hitCount),
		items,
		zenity.Title("智能解压 - 建议创建人物"),
	)
	if err != nil {
		if err == zenity.ErrCanceled {
			return &DialogResult{Action: "cache"}, nil
		}
		return nil, err
	}

	result := &DialogResult{}

	switch chosen {
	case "仅记住文件名":
		result.Action = "cache"

	case "新建人物":
		name, err := zenity.Entry(
			"请输入新人物名称：",
			zenity.Title("智能解压 - 新建人物"),
		)
		if err != nil || name == "" {
			result.Action = "cache"
			return result, nil
		}
		pattern, err := zenity.Entry(
			"请输入文件名匹配模式（正则表达式，可留空）：",
			zenity.Title("智能解压 - 匹配模式"),
		)
		if err != nil {
			pattern = ""
		}
		result.Action = "new_person"
		result.PersonName = name
		result.Pattern = pattern
	}

	return result, nil
}

// AllocConsole allocates a console window for output (Windows API)
// and redirects Go's os.Stdout and os.Stderr to the new console.
func AllocConsole() {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	allocConsole := kernel32.NewProc("AllocConsole")
	allocConsole.Call()

	// Set UTF-8 code page first
	setConsoleCP := kernel32.NewProc("SetConsoleCP")
	setConsoleOutputCP := kernel32.NewProc("SetConsoleOutputCP")
	setConsoleCP.Call(65001)
	setConsoleOutputCP.Call(65001)

	// Open CONOUT$ to get a writable handle to the new console
	conout, err := windows.CreateFile(
		windows.StringToUTF16Ptr("CONOUT$"),
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err == nil {
		// Update the Win32 standard handles
		setStdHandle := kernel32.NewProc("SetStdHandle")
		setStdHandle.Call(uintptr(0xFFFFFFF5), uintptr(conout)) // STD_OUTPUT_HANDLE
		setStdHandle.Call(uintptr(0xFFFFFFF4), uintptr(conout)) // STD_ERROR_HANDLE

		// Redirect Go's os.Stdout and os.Stderr to the new console handle
		os.Stdout = os.NewFile(uintptr(conout), "CONOUT$")
		os.Stderr = os.NewFile(uintptr(conout), "CONOUT$")
	}

	// Open CONIN$ for stdin
	conin, err := windows.CreateFile(
		windows.StringToUTF16Ptr("CONIN$"),
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err == nil {
		setStdHandle := kernel32.NewProc("SetStdHandle")
		setStdHandle.Call(uintptr(0xFFFFFFF6), uintptr(conin)) // STD_INPUT_HANDLE
		os.Stdin = os.NewFile(uintptr(conin), "CONIN$")
	}

	// Set console title
	setTitle := kernel32.NewProc("SetConsoleTitleW")
	titlePtr, _ := syscall.UTF16PtrFromString("智能解压")
	setTitle.Call(uintptr(unsafe.Pointer(titlePtr)))
}

// WaitForKeypress prints a message and waits for the user to press Enter.
// If msg is empty, a default prompt is shown.
func WaitForKeypress(msg string) {
	if msg == "" {
		msg = "按 Enter 键关闭..."
	}
	fmt.Println(msg)
	var buf [1]byte
	_ = syscall.Stdin
	// Read one byte from stdin
	windows.ReadConsole(
		windows.Handle(syscall.Stdin),
		(*uint16)(unsafe.Pointer(&buf[0])),
		1,
		nil,
		nil,
	)
}

// AskDeletePreference shows a yes/no dialog asking whether to delete the original archive.
// Returns true if user wants to delete, false to keep.
func AskDeletePreference() (bool, error) {
	handle, err := AcquireMutex()
	if err != nil {
		return false, err
	}
	defer ReleaseMutexHandle(handle)

	err = zenity.Question(
		"解压完成！是否删除原始压缩包？\n\n（以后不再询问，记住我的选择）",
		zenity.Title("智能解压 - 删除原始文件"),
		zenity.OKLabel("是，删除"),
		zenity.CancelLabel("否，保留"),
	)
	if err == zenity.ErrCanceled {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// AskHashDBContribution asks the user whether to contribute a successful
// archive/password pair to the configured local HashDB sink. Returns true if
// the user accepts. Cancel is treated as a decline (false, nil).
func AskHashDBContribution(archiveName string) (bool, error) {
	handle, err := AcquireMutex()
	if err != nil {
		return false, err
	}
	defer ReleaseMutexHandle(handle)

	err = zenity.Question(
		fmt.Sprintf("将本次成功的密码（加密后）贡献到本地 HashDB？\n文件: %s", archiveName),
		zenity.Title("智能解压 - HashDB 贡献"),
		zenity.OKLabel("贡献"),
		zenity.CancelLabel("跳过"),
	)
	if err == zenity.ErrCanceled {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// ConfirmPerson prompts user to confirm person identification
func ConfirmPerson(archiveName, personName string, confidence float64) (bool, error) {
	handle, err := AcquireMutex()
	if err != nil {
		return false, err
	}
	defer ReleaseMutexHandle(handle)

	msg := fmt.Sprintf("文件 %s 可能是 %s 的？（相似度 %.0f%%）", archiveName, personName, confidence*100)
	err = zenity.Question(msg,
		zenity.Title("智能解压 - 确认归属"),
		zenity.OKLabel("是"),
		zenity.CancelLabel("否"),
	)
	if err == zenity.ErrCanceled {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
