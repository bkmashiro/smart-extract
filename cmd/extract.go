package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/bkmashiro/smart-extract/internal/config"
	"github.com/bkmashiro/smart-extract/internal/extractor"
	"github.com/bkmashiro/smart-extract/internal/ml"
	"github.com/bkmashiro/smart-extract/internal/ui"
)

// Extract is the main entry point for extracting a single archive file.
func Extract(archivePath string) error {
	// Resolve to absolute path to handle relative paths and symlinks
	absPath, err := filepath.Abs(archivePath)
	if err == nil {
		archivePath = absPath
	}

	// Verify the file exists
	if _, err := os.Stat(archivePath); err != nil {
		return fmt.Errorf("文件不存在: %s", archivePath)
	}

	// Allocate console for progress display
	ui.AllocConsole()

	fmt.Printf("🔑 智能解压\n")
	fmt.Printf("📦 文件: %s\n\n", filepath.Base(archivePath))

	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("加载配置失败: %w", err)
	}

	learned, err := config.LoadLearned()
	if err != nil {
		return fmt.Errorf("加载学习数据失败: %w", err)
	}

	// Find 7z.exe
	sevenZipPath, err := extractor.FindSevenZip(cfg.SevenZipPath)
	if err != nil {
		return err
	}

	archiveName := filepath.Base(archivePath)

	// Build password provider
	provider := newPasswordProvider(archivePath, archiveName, cfg, learned)

	// Determine the person for this file
	person, err := provider.identifyPerson()
	if err != nil {
		fmt.Printf("警告：人物识别失败: %v\n", err)
	}
	provider.resolvedPerson = person

	opts := extractor.RecursiveExtractOptions{
		SevenZipPath:      sevenZipPath,
		BandizipPath:      cfg.BandizipPath,
		MaxDepth:          10,
		MaxParallelProbes: cfg.MaxParallelProbes,
		TryPassword: func(ap string) ([]string, error) {
			// For nested archives, create a sub-provider
			subProvider := newPasswordProvider(ap, filepath.Base(ap), cfg, learned)
			person2, _ := subProvider.identifyPerson()
			subProvider.resolvedPerson = person2
			return subProvider.getPasswords(ap)
		},
		OnProgress: func(msg string) {
			fmt.Println(msg)
		},
	}

	outDir, successPwd, err := extractor.RecursiveExtract(archivePath, opts, 0)
	if err != nil {
		// All passwords failed — ask user
		return handleUnknownPassword(archivePath, archiveName, sevenZipPath, cfg, learned, opts)
	}

	fmt.Printf("\n✓ 解压完成 → %s\n", filepath.Base(outDir))

	// Record success
	if person != "" {
		_ = config.RecordSuccess(person, successPwd)
		_ = config.AddPersonFilename(person, filenameBase(archiveName))
	}

	// Auto-clustering hint for unknown files
	if person == "" && successPwd != "" {
		config.ReloadAll()
		if freshLearned, lerr := config.LoadLearned(); lerr == nil {
			hint := ml.CheckClusteringHint(successPwd, freshLearned)
			if hint != "" {
				fmt.Printf("\n💡 %s\n", hint)
			}
		}
	}

	// Handle delete-after-extract preference
	handleDeleteAfterExtract(archivePath, outDir)

	return nil
}

// passwordProvider builds ordered password lists for a given archive
type passwordProvider struct {
	archivePath    string
	archiveName    string
	cfg            *config.Config
	learned        *config.Learned
	resolvedPerson string
}

func newPasswordProvider(archivePath, archiveName string, cfg *config.Config, learned *config.Learned) *passwordProvider {
	return &passwordProvider{
		archivePath: archivePath,
		archiveName: archiveName,
		cfg:         cfg,
		learned:     learned,
	}
}

// identifyPerson determines which person this file belongs to
func (p *passwordProvider) identifyPerson() (string, error) {
	archiveName := p.archiveName
	cfg := p.cfg
	learned := p.learned

	// 1. Check pattern matching
	for name, person := range cfg.People {
		if person.MatchMode == "pattern" {
			for _, pat := range person.Patterns {
				re, err := regexp.Compile(pat)
				if err != nil {
					continue
				}
				base := filenameBase(archiveName)
				if re.MatchString(base) || re.MatchString(archiveName) {
					fmt.Printf("🔑 正则匹配到人物: %s (模式: %s)\n", name, pat)
					return name, nil
				}
			}
		}
	}

	// 2. N-gram ML identification
	if len(learned.PersonFilenames) > 0 {
		matches := ml.IdentifyPerson(archiveName, learned.PersonFilenames)
		if len(matches) > 0 {
			top := matches[0]
			if top.Confidence > 0.7 {
				fmt.Printf("🔑 自动识别人物: %s（相似度 %.0f%%）\n", top.PersonName, top.Confidence*100)
				return top.PersonName, nil
			} else if top.Confidence >= 0.5 {
				confirmed, err := ui.ConfirmPerson(archiveName, top.PersonName, top.Confidence)
				if err == nil && confirmed {
					return top.PersonName, nil
				}
			}
		}
	}

	return "", nil
}

// getPasswords returns the ordered password list for an archive
func (p *passwordProvider) getPasswords(archivePath string) ([]string, error) {
	archiveName := filepath.Base(archivePath)
	cfg := p.cfg
	learned := p.learned

	var passwords []string
	seen := make(map[string]bool)

	addPwd := func(pw string) {
		if !seen[pw] {
			seen[pw] = true
			passwords = append(passwords, pw)
		}
	}

	// Tier 1: Exact cache (case-insensitive lookup for Windows compatibility)
	archiveNameLower := strings.ToLower(archiveName)
	for k, v := range learned.Exact {
		if strings.ToLower(k) == archiveNameLower {
			fmt.Printf("🔑 使用缓存密码\n")
			addPwd(v)
			break
		}
	}

	// Tier 2: Person profile (if identified)
	// Password candidates = UNION of config.yaml passwords + learned.yaml person_stats keys
	if p.resolvedPerson != "" {
		pwSet := make(map[string]bool)
		var personPasswords []string

		// From config.yaml
		person := cfg.People[p.resolvedPerson]
		if person != nil {
			for _, pw := range person.Passwords {
				if !pwSet[pw] {
					pwSet[pw] = true
					personPasswords = append(personPasswords, pw)
				}
			}
		}

		// From learned.yaml person_stats (passwords learned through usage)
		if stats, ok := learned.PersonStats[p.resolvedPerson]; ok {
			for pw := range stats {
				if !pwSet[pw] {
					pwSet[pw] = true
					personPasswords = append(personPasswords, pw)
				}
			}
		}

		if len(personPasswords) > 0 {
			ranked := ml.RankPasswordsThompson(p.resolvedPerson, personPasswords, learned)
			for _, r := range ranked {
				addPwd(r.Password)
			}
		}
	}

	// Tier 2b: always_try people (sorted by priority)
	type personEntry struct {
		name   string
		person *config.Person
	}
	var alwaysTryPeople []personEntry
	for name, person := range cfg.People {
		if person.MatchMode == "always_try" && name != p.resolvedPerson {
			alwaysTryPeople = append(alwaysTryPeople, personEntry{name, person})
		}
	}
	sort.Slice(alwaysTryPeople, func(i, j int) bool {
		return alwaysTryPeople[i].person.Priority < alwaysTryPeople[j].person.Priority
	})
	for _, pe := range alwaysTryPeople {
		if len(pe.person.Passwords) > 0 {
			ranked := ml.RankPasswordsThompson(pe.name, pe.person.Passwords, learned)
			for _, r := range ranked {
				addPwd(r.Password)
			}
		}
	}

	// Tier 3: Fallback passwords
	for _, pw := range cfg.FallbackPasswords {
		addPwd(pw)
	}

	// Always try without password (empty string) as last resort
	addPwd("")

	return passwords, nil
}

// handleUnknownPassword is called when all passwords fail — shows dialog and learns
func handleUnknownPassword(
	archivePath, archiveName, sevenZipPath string,
	cfg *config.Config,
	learned *config.Learned,
	opts extractor.RecursiveExtractOptions,
) error {
	fmt.Printf("\n✗ 所有密码均失败\n")

	// Ask user for password
	password, err := ui.AskPassword(archiveName)
	if err != nil {
		return fmt.Errorf("无法解压: %w", err)
	}

	// Try the user-provided password
	outputDir := extractor.OutputDirForArchive(archivePath)
	result := extractor.TryExtract(sevenZipPath, archivePath, outputDir, password)
	if !result.Success {
		return fmt.Errorf("用户提供的密码也失败了: %s", result.Output)
	}

	fmt.Printf("✓ 解压成功\n")

	// Step 1: Check if this password already belongs to a known person
	existingPerson := config.FindPersonByPassword(password)
	if existingPerson != "" {
		// Auto-assign silently — password already belongs to a known person
		fmt.Printf("✓ 密码自动匹配到人物: %s\n", existingPerson)
		_ = config.RecordSuccess(existingPerson, password)
		_ = config.AddPersonFilename(existingPerson, filenameBase(archiveName))
		_ = config.SaveExactCache(archiveName, password)
	} else {
		// This is a genuinely new password — increment hit counter
		hitCount, _ := config.IncrementPasswordHitCount(password)

		// Step 3: Check if this password has been used 3+ times — suggest creating a person
		if hitCount >= 3 {
			fmt.Printf("\n💡 这个密码已经用了%d次了\n", hitCount)
			attribution, err := ui.SuggestCreatePerson(password, hitCount)
			if err != nil {
				_ = config.SaveExactCache(archiveName, password)
			} else {
				handleNewPasswordAttribution(attribution, archiveName, password)
			}
		} else {
			// Step 2: Show simplified dialog — only "新建人物" / "仅记住文件名"
			attribution, err := ui.AskNewPasswordAttribution(archiveName)
			if err != nil {
				_ = config.SaveExactCache(archiveName, password)
			} else {
				handleNewPasswordAttribution(attribution, archiveName, password)
			}
		}
	}

	// Flatten and recurse nested archives
	_ = extractor.FlattenSingleFolder(outputDir)

	_ = walkNested(outputDir, opts)

	fmt.Printf("\n✓ 解压完成 → %s\n", filepath.Base(outputDir))

	// Handle delete-after-extract preference
	handleDeleteAfterExtract(archivePath, outputDir)

	return nil
}

// handleNewPasswordAttribution processes the result of a new-password dialog
func handleNewPasswordAttribution(attribution *ui.DialogResult, archiveName, password string) {
	switch attribution.Action {
	case "cache":
		if err := config.SaveExactCache(archiveName, password); err != nil {
			fmt.Printf("警告：保存密码缓存失败: %v\n", err)
		} else {
			fmt.Printf("✓ 已保存到文件名缓存\n")
		}

	case "new_person":
		patterns := []string{}
		if attribution.Pattern != "" {
			patterns = []string{attribution.Pattern}
		}
		if err := config.AddPerson(attribution.PersonName, patterns, []string{password}, "pattern"); err != nil {
			fmt.Printf("警告：创建人物档案失败: %v\n", err)
		} else {
			fmt.Printf("✓ 已创建人物档案: %s\n", attribution.PersonName)
		}
		_ = config.AddPersonFilename(attribution.PersonName, filenameBase(archiveName))
		_ = config.SaveExactCache(archiveName, password)
		// Clear hit counter since password is now assigned to a person
		_ = config.ClearPasswordHitCount(password)
	}
}

// walkNested recursively walks dir and extracts any archives found at any depth.
func walkNested(dir string, opts extractor.RecursiveExtractOptions) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		if e.IsDir() {
			if err := walkNested(path, opts); err != nil {
				return err
			}
			continue
		}
		if extractor.IsArchive(path) {
			_, _, err := extractor.RecursiveExtract(path, opts, 1)
			if err != nil && opts.OnProgress != nil {
				opts.OnProgress(fmt.Sprintf("警告：无法解压嵌套档案 %s: %v", e.Name(), err))
			}
		}
	}
	return nil
}

// handleDeleteAfterExtract checks the user's preference for deleting archives
// after successful extraction. If not set, shows a dialog to ask. Then applies
// the preference.
func handleDeleteAfterExtract(archivePath, outDir string) {
	// Verify the output directory exists and is non-empty
	entries, err := os.ReadDir(outDir)
	if err != nil || len(entries) == 0 {
		return
	}

	// Reload learned data to get current preferences
	config.ReloadAll()
	l, err := config.LoadLearned()
	if err != nil {
		fmt.Printf("警告：无法加载偏好设置: %v\n", err)
		return
	}

	shouldDelete := false

	if !l.Preferences.DeletePreferenceSet {
		// First time — ask the user
		wantDelete, err := ui.AskDeletePreference()
		if err != nil {
			fmt.Printf("警告：无法显示删除确认对话框: %v\n", err)
			return
		}
		// Save the preference
		if err := config.SaveDeletePreference(wantDelete); err != nil {
			fmt.Printf("警告：无法保存偏好设置: %v\n", err)
		}
		shouldDelete = wantDelete
	} else {
		shouldDelete = l.Preferences.DeleteAfterExtract
	}

	if shouldDelete {
		deleteArchiveWithParts(archivePath)
	}
}

// deleteArchiveWithParts deletes the archive file and, for multi-part archives
// (.zip.001 etc.), deletes all parts (.001, .002, ...).
func deleteArchiveWithParts(archivePath string) {
	lower := strings.ToLower(archivePath)

	// Check if this is a multi-part archive (.zip.001, .7z.001, .rar.001)
	if strings.HasSuffix(lower, ".001") {
		withoutPart := archivePath[:len(archivePath)-4]
		withoutPartLower := strings.ToLower(withoutPart)
		partExt := filepath.Ext(withoutPartLower)
		isMultiPart := false
		switch partExt {
		case ".zip", ".7z", ".rar":
			isMultiPart = true
		}

		if isMultiPart {
			// Delete all parts: .001, .002, .003, ...
			for i := 1; i < 10000; i++ {
				partPath := fmt.Sprintf("%s.%03d", withoutPart, i)
				if _, err := os.Stat(partPath); os.IsNotExist(err) {
					break
				}
				if err := os.Remove(partPath); err != nil {
					fmt.Printf("警告：无法删除分卷 %s: %v\n", filepath.Base(partPath), err)
				} else {
					fmt.Printf("🗑 已删除分卷: %s\n", filepath.Base(partPath))
				}
			}
			return
		}
	}

	// Single archive file
	if err := os.Remove(archivePath); err != nil {
		fmt.Printf("警告：无法删除原始压缩包 %s: %v\n", filepath.Base(archivePath), err)
	} else {
		fmt.Printf("🗑 已删除原始压缩包: %s\n", filepath.Base(archivePath))
	}
}

// filenameBase returns the filename without extension
func filenameBase(name string) string {
	base := filepath.Base(name)
	ext := filepath.Ext(base)
	if ext != "" {
		return base[:len(base)-len(ext)]
	}
	return base
}
