package cmd

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/bkmashiro/smart-extract/internal/budget"
	"github.com/bkmashiro/smart-extract/internal/candidates"
	"github.com/bkmashiro/smart-extract/internal/config"
	"github.com/bkmashiro/smart-extract/internal/extractor"
	"github.com/bkmashiro/smart-extract/internal/hashdb"
	"github.com/bkmashiro/smart-extract/internal/learning"
	"github.com/bkmashiro/smart-extract/internal/ml"
	learningstore "github.com/bkmashiro/smart-extract/internal/store"
	"github.com/bkmashiro/smart-extract/internal/throttle"
	"github.com/bkmashiro/smart-extract/internal/ui"
)

// Extract is the main entry point for extracting a single archive file.
func Extract(archivePath string) error {
	return ExtractWithOptions(archivePath, ExtractOptions{})
}

// ExtractOptions controls optional diagnostics for a single extraction.
type ExtractOptions struct {
	// DebugLog receives structured diagnostic lines for troubleshooting. It must
	// not receive plaintext passwords; logs should report counts/sources only.
	DebugLog io.Writer
}

// ExtractWithOptions extracts a single archive file with optional diagnostics.
func ExtractWithOptions(archivePath string, options ExtractOptions) error {
	debug := newDebugLogger(options.DebugLog)
	debug.Logf("extract start archive=%s", filepath.Base(archivePath))
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

	learningStore, err := openLearningStore(learned)
	if err != nil {
		fmt.Printf("警告：SQLite 学习库不可用，回退到旧学习数据: %v\n", err)
	} else {
		defer learningStore.Close()
	}

	// Build password provider
	provider := newPasswordProvider(archivePath, archiveName, cfg, learned)
	provider.debug = debug
	provider.candidateSource = learningStore
	provider.sevenZipPath = sevenZipPath

	// Determine the person for this file
	person, err := provider.identifyPerson()
	if err != nil {
		fmt.Printf("警告：人物识别失败: %v\n", err)
	}
	provider.resolvedPerson = person

	opts := extractor.RecursiveExtractOptions{
		SevenZipPath:       sevenZipPath,
		BandizipPath:       cfg.BandizipPath,
		MaxDepth:           10,
		MaxParallelProbes:  cfg.MaxParallelProbes,
		ThrottleDir:        throttle.DefaultDir(),
		ThrottleSlots:      cfg.MaxParallelProbes,
		ThrottleStaleAfter: 10 * time.Minute,
		BudgetProfile:      budget.ParseProfile(cfg.ProbeBudgetProfile),
		OnArchiveSuccess:   makeArchiveSuccessRecorder(learningStore, cfg),
		TryPassword: func(ap, parentPassword string) ([]string, error) {
			// For nested archives, create a sub-provider
			subProvider := newPasswordProvider(ap, filepath.Base(ap), cfg, learned)
			subProvider.debug = debug
			subProvider.candidateSource = learningStore
			subProvider.sevenZipPath = sevenZipPath
			subProvider.parentPassword = parentPassword
			person2, _ := subProvider.identifyPerson()
			subProvider.resolvedPerson = person2
			return subProvider.getPasswords(ap)
		},
		OnProgress: func(msg string) {
			debug.Logf("progress %s", msg)
			fmt.Println(msg)
		},
	}

	outDir, successPwd, err := extractor.RecursiveExtract(archivePath, opts, 0)
	if err != nil {
		// All passwords failed — ask user
		debug.Logf("extract password candidates exhausted archive=%s err=%v", filepath.Base(archivePath), err)
		return handleUnknownPassword(archivePath, archiveName, sevenZipPath, cfg, learned, learningStore, opts)
	}

	debug.Logf("extract success archive=%s output=%s password_present=%t", filepath.Base(archivePath), filepath.Base(outDir), successPwd != "")
	fmt.Printf("\n✓ 解压完成 → %s\n", filepath.Base(outDir))

	// Record success. With SQLite available, recordLearningSuccess via the
	// recursive success callback is the authoritative learning write path;
	// learned.yaml is only a legacy fallback when SQLite could not open.
	if learningStore == nil && person != "" {
		_ = config.RecordSuccess(person, successPwd)
		_ = config.AddPersonFilename(person, filenameBase(archiveName))
	}

	// Auto-clustering hint for unknown files (legacy learned.yaml fallback only).
	if learningStore == nil && person == "" && successPwd != "" {
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
	archivePath     string
	archiveName     string
	cfg             *config.Config
	learned         *config.Learned
	candidateSource candidates.Source
	resolvedPerson  string
	sevenZipPath    string
	parentPassword  string
	debug           *debugLogger
}

func newPasswordProvider(archivePath, archiveName string, cfg *config.Config, learned *config.Learned) *passwordProvider {
	return &passwordProvider{
		archivePath: archivePath,
		archiveName: archiveName,
		cfg:         cfg,
		learned:     learned,
	}
}

func openLearningStore(learned *config.Learned) (*learningstore.Store, error) {
	st, err := learningstore.Open(config.LearningStorePath())
	if err != nil {
		return nil, err
	}
	if err := st.MigrateLearned(context.Background(), learned); err != nil {
		_ = st.Close()
		return nil, err
	}
	return st, nil
}

func recordLearningSuccess(st *learningstore.Store, archivePath, password, source string) error {
	if st == nil || password == "" {
		return nil
	}
	if source == "" {
		source = "extract_success"
	}
	archiveName := filepath.Base(archivePath)
	if err := st.SaveExact(context.Background(), learningstore.ExactCacheEntry{
		ArchiveKey: archiveName,
		Password:   password,
		Source:     source,
	}); err != nil {
		return err
	}
	var size int64
	if info, err := os.Stat(archivePath); err == nil {
		size = info.Size()
	}
	ctx := context.Background()
	_, err := st.AddObservation(ctx, learningstore.PasswordObservation{
		ArchivePath: archivePath,
		ArchiveName: archiveName,
		ParentDir:   filepath.Dir(archivePath),
		Password:    password,
		Source:      source,
		ArchiveSize: size,
	})
	if err != nil {
		return err
	}
	return learning.SummarizeShapePatterns(ctx, st, 2)
}

func makeArchiveSuccessRecorder(st *learningstore.Store, cfg *config.Config) func(archivePath, password string) {
	return func(archivePath, password string) {
		if err := recordLearningSuccess(st, archivePath, password, "auto_candidate"); err != nil {
			fmt.Printf("警告：保存 SQLite 学习记录失败: %v\n", err)
		}
		contributeLocalHashDB(cfg, archivePath, password)
	}
}

// confirmHashDBContribution is the seam used by ask-mode contribution to
// confirm with the user before appending a successful record. Tests override
// this to assert ask/decline/error paths without touching real dialogs.
var confirmHashDBContribution = func(archiveName string) (bool, error) {
	return ui.AskHashDBContribution(archiveName)
}

// contributeLocalHashDB appends a successful (archive, password) pair to the
// configured local HashDB contribution target when contribution mode is auto,
// or when mode is ask and the user accepts. All failures are soft: a warning
// is printed and the caller continues. No network access is performed.
func contributeLocalHashDB(cfg *config.Config, archivePath, password string) {
	if cfg == nil || password == "" {
		return
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.HashDB.Contribute))
	if mode != "auto" && mode != "ask" {
		return
	}
	c := cfg.HashDB.Contribution
	keyPath := strings.TrimSpace(c.KeyPath)
	if keyPath == "" {
		fmt.Printf("警告：HashDB 贡献跳过：未配置 key_path\n")
		return
	}
	source := c.Source
	if source == "" {
		source = "extract_success"
	}
	typ := strings.ToLower(strings.TrimSpace(c.Type))
	if typ == "" {
		if c.Path != "" {
			typ = "bundle"
		} else if c.BaseDir != "" {
			typ = "sharded"
		}
	}
	switch typ {
	case "bundle":
		if strings.TrimSpace(c.Path) == "" {
			fmt.Printf("警告：HashDB 贡献跳过：bundle 类型缺少 path\n")
			return
		}
	case "sharded":
		if strings.TrimSpace(c.BaseDir) == "" {
			fmt.Printf("警告：HashDB 贡献跳过：sharded 类型缺少 base_dir\n")
			return
		}
	default:
		fmt.Printf("警告：HashDB 贡献类型未知: %q\n", c.Type)
		return
	}
	if mode == "ask" {
		ok, err := confirmHashDBContribution(filepath.Base(archivePath))
		if err != nil {
			fmt.Printf("警告：HashDB 贡献询问失败: %v\n", err)
			return
		}
		if !ok {
			return
		}
	}

	ctx := context.Background()
	_, priv, err := hashdb.LoadOrCreateSigningKey(ctx, keyPath)
	if err != nil {
		fmt.Printf("警告：HashDB 贡献签名密钥不可用: %v\n", err)
		return
	}
	inputs := []hashdb.ArchivePassword{{ArchivePath: archivePath, Password: password, Source: source}}

	switch typ {
	case "bundle":
		if strings.TrimSpace(c.Path) == "" {
			fmt.Printf("警告：HashDB 贡献跳过：bundle 类型缺少 path\n")
			return
		}
		if _, err := hashdb.AppendSignedBundleRecords(ctx, c.Path, source, inputs, priv); err != nil {
			fmt.Printf("警告：HashDB 本地 bundle 贡献失败: %v\n", err)
		}
	case "sharded":
		if strings.TrimSpace(c.BaseDir) == "" {
			fmt.Printf("警告：HashDB 贡献跳过：sharded 类型缺少 base_dir\n")
			return
		}
		prefixLen := c.ShardPrefixLength
		if prefixLen == 0 {
			prefixLen = 2
		}
		if _, err := hashdb.AppendShardedSourceRecords(ctx, c.BaseDir, source, inputs, priv, prefixLen); err != nil {
			fmt.Printf("警告：HashDB 本地 sharded 贡献失败: %v\n", err)
		}
	default:
		fmt.Printf("警告：HashDB 贡献类型未知: %q\n", c.Type)
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

	// 2. Legacy n-gram ML identification. When SQLite is available, it is the
	// normal learning source; learned.yaml remains only a migration/fallback path.
	if p.candidateSource == nil && len(learned.PersonFilenames) > 0 {
		matches := ml.IdentifyPerson(archiveName, learned.PersonFilenames)
		if len(matches) > 0 {
			top := matches[0]
			if top.Confidence >= 0.5 {
				fmt.Printf("🔑 自动识别人物: %s（相似度 %.0f%%）\n", top.PersonName, top.Confidence*100)
				return top.PersonName, nil
			}
		}
	}

	return "", nil
}

func (p *passwordProvider) staticPasswords(includeLegacyLearned bool) []string {
	cfg := p.cfg
	learned := p.learned
	rankingLearned := learned
	if !includeLegacyLearned {
		rankingLearned = &config.Learned{PersonStats: map[string]map[string]*config.BetaStats{}}
	}
	var passwords []string
	seen := make(map[string]bool)
	addPwd := func(pw string) {
		if !seen[pw] {
			seen[pw] = true
			passwords = append(passwords, pw)
		}
	}

	if p.resolvedPerson != "" {
		pwSet := make(map[string]bool)
		var personPasswords []string
		person := cfg.People[p.resolvedPerson]
		if person != nil {
			for _, pw := range person.Passwords {
				if !pwSet[pw] {
					pwSet[pw] = true
					personPasswords = append(personPasswords, pw)
				}
			}
		}
		if includeLegacyLearned {
			if stats, ok := learned.PersonStats[p.resolvedPerson]; ok {
				for pw := range stats {
					if !pwSet[pw] {
						pwSet[pw] = true
						personPasswords = append(personPasswords, pw)
					}
				}
			}
		}
		if len(personPasswords) > 0 {
			ranked := ml.RankPasswordsThompson(p.resolvedPerson, personPasswords, rankingLearned)
			for _, r := range ranked {
				addPwd(r.Password)
			}
		}
	}

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
			ranked := ml.RankPasswordsThompson(pe.name, pe.person.Passwords, rankingLearned)
			for _, r := range ranked {
				addPwd(r.Password)
			}
		}
	}
	return passwords
}

// getPasswords returns the ordered password list for an archive
func (p *passwordProvider) getPasswords(archivePath string) ([]string, error) {
	archiveName := filepath.Base(archivePath)
	cfg := p.cfg
	learned := p.learned

	if p.candidateSource != nil {
		rec := p.budgetRecommendation(archivePath)
		hashDBPasswords := p.hashDBPasswords(context.Background(), archivePath)
		built, err := candidates.Build(context.Background(), candidates.Request{
			ArchivePath:       archivePath,
			ArchiveKey:        archiveName,
			ParentPassword:    p.parentPassword,
			HashDBPasswords:   hashDBPasswords,
			StaticPasswords:   p.staticPasswords(false),
			FallbackPasswords: cfg.FallbackPasswords,
			CandidateLimit:    rec.CandidateLimit,
		}, p.candidateSource)
		if err != nil {
			return nil, err
		}
		passwords := make([]string, 0, len(built))
		counts := make(map[string]int)
		for _, candidate := range built {
			passwords = append(passwords, candidate.Password)
			counts[candidate.Source]++
		}
		p.debug.Logf("candidate summary archive=%s profile=%s limit=%d total=%d hashdb_matches=%d %s", archiveName, debugProfileName(cfg.ProbeBudgetProfile), rec.CandidateLimit, len(built), len(hashDBPasswords), sortedCountSummary(counts))
		return passwords, nil
	}

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

	// Tier 1b: optional local HashDB signed bundle candidates. These are
	// archive-exact external candidates, but local exact cache remains first.
	for _, pw := range p.hashDBPasswords(context.Background(), archivePath) {
		addPwd(pw)
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

	p.debug.Logf("candidate summary archive=%s source=legacy total=%d", archiveName, len(passwords))
	return passwords, nil
}

func (p *passwordProvider) hashDBPasswords(ctx context.Context, archivePath string) []string {
	if p == nil || p.cfg == nil || !strings.EqualFold(p.cfg.HashDB.Mode, "lookup") {
		if p != nil {
			p.debug.Logf("hashdb summary mode=off")
		}
		return nil
	}

	var out []string
	seen := make(map[string]struct{})
	active := 0
	for _, src := range p.cfg.HashDB.Sources {
		label := hashDBSourceLabel(src)
		if src.Disabled {
			p.debug.Logf("hashdb source skipped name=%s reason=disabled", label)
			continue
		}
		active++
		passwords, err := p.lookupHashDBSource(ctx, src, archivePath)
		if err != nil {
			fmt.Printf("警告：HashDB 来源 %s 查询失败: %v\n", label, err)
			p.debug.Logf("hashdb source error name=%s err=%v", label, err)
			continue
		}
		p.debug.Logf("hashdb source lookup name=%s matches=%d", label, len(passwords))
		for _, password := range passwords {
			if _, ok := seen[password]; ok {
				continue
			}
			seen[password] = struct{}{}
			out = append(out, password)
		}
	}
	p.debug.Logf("hashdb summary sources=%d active=%d matches=%d", len(p.cfg.HashDB.Sources), active, len(out))
	return out
}

func (p *passwordProvider) lookupHashDBSource(ctx context.Context, src config.HashDBSource, archivePath string) ([]string, error) {
	prepared, err := p.prepareHashDBSource(ctx, src, archivePath)
	if err != nil {
		return nil, err
	}
	sourceType := strings.ToLower(strings.TrimSpace(prepared.Type))
	switch sourceType {
	case "", "bundle":
		return hashdb.LookupFileSource(ctx, hashdb.FileSource{
			Name:      prepared.Name,
			Path:      prepared.Path,
			PublicKey: prepared.PublicKey,
		}, archivePath)
	case "sharded":
		return hashdb.LookupShardedFileSource(ctx, hashdb.ShardedFileSource{
			Name:         prepared.Name,
			BaseDir:      prepared.BaseDir,
			ManifestPath: prepared.ManifestPath,
			PublicKey:    prepared.PublicKey,
		}, archivePath)
	default:
		return nil, fmt.Errorf("unsupported source type %q", prepared.Type)
	}
}

func (p *passwordProvider) prepareHashDBSource(ctx context.Context, src config.HashDBSource, archivePath string) (config.HashDBSource, error) {
	sourceType := strings.ToLower(strings.TrimSpace(src.Type))
	if (sourceType == "" || sourceType == "bundle") && strings.TrimSpace(src.Path) == "" && strings.TrimSpace(src.URL) != "" {
		cachedPath, err := cachedHashDBDownload(ctx, src, src.URL, "bundle.json", cachedHashDBDownloadOptions{
			Compression: src.Compression,
			SHA256:      src.SHA256,
		})
		if err != nil {
			return src, err
		}
		src.Path = cachedPath
	}
	if sourceType == "sharded" && strings.TrimSpace(src.ManifestPath) == "" && strings.TrimSpace(src.ManifestURL) != "" {
		cacheRoot, err := hashDBSourceCacheRoot(src)
		if err != nil {
			return src, err
		}
		manifestPath, err := cachedHashDBDownloadTo(ctx, src.ManifestURL, filepath.Join(cacheRoot, "manifest.json"), cachedHashDBDownloadOptions{})
		if err != nil {
			return src, err
		}
		manifestData, err := os.ReadFile(manifestPath)
		if err != nil {
			return src, fmt.Errorf("hashdb sharded source cache: read manifest: %w", err)
		}
		manifest, err := hashdb.ParseManifest(manifestData)
		if err != nil {
			return src, fmt.Errorf("hashdb sharded source cache: parse manifest: %w", err)
		}
		prefix, err := hashDBShardPrefixForArchive(archivePath, manifest.ShardPrefixLength)
		if err != nil {
			return src, err
		}
		if shard, ok := manifest.Shards[prefix]; ok {
			shardURL, err := resolveHashDBURL(src.ManifestURL, shard.Path)
			if err != nil {
				return src, err
			}
			if _, err := cachedHashDBDownloadTo(ctx, shardURL, filepath.Join(cacheRoot, shard.Path), cachedHashDBDownloadOptions{
				Compression: shard.Compression,
				SHA256:      shard.SHA256,
			}); err != nil {
				return src, err
			}
		}
		src.BaseDir = cacheRoot
		src.ManifestPath = manifestPath
	}
	return src, nil
}

func hashDBShardPrefixForArchive(archivePath string, prefixLen int) (string, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return "", fmt.Errorf("hashdb sharded source cache: open archive: %w", err)
	}
	defer f.Close()
	digest := hashdb.ArchiveHash(f)
	recordIDHex := hashdb.RecordID(digest).Hex()
	if len(recordIDHex) < prefixLen {
		return "", fmt.Errorf("hashdb sharded source cache: record_id shorter than prefix length")
	}
	return strings.ToLower(recordIDHex[:prefixLen]), nil
}

func cachedHashDBDownload(ctx context.Context, src config.HashDBSource, rawURL, filename string, opts cachedHashDBDownloadOptions) (string, error) {
	cacheRoot, err := hashDBSourceCacheRoot(src)
	if err != nil {
		return "", err
	}
	return cachedHashDBDownloadTo(ctx, rawURL, filepath.Join(cacheRoot, filename), opts)
}

// cachedHashDBDownloadOptions configures optional integrity and decompression
// behaviors for the static HTTP HashDB cache helper.
type cachedHashDBDownloadOptions struct {
	// Compression, when non-empty, names the codec used for the downloaded
	// bytes. Currently only "gzip" is supported.
	Compression string
	// SHA256, when non-empty, is the expected lowercase hex SHA-256 over the
	// raw downloaded bytes (i.e. the compressed payload when Compression is
	// set). Verified before installing the cache file.
	SHA256 string
}

func hashDBSourceCacheRoot(src config.HashDBSource) (string, error) {
	root := strings.TrimSpace(src.CacheDir)
	if root == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return "", fmt.Errorf("hashdb source cache: resolve user cache dir: %w", err)
		}
		root = filepath.Join(base, "smart-extract", "hashdb")
	}
	idInput := src.URL
	if idInput == "" {
		idInput = src.ManifestURL
	}
	if idInput == "" {
		idInput = src.Name
	}
	sum := sha256.Sum256([]byte(idInput))
	return filepath.Join(root, hex.EncodeToString(sum[:8])), nil
}

const hashDBCacheMaxBytes = 64 << 20

func cachedHashDBDownloadTo(ctx context.Context, rawURL, targetPath string, opts cachedHashDBDownloadOptions) (string, error) {
	if strings.TrimSpace(rawURL) == "" {
		return "", fmt.Errorf("hashdb source cache: empty url")
	}
	compression := strings.ToLower(strings.TrimSpace(opts.Compression))
	switch compression {
	case "", "gzip":
		// supported
	default:
		return "", fmt.Errorf("hashdb source cache: unsupported compression %q (supported: gzip)", opts.Compression)
	}
	wantShaOpt := strings.ToLower(strings.TrimSpace(opts.SHA256))
	if wantShaOpt != "" {
		raw, err := hex.DecodeString(wantShaOpt)
		if err != nil || len(raw) != sha256.Size {
			return "", fmt.Errorf("hashdb source cache: malformed sha256 %q", opts.SHA256)
		}
	}
	metaPath := targetPath + ".meta.json"
	if _, err := os.Stat(targetPath); err == nil {
		if m, mErr := readCachedHashDBMetadata(metaPath); mErr == nil {
			if cachedHashDBMetadataMatches(m, rawURL, compression, wantShaOpt) {
				return targetPath, nil
			}
		} else if !errors.Is(mErr, os.ErrNotExist) {
			// Unreadable metadata: treat as mismatch and refresh.
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("hashdb source cache: stat %s: %w", targetPath, err)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("hashdb source cache: parse url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("hashdb source cache: unsupported url scheme %q", parsed.Scheme)
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", fmt.Errorf("hashdb source cache: build request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("hashdb source cache: download %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("hashdb source cache: download %s: status %s", rawURL, resp.Status)
	}

	limited := io.LimitReader(resp.Body, int64(hashDBCacheMaxBytes)+1)
	downloaded, err := io.ReadAll(limited)
	if err != nil {
		return "", fmt.Errorf("hashdb source cache: read body: %w", err)
	}
	if len(downloaded) > hashDBCacheMaxBytes {
		return "", fmt.Errorf("hashdb source cache: response too large (limit 64 MiB)")
	}

	rawSum := sha256.Sum256(downloaded)
	downloadedShaHex := hex.EncodeToString(rawSum[:])
	if wantShaOpt != "" {
		if downloadedShaHex != wantShaOpt {
			return "", fmt.Errorf("hashdb source cache: sha256 mismatch for %s: got %s, want %s", rawURL, downloadedShaHex, wantShaOpt)
		}
	}

	payload := downloaded
	if compression == "gzip" {
		gz, err := gzip.NewReader(bytes.NewReader(downloaded))
		if err != nil {
			return "", fmt.Errorf("hashdb source cache: gzip reader for %s: %w", rawURL, err)
		}
		defer gz.Close()
		decompressed, err := io.ReadAll(io.LimitReader(gz, int64(hashDBCacheMaxBytes)+1))
		if err != nil {
			return "", fmt.Errorf("hashdb source cache: gunzip %s: %w", rawURL, err)
		}
		if len(decompressed) > hashDBCacheMaxBytes {
			return "", fmt.Errorf("hashdb source cache: decompressed payload too large (limit 64 MiB)")
		}
		payload = decompressed
	}

	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return "", fmt.Errorf("hashdb source cache: mkdir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(targetPath), ".download-*.tmp")
	if err != nil {
		return "", fmt.Errorf("hashdb source cache: create temp: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("hashdb source cache: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("hashdb source cache: close temp: %w", err)
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		return "", fmt.Errorf("hashdb source cache: install cache file: %w", err)
	}
	meta := cachedHashDBMetadata{
		URL:              rawURL,
		Compression:      compression,
		SHA256:           wantShaOpt,
		DownloadedSHA256: downloadedShaHex,
		CachedAt:         time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := writeCachedHashDBMetadata(metaPath, meta); err != nil {
		return "", err
	}
	return targetPath, nil
}

// cachedHashDBMetadata is the sidecar stored next to a cached HashDB payload.
// It binds a cache file to the (url, compression, sha256) that produced it so
// configuration changes force a redownload rather than silently reusing stale
// content.
type cachedHashDBMetadata struct {
	URL              string `json:"url"`
	Compression      string `json:"compression"`
	SHA256           string `json:"sha256"`
	DownloadedSHA256 string `json:"downloaded_sha256"`
	CachedAt         string `json:"cached_at"`
}

func readCachedHashDBMetadata(path string) (cachedHashDBMetadata, error) {
	var m cachedHashDBMetadata
	data, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return m, err
	}
	return m, nil
}

func cachedHashDBMetadataMatches(m cachedHashDBMetadata, rawURL, compression, sha string) bool {
	gotCompression := strings.ToLower(strings.TrimSpace(m.Compression))
	gotSha := strings.ToLower(strings.TrimSpace(m.SHA256))
	return m.URL == rawURL && gotCompression == compression && gotSha == sha
}

func writeCachedHashDBMetadata(metaPath string, m cachedHashDBMetadata) error {
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("hashdb source cache: marshal metadata: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(metaPath), ".meta-*.tmp")
	if err != nil {
		return fmt.Errorf("hashdb source cache: create metadata temp: %w", err)
	}
	tmpPath := tmp.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("hashdb source cache: write metadata temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("hashdb source cache: close metadata temp: %w", err)
	}
	if err := os.Rename(tmpPath, metaPath); err != nil {
		return fmt.Errorf("hashdb source cache: install metadata: %w", err)
	}
	keep = true
	return nil
}

func resolveHashDBURL(baseURL, relPath string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("hashdb source cache: parse manifest url: %w", err)
	}
	ref, err := url.Parse(relPath)
	if err != nil {
		return "", fmt.Errorf("hashdb source cache: parse shard url: %w", err)
	}
	return base.ResolveReference(ref).String(), nil
}

func hashDBSourceLabel(src config.HashDBSource) string {
	if src.Name != "" {
		return src.Name
	}
	if src.Path != "" {
		return src.Path
	}
	if src.URL != "" {
		return src.URL
	}
	if src.ManifestPath != "" {
		return src.ManifestPath
	}
	if src.ManifestURL != "" {
		return src.ManifestURL
	}
	if src.BaseDir != "" {
		return src.BaseDir
	}
	if src.Type != "" {
		return src.Type
	}
	return "<unnamed>"
}

func (p *passwordProvider) budgetRecommendation(archivePath string) budget.Recommendation {
	af := extractor.DetectFormat(archivePath, p.sevenZipPath)
	var size int64
	if info, err := os.Stat(archivePath); err == nil {
		size = info.Size()
	}
	return budget.Recommend(budget.Inputs{
		Format:            af.Format,
		ArchiveSizeBytes:  size,
		Profile:           budget.ParseProfile(p.cfg.ProbeBudgetProfile),
		MaxParallelProbes: p.cfg.MaxParallelProbes,
	})
}

// handleUnknownPassword is called when all passwords fail — shows dialog and learns
func handleUnknownPassword(
	archivePath, archiveName, sevenZipPath string,
	cfg *config.Config,
	learned *config.Learned,
	learningStore *learningstore.Store,
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
	if err := recordLearningSuccess(learningStore, archivePath, password, "user_input"); err != nil {
		fmt.Printf("警告：保存 SQLite 学习记录失败: %v\n", err)
	}

	// Step 1: Check if this password already belongs to a known person
	existingPerson := config.FindPersonByPassword(password)
	if learningStore == nil {
		// Legacy fallback when SQLite is unavailable.
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
	} else if existingPerson != "" {
		// Keep the UI hint without mutating learned.yaml; SQLite already recorded
		// the extraction above.
		fmt.Printf("✓ 密码自动匹配到人物: %s\n", existingPerson)
	}

	// Flatten and recurse nested archives
	_ = extractor.FlattenSingleFolder(outputDir)

	childOpts := opts
	childOpts.ParentPassword = password
	_ = walkNested(outputDir, childOpts)

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
