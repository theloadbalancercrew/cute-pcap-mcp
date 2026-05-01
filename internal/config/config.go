package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sigs.k8s.io/yaml"
)

type Config struct {
	AllowedArtifactDirs []string        `json:"allowed_artifact_dirs"`
	Workspace           WorkspaceConfig `json:"workspace"`
	Analysis            AnalysisConfig  `json:"analysis"`
}

// WorkspaceConfig is the local filesystem contract for the server. The
// canonical container shape is `-v ~/mcp-work:/work`, with PCAPs read
// from `/work/pcaps`, derived artifacts written to `/work/output`, and
// per-call analyzer temp work under `/work/tmp`. All four roots are
// resolved through filepath.EvalSymlinks at config-load time and
// rejected if they escape one another.
type WorkspaceConfig struct {
	Root      string `json:"root"`
	PCAPDir   string `json:"pcap_dir"`
	OutputDir string `json:"output_dir"`
	TmpDir    string `json:"tmp_dir"`
	// KeylogDir is the optional allowlisted directory for TLS
	// SSLKEYLOGFILE inputs. When unset, TLS decryption is
	// reported as `unavailable` regardless of caller input. When
	// set, callers may pass tls_keylog_path values that resolve
	// strictly under this directory.
	KeylogDir string `json:"keylog_dir"`
}

type AnalysisConfig struct {
	CommandTimeoutSeconds int `json:"command_timeout_seconds"`
	MaxStdoutBytes        int `json:"max_stdout_bytes"`
	MaxPacketRows         int `json:"max_packet_rows"`
	MaxASCIIStrings       int `json:"max_ascii_strings"`
	MaxASCIIBytes         int `json:"max_ascii_bytes"`
	MaxZeekRecordsPerLog  int `json:"max_zeek_records_per_log"`

	// MaxPCAPBytes is the maximum size of a pcap/pcapng file the server
	// will accept. Files strictly larger than this are rejected before
	// any external analyzer runs. 0 means use the default (1 GiB).
	MaxPCAPBytes int64 `json:"max_pcap_bytes"`

	// MaxConcurrentAnalyses caps the number of analyzer-bearing tool
	// calls in flight at once. analyze_pcap and summarize_pcap acquire
	// a slot before invoking external tools; over-budget calls return
	// the typed analysis_busy error. 0 means use the default (2).
	MaxConcurrentAnalyses int `json:"max_concurrent_analyses"`

	// TmpDiskBudgetBytes caps the on-disk size of per-call analyzer
	// temp work (e.g. Zeek's per-call working directory). 0 means use
	// the default (512 MiB).
	TmpDiskBudgetBytes int64 `json:"tmp_disk_budget_bytes"`

	// OutputDiskBudgetBytes caps the on-disk size of derived JSON /
	// Markdown artifacts written under the configured output dir. 0
	// means use the default (256 MiB).
	OutputDiskBudgetBytes int64 `json:"output_disk_budget_bytes"`
}

func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return Config{}, err
	}
	return Normalize(cfg)
}

func Normalize(cfg Config) (Config, error) {
	cfg, err := normalizeWorkspace(cfg)
	if err != nil {
		return Config{}, err
	}
	if len(cfg.AllowedArtifactDirs) == 0 && cfg.Workspace.PCAPDir == "" {
		return Config{}, fmt.Errorf("either allowed_artifact_dirs or workspace.pcap_dir must be configured")
	}
	dirs := make([]string, 0, len(cfg.AllowedArtifactDirs))
	seen := map[string]bool{}
	for _, dir := range cfg.AllowedArtifactDirs {
		if dir == "" {
			return Config{}, fmt.Errorf("allowed_artifact_dirs must not contain an empty path")
		}
		abs, err := resolveExistingDir(dir)
		if err != nil {
			return Config{}, fmt.Errorf("resolve allowed_artifact_dirs entry %q: %w", dir, err)
		}
		if seen[abs] {
			continue
		}
		seen[abs] = true
		dirs = append(dirs, abs)
	}
	if cfg.Workspace.PCAPDir != "" && !seen[cfg.Workspace.PCAPDir] {
		dirs = append(dirs, cfg.Workspace.PCAPDir)
		seen[cfg.Workspace.PCAPDir] = true
	}
	cfg.AllowedArtifactDirs = dirs

	if cfg.Analysis.CommandTimeoutSeconds == 0 {
		cfg.Analysis.CommandTimeoutSeconds = 20
	}
	if cfg.Analysis.CommandTimeoutSeconds < 1 || cfg.Analysis.CommandTimeoutSeconds > 120 {
		return Config{}, fmt.Errorf("analysis.command_timeout_seconds must be between 1 and 120")
	}
	if cfg.Analysis.MaxStdoutBytes == 0 {
		cfg.Analysis.MaxStdoutBytes = 200000
	}
	if cfg.Analysis.MaxStdoutBytes < 1024 || cfg.Analysis.MaxStdoutBytes > 5_000_000 {
		return Config{}, fmt.Errorf("analysis.max_stdout_bytes must be between 1024 and 5000000")
	}
	if cfg.Analysis.MaxPacketRows == 0 {
		cfg.Analysis.MaxPacketRows = 200
	}
	if cfg.Analysis.MaxPacketRows < 1 || cfg.Analysis.MaxPacketRows > 10_000 {
		return Config{}, fmt.Errorf("analysis.max_packet_rows must be between 1 and 10000")
	}
	if cfg.Analysis.MaxASCIIStrings == 0 {
		cfg.Analysis.MaxASCIIStrings = 200
	}
	if cfg.Analysis.MaxASCIIStrings < 1 || cfg.Analysis.MaxASCIIStrings > 10_000 {
		return Config{}, fmt.Errorf("analysis.max_ascii_strings must be between 1 and 10000")
	}
	if cfg.Analysis.MaxASCIIBytes == 0 {
		cfg.Analysis.MaxASCIIBytes = 200_000
	}
	if cfg.Analysis.MaxASCIIBytes < 1024 || cfg.Analysis.MaxASCIIBytes > 5_000_000 {
		return Config{}, fmt.Errorf("analysis.max_ascii_bytes must be between 1024 and 5000000")
	}
	if cfg.Analysis.MaxZeekRecordsPerLog == 0 {
		cfg.Analysis.MaxZeekRecordsPerLog = 100
	}
	if cfg.Analysis.MaxZeekRecordsPerLog < 1 || cfg.Analysis.MaxZeekRecordsPerLog > 10_000 {
		return Config{}, fmt.Errorf("analysis.max_zeek_records_per_log must be between 1 and 10000")
	}
	if cfg.Analysis.MaxPCAPBytes == 0 {
		cfg.Analysis.MaxPCAPBytes = 1 << 30 // 1 GiB
	}
	if cfg.Analysis.MaxPCAPBytes < 64*1024 {
		return Config{}, fmt.Errorf("analysis.max_pcap_bytes must be at least 65536 bytes")
	}
	if cfg.Analysis.MaxConcurrentAnalyses == 0 {
		cfg.Analysis.MaxConcurrentAnalyses = 2
	}
	if cfg.Analysis.MaxConcurrentAnalyses < 1 || cfg.Analysis.MaxConcurrentAnalyses > 64 {
		return Config{}, fmt.Errorf("analysis.max_concurrent_analyses must be between 1 and 64")
	}
	if cfg.Analysis.TmpDiskBudgetBytes == 0 {
		cfg.Analysis.TmpDiskBudgetBytes = 512 << 20 // 512 MiB
	}
	if cfg.Analysis.TmpDiskBudgetBytes < 1<<20 {
		return Config{}, fmt.Errorf("analysis.tmp_disk_budget_bytes must be at least 1 MiB")
	}
	if cfg.Analysis.OutputDiskBudgetBytes == 0 {
		cfg.Analysis.OutputDiskBudgetBytes = 256 << 20 // 256 MiB
	}
	if cfg.Analysis.OutputDiskBudgetBytes < 1<<20 {
		return Config{}, fmt.Errorf("analysis.output_disk_budget_bytes must be at least 1 MiB")
	}
	return cfg, nil
}

// normalizeWorkspace fills in workspace defaults from Root, resolves
// each non-empty workspace dir, and rejects roots that escape each
// other. Empty Root means "no canonical workspace" — the caller still
// has to supply allowed_artifact_dirs.
func normalizeWorkspace(cfg Config) (Config, error) {
	ws := cfg.Workspace
	if ws.Root != "" {
		root, err := resolveOptionalDir(ws.Root)
		if err != nil {
			return cfg, fmt.Errorf("resolve workspace.root %q: %w", ws.Root, err)
		}
		ws.Root = root
		if ws.PCAPDir == "" {
			ws.PCAPDir = filepath.Join(root, "pcaps")
		}
		if ws.OutputDir == "" {
			ws.OutputDir = filepath.Join(root, "output")
		}
		if ws.TmpDir == "" {
			ws.TmpDir = filepath.Join(root, "tmp")
		}
	}
	for _, slot := range []struct {
		name string
		dir  *string
	}{
		{"workspace.pcap_dir", &ws.PCAPDir},
		{"workspace.output_dir", &ws.OutputDir},
		{"workspace.tmp_dir", &ws.TmpDir},
		{"workspace.keylog_dir", &ws.KeylogDir},
	} {
		if *slot.dir == "" {
			continue
		}
		resolved, err := resolveOptionalDir(*slot.dir)
		if err != nil {
			return cfg, fmt.Errorf("resolve %s %q: %w", slot.name, *slot.dir, err)
		}
		*slot.dir = resolved
	}
	if ws.OutputDir != "" && ws.PCAPDir != "" && samePath(ws.OutputDir, ws.PCAPDir) {
		return cfg, fmt.Errorf("workspace.output_dir must not equal workspace.pcap_dir")
	}
	if ws.TmpDir != "" && ws.PCAPDir != "" && samePath(ws.TmpDir, ws.PCAPDir) {
		return cfg, fmt.Errorf("workspace.tmp_dir must not equal workspace.pcap_dir")
	}
	if ws.OutputDir != "" && ws.PCAPDir != "" && pathContains(ws.PCAPDir, ws.OutputDir) {
		return cfg, fmt.Errorf("workspace.output_dir must not be nested under workspace.pcap_dir; refusing to write derived artifacts under raw pcap input")
	}
	if ws.TmpDir != "" && ws.PCAPDir != "" && pathContains(ws.PCAPDir, ws.TmpDir) {
		return cfg, fmt.Errorf("workspace.tmp_dir must not be nested under workspace.pcap_dir; refusing to write tmp work under raw pcap input")
	}
	// When workspace.root is set, every workspace subdir must remain
	// under root. Otherwise root would be defaults-only, and the
	// "/work is the canonical container shape" claim in CONTAINER.md
	// would not be enforced. Operators who legitimately want subdirs
	// outside one root should leave root empty and configure each
	// subdir explicitly.
	if ws.Root != "" {
		for _, slot := range []struct {
			name string
			dir  string
		}{
			{"workspace.pcap_dir", ws.PCAPDir},
			{"workspace.output_dir", ws.OutputDir},
			{"workspace.tmp_dir", ws.TmpDir},
			{"workspace.keylog_dir", ws.KeylogDir},
		} {
			if slot.dir == "" {
				continue
			}
			if samePath(slot.dir, ws.Root) {
				return cfg, fmt.Errorf("%s must not equal workspace.root; the root is a directory containing the subdirs, not a subdir itself", slot.name)
			}
			if !pathContains(ws.Root, slot.dir) {
				return cfg, fmt.Errorf("%s %q must be nested under workspace.root %q", slot.name, slot.dir, ws.Root)
			}
		}
	}
	cfg.Workspace = ws
	return cfg, nil
}

// resolveExistingDir cleans a path, resolves symlinks, and requires
// the resulting path to exist as a directory. Used for inputs that
// must exist at config-load time (allowed_artifact_dirs, workspace.
// pcap_dir).
func resolveExistingDir(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("not a directory: %s", resolved)
	}
	return filepath.Clean(resolved), nil
}

// resolveOptionalDir cleans + resolves a workspace path. Output and
// tmp dirs may not exist yet at config-load time (the operator may
// rely on `mkdir -p` at first call); this helper tolerates ENOENT but
// still rejects symlink-resolution errors and non-directory paths.
//
// The trickiness is that when the path itself does not exist, we
// still need a stable, symlink-resolved form so the same workspace
// directory always normalizes to the same string regardless of
// whether it has been created yet. We walk up to the deepest existing
// ancestor, EvalSymlinks that, and re-append the missing tail. This
// keeps PCAPDir and (not-yet-existing) OutputDir under the same
// resolved prefix on platforms where /tmp is itself a symlink (e.g.
// macOS /var -> /private/var).
func resolveOptionalDir(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	if info, err := os.Stat(abs); err == nil {
		if !info.IsDir() {
			return "", fmt.Errorf("not a directory: %s", abs)
		}
		resolved, err := filepath.EvalSymlinks(abs)
		if err != nil {
			return "", err
		}
		return filepath.Clean(resolved), nil
	} else if !os.IsNotExist(err) {
		return "", err
	}

	// Path does not exist. Walk up to the nearest existing ancestor
	// and resolve symlinks on that prefix.
	tail := []string{}
	cur := abs
	for {
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", fmt.Errorf("no existing ancestor for %s", abs)
		}
		tail = append([]string{filepath.Base(cur)}, tail...)
		cur = parent
		info, err := os.Stat(cur)
		if err == nil {
			if !info.IsDir() {
				return "", fmt.Errorf("ancestor is not a directory: %s", cur)
			}
			resolved, err := filepath.EvalSymlinks(cur)
			if err != nil {
				return "", err
			}
			return filepath.Clean(filepath.Join(append([]string{resolved}, tail...)...)), nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
	}
}

func samePath(a, b string) bool { return filepath.Clean(a) == filepath.Clean(b) }

// pathContains reports whether `outer` is an ancestor of `inner`. It
// is a strict ancestor check: equal paths return false (handled by
// samePath callers). The check rejects only the escape forms (".",
// ".." anywhere in the path) — a hidden subdir like ".out" is still
// nested under outer, so containment must return true for it.
func pathContains(outer, inner string) bool {
	rel, err := filepath.Rel(outer, inner)
	if err != nil {
		return false
	}
	if filepath.IsAbs(rel) || rel == "" || rel == "." || rel == ".." {
		return false
	}
	if strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

func (c Config) Timeout() time.Duration {
	return time.Duration(c.Analysis.CommandTimeoutSeconds) * time.Second
}
