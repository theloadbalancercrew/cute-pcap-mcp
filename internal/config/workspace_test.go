package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeFillsWorkspaceDefaultsFromRoot(t *testing.T) {
	root := mustEvalSymlinks(t, t.TempDir())
	cfg, err := Normalize(Config{
		AllowedArtifactDirs: []string{root},
		Workspace:           WorkspaceConfig{Root: root},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Workspace.Root != root {
		t.Fatalf("Root = %q, want %q", cfg.Workspace.Root, root)
	}
	if cfg.Workspace.PCAPDir != filepath.Join(root, "pcaps") {
		t.Fatalf("PCAPDir = %q", cfg.Workspace.PCAPDir)
	}
	if cfg.Workspace.OutputDir != filepath.Join(root, "output") {
		t.Fatalf("OutputDir = %q", cfg.Workspace.OutputDir)
	}
	if cfg.Workspace.TmpDir != filepath.Join(root, "tmp") {
		t.Fatalf("TmpDir = %q", cfg.Workspace.TmpDir)
	}
	// The pcap_dir derived from root must also land in the implicit
	// input allowlist so existing inspectArtifact path checks accept
	// files placed there.
	found := false
	for _, dir := range cfg.AllowedArtifactDirs {
		if dir == cfg.Workspace.PCAPDir {
			found = true
		}
	}
	if !found {
		t.Fatalf("workspace.pcap_dir %q not in AllowedArtifactDirs %v", cfg.Workspace.PCAPDir, cfg.AllowedArtifactDirs)
	}
}

func TestNormalizeRejectsOutputDirNestedUnderPCAPDir(t *testing.T) {
	root := t.TempDir()
	pcaps := filepath.Join(root, "pcaps")
	if err := os.MkdirAll(pcaps, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Normalize(Config{
		AllowedArtifactDirs: []string{root},
		Workspace: WorkspaceConfig{
			PCAPDir:   pcaps,
			OutputDir: filepath.Join(pcaps, "out"),
			TmpDir:    filepath.Join(root, "tmp"),
		},
	})
	if err == nil {
		t.Fatal("Normalize accepted output_dir nested under pcap_dir, want rejection")
	}
	if !strings.Contains(err.Error(), "must not be nested under workspace.pcap_dir") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNormalizeRejectsTmpDirEqualsPCAPDir(t *testing.T) {
	root := t.TempDir()
	pcaps := filepath.Join(root, "pcaps")
	if err := os.MkdirAll(pcaps, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Normalize(Config{
		AllowedArtifactDirs: []string{root},
		Workspace: WorkspaceConfig{
			PCAPDir: pcaps,
			TmpDir:  pcaps,
		},
	})
	if err == nil {
		t.Fatal("Normalize accepted tmp_dir == pcap_dir, want rejection")
	}
}

func TestNormalizeRejectsAllowlistAndWorkspaceBothEmpty(t *testing.T) {
	_, err := Normalize(Config{})
	if err == nil {
		t.Fatal("Normalize accepted empty config, want rejection")
	}
}

func TestNormalizeAllowsWorkspacePCAPDirWithoutAllowlist(t *testing.T) {
	root := mustEvalSymlinks(t, t.TempDir())
	cfg, err := Normalize(Config{
		Workspace: WorkspaceConfig{PCAPDir: root},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.AllowedArtifactDirs) != 1 || cfg.AllowedArtifactDirs[0] != root {
		t.Fatalf("AllowedArtifactDirs = %v, want [%s]", cfg.AllowedArtifactDirs, root)
	}
}

func TestNormalizeRejectsHiddenSubdirNestedUnderPCAPDir(t *testing.T) {
	root := mustEvalSymlinks(t, t.TempDir())
	pcaps := filepath.Join(root, "pcaps")
	if err := os.MkdirAll(pcaps, 0o755); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		workspace WorkspaceConfig
	}{
		{
			name: "hidden_output_dir",
			workspace: WorkspaceConfig{
				PCAPDir:   pcaps,
				OutputDir: filepath.Join(pcaps, ".out"),
				TmpDir:    filepath.Join(root, "tmp"),
			},
		},
		{
			name: "hidden_tmp_dir",
			workspace: WorkspaceConfig{
				PCAPDir:   pcaps,
				OutputDir: filepath.Join(root, "out"),
				TmpDir:    filepath.Join(pcaps, ".tmp"),
			},
		},
		{
			name: "deeply_hidden_output_dir",
			workspace: WorkspaceConfig{
				PCAPDir:   pcaps,
				OutputDir: filepath.Join(pcaps, ".cache", "out"),
				TmpDir:    filepath.Join(root, "tmp"),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Normalize(Config{
				AllowedArtifactDirs: []string{root},
				Workspace:           tc.workspace,
			})
			if err == nil {
				t.Fatal("Normalize accepted hidden subdir nested under pcap_dir, want rejection")
			}
			if !strings.Contains(err.Error(), "must not be nested under workspace.pcap_dir") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestNormalizeRejectsSubdirsOutsideRoot(t *testing.T) {
	root := mustEvalSymlinks(t, t.TempDir())
	outside := mustEvalSymlinks(t, t.TempDir())
	cases := []struct {
		name      string
		workspace WorkspaceConfig
	}{
		{
			name: "tmp_dir_outside",
			workspace: WorkspaceConfig{
				Root:    root,
				PCAPDir: filepath.Join(root, "pcaps"),
				TmpDir:  filepath.Join(outside, "tmp"),
			},
		},
		{
			name: "output_dir_outside",
			workspace: WorkspaceConfig{
				Root:      root,
				PCAPDir:   filepath.Join(root, "pcaps"),
				OutputDir: filepath.Join(outside, "out"),
			},
		},
		{
			name: "pcap_dir_outside",
			workspace: WorkspaceConfig{
				Root:    root,
				PCAPDir: filepath.Join(outside, "pcaps"),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Normalize(Config{
				AllowedArtifactDirs: []string{root},
				Workspace:           tc.workspace,
			})
			if err == nil {
				t.Fatal("Normalize accepted subdir outside root, want rejection")
			}
			if !strings.Contains(err.Error(), "must be nested under workspace.root") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestNormalizeRejectsSubdirEqualToRoot(t *testing.T) {
	root := mustEvalSymlinks(t, t.TempDir())
	_, err := Normalize(Config{
		AllowedArtifactDirs: []string{root},
		Workspace: WorkspaceConfig{
			Root:    root,
			PCAPDir: root,
		},
	})
	if err == nil {
		t.Fatal("Normalize accepted pcap_dir == root, want rejection")
	}
}

func mustEvalSymlinks(t *testing.T, p string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", p, err)
	}
	return filepath.Clean(resolved)
}

func TestNormalizeRejectsResourceBudgetsOutOfRange(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{
			name: "max_pcap_bytes_too_small",
			cfg: Config{
				AllowedArtifactDirs: []string{"."},
				Analysis:            AnalysisConfig{MaxPCAPBytes: 1024},
			},
		},
		{
			name: "max_concurrent_too_low",
			cfg: Config{
				AllowedArtifactDirs:   []string{"."},
				Analysis:              AnalysisConfig{MaxConcurrentAnalyses: -1},
			},
		},
		{
			name: "max_concurrent_too_high",
			cfg: Config{
				AllowedArtifactDirs: []string{"."},
				Analysis:            AnalysisConfig{MaxConcurrentAnalyses: 65},
			},
		},
		{
			name: "tmp_budget_too_small",
			cfg: Config{
				AllowedArtifactDirs: []string{"."},
				Analysis:            AnalysisConfig{TmpDiskBudgetBytes: 1024},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Normalize(tc.cfg); err == nil {
				t.Fatal("Normalize accepted out-of-range value, want rejection")
			}
		})
	}
}

func TestNormalizeAppliesResourceDefaults(t *testing.T) {
	cfg, err := Normalize(Config{AllowedArtifactDirs: []string{"."}})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Analysis.MaxPCAPBytes != 1<<30 {
		t.Fatalf("MaxPCAPBytes = %d", cfg.Analysis.MaxPCAPBytes)
	}
	if cfg.Analysis.MaxConcurrentAnalyses != 2 {
		t.Fatalf("MaxConcurrentAnalyses = %d", cfg.Analysis.MaxConcurrentAnalyses)
	}
	if cfg.Analysis.TmpDiskBudgetBytes != 512<<20 {
		t.Fatalf("TmpDiskBudgetBytes = %d", cfg.Analysis.TmpDiskBudgetBytes)
	}
	if cfg.Analysis.OutputDiskBudgetBytes != 256<<20 {
		t.Fatalf("OutputDiskBudgetBytes = %d", cfg.Analysis.OutputDiskBudgetBytes)
	}
}
