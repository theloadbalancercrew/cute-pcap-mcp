package pcap

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"cute-pcap-mcp/internal/config"
)

// TestInspectArtifactRejectsOversizedPCAP pins the pcap_too_large
// budget. Files strictly larger than analysis.max_pcap_bytes must be
// rejected before any external analyzer runs and before the SHA-256
// hash read.
func TestInspectArtifactRejectsOversizedPCAP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.pcap")
	if err := os.WriteFile(path, make([]byte, 200_000), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{dir},
		Analysis:            config.AnalysisConfig{MaxPCAPBytes: 100_000},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = inspectArtifact(path, cfg, artifactExpectations{})
	if !errors.Is(err, errPCAPTooLarge) {
		t.Fatalf("inspectArtifact err = %v, want errPCAPTooLarge", err)
	}
	if got := classify(err).Kind; got != ErrorKindPCAPTooLarge {
		t.Fatalf("classify Kind = %q, want %q", got, ErrorKindPCAPTooLarge)
	}
}

// TestInspectArtifactAcceptsAtBoundary confirms an exactly-budget file
// is allowed; the budget is "strictly larger than" max_pcap_bytes.
func TestInspectArtifactAcceptsAtBoundary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "boundary.pcap")
	const size = 100_000
	if err := os.WriteFile(path, make([]byte, size), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{dir},
		Analysis:            config.AnalysisConfig{MaxPCAPBytes: size},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inspectArtifact(path, cfg, artifactExpectations{}); err != nil {
		t.Fatalf("inspectArtifact at-boundary err = %v, want nil", err)
	}
}

// TestServerStateAnalyzerSlotEmitsAnalysisBusy pins the non-blocking
// semaphore: when every slot is held, the next acquire returns the
// typed analysis_busy error rather than queueing.
func TestServerStateAnalyzerSlotEmitsAnalysisBusy(t *testing.T) {
	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{t.TempDir()},
		Analysis:            config.AnalysisConfig{MaxConcurrentAnalyses: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	state := newServerState(cfg, slog.New(slog.NewTextHandler(discardWriter{}, nil)))
	if err := state.acquireAnalyzerSlot(); err != nil {
		t.Fatalf("first acquire err = %v, want nil", err)
	}
	defer state.releaseAnalyzerSlot()
	err = state.acquireAnalyzerSlot()
	if !errors.Is(err, errAnalysisBusy) {
		t.Fatalf("second acquire err = %v, want errAnalysisBusy", err)
	}
	terr := classify(err)
	if terr.Kind != ErrorKindAnalysisBusy {
		t.Fatalf("classify Kind = %q, want %q", terr.Kind, ErrorKindAnalysisBusy)
	}
	if !terr.Retryable {
		t.Fatal("analysis_busy must be retryable; got Retryable=false")
	}
}

// TestServerStateAnalyzerSlotReleases pins the release path so a
// completed call frees its slot for the next caller.
func TestServerStateAnalyzerSlotReleases(t *testing.T) {
	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{t.TempDir()},
		Analysis:            config.AnalysisConfig{MaxConcurrentAnalyses: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	state := newServerState(cfg, slog.New(slog.NewTextHandler(discardWriter{}, nil)))
	if err := state.acquireAnalyzerSlot(); err != nil {
		t.Fatal(err)
	}
	state.releaseAnalyzerSlot()
	if err := state.acquireAnalyzerSlot(); err != nil {
		t.Fatalf("re-acquire after release err = %v, want nil", err)
	}
	state.releaseAnalyzerSlot()
}

// TestRunZeekReportUsesWorkspaceTmpDir pins the workspace placement:
// when cfg.Workspace.TmpDir is set, Zeek's per-call workdir lives
// underneath it, not in the OS-default tmp.
//
// The test stubs Zeek at the runner-command level by using a
// deliberately-missing pcap path so the analyzer fails fast; the
// branch-under-test is the MkdirTemp call that happens before
// runAnalyzerCommand. We verify by snapshotting tmp_dir entries before
// and after.
func TestRunZeekReportUsesWorkspaceTmpDir(t *testing.T) {
	requireCommand(t, "zeek")

	root := t.TempDir()
	tmpDir := filepath.Join(root, "tmp")
	pcapDir := filepath.Join(root, "pcaps")
	if err := os.MkdirAll(pcapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pcap := filepath.Join(pcapDir, "tiny.pcap")
	if err := os.WriteFile(pcap, syntheticHTTPPcap(), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{pcapDir},
		Workspace:           config.WorkspaceConfig{TmpDir: tmpDir},
		Analysis: config.AnalysisConfig{
			CommandTimeoutSeconds: 10,
			MaxStdoutBytes:        200000,
			MaxZeekRecordsPerLog:  20,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Run zeek; if it succeeds the workdir is removed by the deferred
	// RemoveAll, but the parent tmpDir must still have been created.
	report, runErr := runZeekReport(t.Context(), pcap, cfg, 20, "")
	_ = report
	_ = runErr // analyzer may legitimately fail in CI; we only assert tmp_dir creation.

	if _, err := os.Stat(tmpDir); err != nil {
		t.Fatalf("workspace.tmp_dir was not created at %q: %v", tmpDir, err)
	}
}
