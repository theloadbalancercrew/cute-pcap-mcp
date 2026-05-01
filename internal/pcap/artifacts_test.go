package pcap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cute-pcap-mcp/internal/config"
)

// TestWriteAnalysisArtifactsLandsUnderOutputDir pins the writer's
// directory layout, file content types, sha256 verification, and
// schema-version stamping.
func TestWriteAnalysisArtifactsLandsUnderOutputDir(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "output")
	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{root},
		Workspace:           config.WorkspaceConfig{OutputDir: output},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Read back the normalized output_dir for the prefix check; the
	// normalizer resolves symlinks (on macOS /var → /private/var) so
	// the test must compare against the resolved form.
	output = cfg.Workspace.OutputDir

	out := analyzeOutput{
		SchemaVersion: SchemaVersion,
		Artifact: ArtifactInfo{
			Path:      "/work/pcaps/example.pcap",
			SizeBytes: 4096,
			SHA256:    "deadbeefcafebabe0000000000000000000000000000000000000000000000aa",
		},
		CaptureSummary: &CaptureSummary{PacketCount: 7, DurationSeconds: 0.0001, Raw: "Number of packets: 7\n"},
		Findings: []PacketFinding{{
			Code: FindingAnalysisGenerated, Severity: "info", Message: "ok",
		}},
	}

	written, err := writeAnalysisArtifacts(cfg, out)
	if err != nil {
		t.Fatalf("writeAnalysisArtifacts: %v", err)
	}
	if got, want := len(written), 2; got != want {
		t.Fatalf("len(written) = %d, want %d", got, want)
	}

	var jsonArt, mdArt OutputArtifact
	for _, a := range written {
		switch a.Kind {
		case OutputArtifactKindAnalysisJSON:
			jsonArt = a
		case OutputArtifactKindSummaryMarkdown:
			mdArt = a
		}
	}

	for _, a := range []OutputArtifact{jsonArt, mdArt} {
		if a.Path == "" {
			t.Fatalf("missing path: %#v", a)
		}
		if !strings.HasPrefix(a.Path, output) {
			t.Fatalf("artifact path %q not under output_dir %q", a.Path, output)
		}
		if a.SchemaVersion != SchemaVersion {
			t.Fatalf("SchemaVersion = %q, want %q", a.SchemaVersion, SchemaVersion)
		}
		if a.GeneratedAt == "" {
			t.Fatal("GeneratedAt is empty")
		}
		body, err := os.ReadFile(a.Path)
		if err != nil {
			t.Fatalf("read %s: %v", a.Path, err)
		}
		if int64(len(body)) != a.SizeBytes {
			t.Fatalf("SizeBytes = %d, on-disk = %d", a.SizeBytes, len(body))
		}
		sum := sha256.Sum256(body)
		if hex.EncodeToString(sum[:]) != a.SHA256 {
			t.Fatalf("SHA256 mismatch for %s", a.Path)
		}
	}

	if jsonArt.ContentType != "application/json" {
		t.Fatalf("json ContentType = %q", jsonArt.ContentType)
	}
	if mdArt.ContentType != "text/markdown" {
		t.Fatalf("md ContentType = %q", mdArt.ContentType)
	}

	// analysis.json must round-trip through the wire shape.
	var roundtrip analyzeOutput
	body, err := os.ReadFile(jsonArt.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &roundtrip); err != nil {
		t.Fatalf("analysis.json is not valid JSON: %v", err)
	}
	if roundtrip.SchemaVersion != SchemaVersion {
		t.Fatalf("round-trip SchemaVersion = %q", roundtrip.SchemaVersion)
	}
	// The writer must clear out.Artifacts before serializing so the
	// JSON content is stable on re-read.
	if len(roundtrip.Artifacts) != 0 {
		t.Fatalf("analysis.json contains a self-pointer Artifacts list: %v", roundtrip.Artifacts)
	}

	// summary.md must reference the schema version + sha256 prefix.
	mdBody, err := os.ReadFile(mdArt.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mdBody), SchemaVersion) {
		t.Fatalf("summary.md missing schema version")
	}
	if !strings.Contains(string(mdBody), out.Artifact.SHA256) {
		t.Fatalf("summary.md missing input pcap sha256")
	}
}

// TestWriteAnalysisArtifactsRequiresOutputDir pins the boundary: the
// writer never falls back to the OS default tmp.
func TestWriteAnalysisArtifactsRequiresOutputDir(t *testing.T) {
	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{t.TempDir()},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = writeAnalysisArtifacts(cfg, analyzeOutput{})
	if err == nil {
		t.Fatal("writeAnalysisArtifacts succeeded without output_dir, want error")
	}
}

// TestCaptureIDForReruns verifies same-pcap re-runs land in distinct
// dirs (timestamp suffix) so evidence diffs across runs are
// preserved.
func TestCaptureIDForReruns(t *testing.T) {
	first := captureIDFor("abc123def456", time.Date(2026, 4, 29, 10, 0, 0, 0, time.UTC))
	second := captureIDFor("abc123def456", time.Date(2026, 4, 29, 10, 0, 1, 0, time.UTC))
	if first == second {
		t.Fatalf("captureIDFor returned identical IDs across timestamps: %s", first)
	}
	if !strings.HasPrefix(first, "abc123def456-") {
		t.Fatalf("captureIDFor missing sha256 prefix: %s", first)
	}
}

// TestSameSecondRerunsLandInDistinctDirs pins the collision-retry
// behaviour so two analyses fired in the same UTC second cannot
// overwrite each other's analysis.json / summary.md. The original
// reviewer noted this is reachable under the default
// max_concurrent_analyses=2 cap.
func TestSameSecondRerunsLandInDistinctDirs(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 4, 29, 10, 0, 0, 0, time.UTC)
	sha := "deadbeefcafe"

	first, err := makeUniqueCaptureDir(root, sha, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := makeUniqueCaptureDir(root, sha, now)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("makeUniqueCaptureDir returned the same path twice: %s", first)
	}
	for _, dir := range []string{first, second} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("stat %s: %v", dir, err)
		}
		if !info.IsDir() {
			t.Fatalf("%s is not a directory", dir)
		}
	}
}

// TestWriteAnalysisArtifactsHonorsDiskBudget pins the
// output_disk_budget_bytes enforcement: the renderer measures both
// bodies in memory and emits output_limit_reached without writing
// anything when the budget would be exceeded.
func TestWriteAnalysisArtifactsHonorsDiskBudget(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "output")
	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{root},
		Workspace:           config.WorkspaceConfig{OutputDir: output},
		Analysis: config.AnalysisConfig{
			OutputDiskBudgetBytes: 1 << 20, // 1 MiB
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Stuff a giant string into a metadata field to drive the
	// rendered JSON over the budget.
	huge := strings.Repeat("x", 2*1024*1024)
	out := analyzeOutput{
		SchemaVersion: SchemaVersion,
		Artifact: ArtifactInfo{
			Path: "/work/pcaps/x.pcap", SizeBytes: 1, SHA256: "deadbeef",
		},
		Metadata: map[string]string{"oversize_test_payload": huge},
	}

	_, err = writeAnalysisArtifacts(cfg, out)
	if err == nil {
		t.Fatal("writeAnalysisArtifacts succeeded over budget, want output_limit_reached")
	}
	if got := classify(err).Kind; got != ErrorKindOutputLimitReached {
		t.Fatalf("classify Kind = %q, want %q", got, ErrorKindOutputLimitReached)
	}

	// Filesystem must be untouched: no analysis.json / summary.md
	// landed under output_dir on the over-budget path.
	matches, _ := filepath.Glob(filepath.Join(cfg.Workspace.OutputDir, "*", "*"))
	if len(matches) != 0 {
		t.Fatalf("over-budget call wrote files anyway: %v", matches)
	}
}
