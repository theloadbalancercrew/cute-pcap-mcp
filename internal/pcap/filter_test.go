package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cute-pcap-mcp/internal/config"
)

func TestValidateFilterInputRejectsBadInputs(t *testing.T) {
	cases := []struct {
		name     string
		input    filterInput
		wantKind string
	}{
		{
			name:     "missing_path",
			input:    filterInput{DisplayFilter: "tcp"},
			wantKind: ErrorKindMissingField,
		},
		{
			name:     "missing_display_filter",
			input:    filterInput{Path: "x"},
			wantKind: ErrorKindMissingField,
		},
		{
			name:     "filter_with_nul",
			input:    filterInput{Path: "x", DisplayFilter: "tcp\x00port"},
			wantKind: ErrorKindValidationFailed,
		},
		{
			name:     "filter_too_long",
			input:    filterInput{Path: "x", DisplayFilter: tooLong(5000)},
			wantKind: ErrorKindValidationFailed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateFilterInput(tc.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if got := classify(err).Kind; got != tc.wantKind {
				t.Fatalf("Kind = %q, want %q", got, tc.wantKind)
			}
		})
	}
}

// TestRunFilterRejectsMissingOutputDir pins the contract: pcap_filter
// requires workspace.output_dir; without it the tool refuses to
// proceed. The previous reviewer flagged the analogous issue on the
// analysis writer; keep the same guarantee here.
func TestRunFilterRejectsMissingOutputDir(t *testing.T) {
	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{t.TempDir()},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = runFilter(t.Context(), ArtifactInfo{Path: "/nope.pcap", SHA256: "deadbeef"}, cfg, "tcp")
	if err == nil {
		t.Fatal("runFilter succeeded without output_dir, want error")
	}
	if !strings.Contains(err.Error(), "workspace.output_dir is not configured") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestRunFilterIntegration exercises the tshark write path end to
// end. Skipped when tshark is not on PATH; CI in M6 will run it.
func TestRunFilterIntegration(t *testing.T) {
	requireCommand(t, "tshark")

	root := t.TempDir()
	pcapDir := filepath.Join(root, "pcaps")
	outputDir := filepath.Join(root, "output")
	if err := os.MkdirAll(pcapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pcap := filepath.Join(pcapDir, "http.pcap")
	if err := os.WriteFile(pcap, syntheticHTTPPcap(), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{pcapDir},
		Workspace: config.WorkspaceConfig{
			OutputDir: outputDir,
		},
		Analysis: config.AnalysisConfig{
			CommandTimeoutSeconds: 10,
			MaxStdoutBytes:        200000,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	source, err := inspectArtifact(pcap, cfg, artifactExpectations{})
	if err != nil {
		t.Fatal(err)
	}

	artifact, count, err := runFilter(t.Context(), source, cfg, "tcp.port == 80")
	if err != nil {
		t.Fatalf("runFilter: %v", err)
	}
	if artifact == nil {
		t.Fatal("artifact = nil")
	}
	if artifact.Kind != OutputArtifactKindFilteredPCAP {
		t.Fatalf("Kind = %q, want %q", artifact.Kind, OutputArtifactKindFilteredPCAP)
	}
	if artifact.ContentType != "application/vnd.tcpdump.pcap" {
		t.Fatalf("ContentType = %q", artifact.ContentType)
	}
	if artifact.SchemaVersion != SchemaVersion {
		t.Fatalf("SchemaVersion = %q", artifact.SchemaVersion)
	}
	if artifact.SizeBytes <= 0 {
		t.Fatalf("SizeBytes = %d, want > 0", artifact.SizeBytes)
	}
	if !strings.HasPrefix(artifact.Path, cfg.Workspace.OutputDir) {
		t.Fatalf("artifact path %q not under output_dir %q", artifact.Path, cfg.Workspace.OutputDir)
	}
	// File on disk must match the reported size + sha256.
	body, err := os.ReadFile(artifact.Path)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(body)) != artifact.SizeBytes {
		t.Fatalf("on-disk size %d != artifact.SizeBytes %d", len(body), artifact.SizeBytes)
	}
	if sha256Hex(body) != artifact.SHA256 {
		t.Fatalf("sha256 mismatch")
	}
	// The synthetic pcap has one HTTP packet; the filter should keep it.
	if count <= 0 {
		t.Logf("packet_count = %d (capinfos may be missing)", count)
	}
}

// TestTSharkHasAnyPacketDistinguishesEmptyFromNonEmpty pins the
// definitive zero-detector that runFilter uses for the
// no_packets_matched decision. The previous capinfos-only count was
// ambiguous: zero from capinfos could mean "really zero packets" or
// "capinfos is missing/failed," and runFilter incorrectly deleted
// valid artifacts in the second case. tsharkHasAnyPacket is the
// always-available signal because runFilter just used tshark to
// write the file.
func TestTSharkHasAnyPacketDistinguishesEmptyFromNonEmpty(t *testing.T) {
	requireCommand(t, "tshark")

	dir := t.TempDir()
	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{dir},
		Analysis: config.AnalysisConfig{
			CommandTimeoutSeconds: 10,
			MaxStdoutBytes:        200000,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Source pcap with a single TCP packet.
	hasPath := filepath.Join(dir, "has.pcap")
	if err := os.WriteFile(hasPath, syntheticHTTPPcap(), 0o600); err != nil {
		t.Fatal(err)
	}
	hasAny, err := tsharkHasAnyPacket(t.Context(), hasPath, cfg)
	if err != nil {
		t.Fatalf("tsharkHasAnyPacket on populated pcap: %v", err)
	}
	if !hasAny {
		t.Fatal("hasAny=false for a pcap with one TCP packet, want true")
	}

	// Now write an empty pcap (libpcap header only, no packet records)
	// and confirm the probe says zero.
	emptyPath := filepath.Join(dir, "empty.pcap")
	if err := os.WriteFile(emptyPath, libpcapHeaderOnly(), 0o600); err != nil {
		t.Fatal(err)
	}
	hasAny, err = tsharkHasAnyPacket(t.Context(), emptyPath, cfg)
	if err != nil {
		t.Fatalf("tsharkHasAnyPacket on empty pcap: %v", err)
	}
	if hasAny {
		t.Fatal("hasAny=true for an empty pcap, want false")
	}
}

// libpcapHeaderOnly emits a 24-byte libpcap header with no packet
// records — the same shape tshark produces when -Y matches zero
// packets.
func libpcapHeaderOnly() []byte {
	var buf bytes.Buffer
	writeLE := func(v any) { _ = binary.Write(&buf, binary.LittleEndian, v) }
	writeLE(uint32(0xa1b2c3d4))
	writeLE(uint16(2))
	writeLE(uint16(4))
	writeLE(int32(0))
	writeLE(uint32(0))
	writeLE(uint32(65535))
	writeLE(uint32(1))
	return buf.Bytes()
}

// TestRunFilterEmitsNoPacketsMatchedOnEmptyResult pins the typed
// no_packets_matched error: a display filter that matches zero
// packets in the source pcap returns the typed kind, removes the
// empty derived pcap, and does not return an OutputArtifact.
func TestRunFilterEmitsNoPacketsMatchedOnEmptyResult(t *testing.T) {
	requireCommand(t, "tshark")

	root := t.TempDir()
	pcapDir := filepath.Join(root, "pcaps")
	outputDir := filepath.Join(root, "output")
	if err := os.MkdirAll(pcapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pcap := filepath.Join(pcapDir, "http.pcap")
	if err := os.WriteFile(pcap, syntheticHTTPPcap(), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{pcapDir},
		Workspace:           config.WorkspaceConfig{OutputDir: outputDir},
		Analysis: config.AnalysisConfig{
			CommandTimeoutSeconds: 10,
			MaxStdoutBytes:        200000,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	source, err := inspectArtifact(pcap, cfg, artifactExpectations{})
	if err != nil {
		t.Fatal(err)
	}

	// The synthetic pcap has only a single TCP packet. A UDP filter
	// matches zero packets.
	_, _, err = runFilter(t.Context(), source, cfg, "udp")
	if !errors.Is(err, errNoPacketsMatched) {
		t.Fatalf("err = %v, want errNoPacketsMatched", err)
	}
	terr := classify(err)
	if terr.Kind != ErrorKindNoPacketsMatched {
		t.Fatalf("classify Kind = %q, want %q", terr.Kind, ErrorKindNoPacketsMatched)
	}
	if terr.Field != "display_filter" {
		t.Fatalf("classify Field = %q, want display_filter", terr.Field)
	}
	// Empty filtered.pcap files must not be left behind.
	matches, _ := filepath.Glob(filepath.Join(outputDir, "*", "filtered.pcap"))
	if len(matches) != 0 {
		t.Fatalf("zero-match runFilter left files behind: %v", matches)
	}
}

// TestRunFilterIntegrationProducesLegacyPCAPFormat pins the
// content-type contract: the derived pcap really is libpcap (-F pcap)
// rather than tshark's pcapng default. The check is the file's
// 4-byte magic — 0xa1b2c3d4 (or its byte-swapped variant) for pcap
// vs 0x0a0d0d0a for pcapng.
func TestRunFilterIntegrationProducesLegacyPCAPFormat(t *testing.T) {
	requireCommand(t, "tshark")

	root := t.TempDir()
	pcapDir := filepath.Join(root, "pcaps")
	outputDir := filepath.Join(root, "output")
	if err := os.MkdirAll(pcapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pcap := filepath.Join(pcapDir, "http.pcap")
	if err := os.WriteFile(pcap, syntheticHTTPPcap(), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{pcapDir},
		Workspace:           config.WorkspaceConfig{OutputDir: outputDir},
		Analysis: config.AnalysisConfig{
			CommandTimeoutSeconds: 10,
			MaxStdoutBytes:        200000,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	source, err := inspectArtifact(pcap, cfg, artifactExpectations{})
	if err != nil {
		t.Fatal(err)
	}
	artifact, _, err := runFilter(t.Context(), source, cfg, "tcp.port == 80")
	if err != nil {
		t.Fatalf("runFilter: %v", err)
	}
	body, err := os.ReadFile(artifact.Path)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) < 4 {
		t.Fatalf("artifact too small: %d bytes", len(body))
	}
	magic := binary.LittleEndian.Uint32(body[:4])
	switch magic {
	case 0xa1b2c3d4, 0xd4c3b2a1: // pcap, either endian
	case 0x0a0d0d0a:
		t.Fatalf("filtered artifact is pcapng, not pcap; tshark -F pcap was not honored")
	default:
		t.Fatalf("unexpected magic 0x%x in filtered artifact", magic)
	}
}

// TestRunFilterEnforcesOutputDiskBudget pins the same disk-budget
// boundary the artifact writer enforces: an over-budget filtered pcap
// is removed before runFilter returns.
func TestRunFilterEnforcesOutputDiskBudget(t *testing.T) {
	requireCommand(t, "tshark")

	root := t.TempDir()
	pcapDir := filepath.Join(root, "pcaps")
	outputDir := filepath.Join(root, "output")
	if err := os.MkdirAll(pcapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pcap := filepath.Join(pcapDir, "http.pcap")
	if err := os.WriteFile(pcap, syntheticHTTPPcap(), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{pcapDir},
		Workspace:           config.WorkspaceConfig{OutputDir: outputDir},
		Analysis: config.AnalysisConfig{
			CommandTimeoutSeconds: 10,
			MaxStdoutBytes:        200000,
			OutputDiskBudgetBytes: 1 << 20, // 1 MiB minimum allowed
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Force the budget down post-normalize to a value smaller than the
	// pcap header tshark will write. config.Normalize would reject
	// values below 1 MiB at load time; this test pokes the in-memory
	// struct to exercise the runtime check.
	cfg.Analysis.OutputDiskBudgetBytes = 24 // smaller than any pcap

	source, err := inspectArtifact(pcap, cfg, artifactExpectations{})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = runFilter(t.Context(), source, cfg, "tcp.port == 80")
	if err == nil {
		t.Fatal("runFilter succeeded over budget, want output_limit_reached")
	}
	if !errors.Is(err, errOutputLimitReached) {
		t.Fatalf("err = %v, want errOutputLimitReached", err)
	}
	if got := classify(err).Kind; got != ErrorKindOutputLimitReached {
		t.Fatalf("Kind = %q", got)
	}
	// Over-budget file must have been removed.
	matches, _ := filepath.Glob(filepath.Join(outputDir, "*", "filtered.pcap"))
	if len(matches) != 0 {
		t.Fatalf("over-budget runFilter left files behind: %v", matches)
	}
}
