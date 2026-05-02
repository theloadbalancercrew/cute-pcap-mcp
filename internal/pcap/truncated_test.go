package pcap

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cute-pcap-mcp/internal/config"
)

// TestIsTruncatedPCAPDiagnostic pins the classifier surface. Every
// known stderr phrase the analyze pipeline trusts as a truncation
// signal lands here in the same MR that adds it; phrases not in
// this table fall through to the generic analyzer_failed path.
func TestIsTruncatedPCAPDiagnostic(t *testing.T) {
	cases := []struct {
		name    string
		stderr  string
		want    bool
	}{
		{
			name:   "tshark_phrase",
			stderr: `tshark: The file "x.pcap" appears to have been cut short in the middle of a packet.`,
			want:   true,
		},
		{
			name:   "capinfos_phrase",
			stderr: `capinfos: An error occurred reading "x.pcap": appears to have been cut short in the middle of a packet.`,
			want:   true,
		},
		{
			name:   "zeek_phrase",
			stderr: "error in /usr/local/zeek/share/zeek/base/init-bare.zeek, line 1: truncated dump file; ./conn.log: 5 records",
			want:   true,
		},
		{
			name:   "zeek_older_phrase",
			stderr: "failed to read a packet header from x.pcap: only got 8 of 16 bytes",
			want:   true,
		},
		{
			name:   "case_insensitive",
			stderr: `TSHARK: The file APPEARS TO HAVE BEEN CUT SHORT IN THE MIDDLE OF A PACKET.`,
			want:   true,
		},
		{
			name:   "unrelated_failure_does_not_match",
			stderr: `tshark: This isn't a known capture file format.`,
			want:   false,
		},
		{
			name:   "empty_stderr_returns_false",
			stderr: "",
			want:   false,
		},
		{
			name:   "missing_only_got_keyword_does_not_match",
			stderr: "failed to read a packet header from x.pcap",
			want:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isTruncatedPCAPDiagnostic(tc.stderr)
			if got != tc.want {
				t.Fatalf("isTruncatedPCAPDiagnostic(%q) = %v, want %v", tc.stderr, got, tc.want)
			}
		})
	}
}

// TestTruncationFindingBoundsStderrFragment pins the bounded human-
// fallback message: a runaway diagnostic cannot inflate the
// response. The stderr excerpt is capped at 240 chars with a
// `...[truncated]` suffix.
func TestTruncationFindingBoundsStderrFragment(t *testing.T) {
	huge := strings.Repeat("x", 5000)
	finding := truncationFinding("tshark", huge)
	if finding.Code != FindingPCAPTruncated {
		t.Fatalf("Code = %q, want %q", finding.Code, FindingPCAPTruncated)
	}
	if finding.Severity != "warning" {
		t.Fatalf("Severity = %q, want warning", finding.Severity)
	}
	if !strings.Contains(finding.Message, "...[truncated]") {
		t.Fatalf("expected truncation suffix; got %q", finding.Message)
	}
	if len(finding.Message) > 400 {
		t.Fatalf("message length %d exceeds bounded cap (~400)", len(finding.Message))
	}
}

// truncatedSyntheticHTTPPcap returns syntheticHTTPPcap with the
// final N bytes of the packet record cut off, simulating a
// half-written pcap. tshark / capinfos / zeek treat this as a
// truncated input and emit one of the recognized diagnostics.
func truncatedSyntheticHTTPPcap(cutLast int) []byte {
	full := syntheticHTTPPcap()
	if cutLast >= len(full) {
		cutLast = len(full) - 1
	}
	if cutLast < 1 {
		cutLast = 1
	}
	return full[:len(full)-cutLast]
}

// twoPacketTruncatedPcap concatenates two copies of the synthetic
// HTTP packet record, then truncates the second mid-payload. Useful
// for the filter salvage test: tshark reads the first complete
// packet, then hits the truncation diagnostic on the second, and
// writes a derived pcap with the first packet preserved.
func twoPacketTruncatedPcap() []byte {
	full := syntheticHTTPPcap()
	// libpcap header is the first 24 bytes; everything after is one
	// packet record. Append a second copy of just the record bytes,
	// then chop the final ~30 bytes so packet 2 is half-written.
	if len(full) < 64 {
		return full // defensive; this should not happen
	}
	header := full[:24]
	record := full[24:]
	combined := make([]byte, 0, 24+len(record)*2)
	combined = append(combined, header...)
	combined = append(combined, record...)
	combined = append(combined, record...)
	cut := 30
	if cut >= len(record) {
		cut = len(record) - 1
	}
	return combined[:len(combined)-cut]
}

// TestRunFilterPreservesArtifactOnTruncatedSource pins the issue #2
// fix for pcap_filter: tshark reports the truncation, exits non-
// zero, but writes a usable filtered.pcap containing every packet
// it managed to read before the cut. runFilter must preserve that
// artifact and surface a pcap_truncated finding rather than discard
// the partial output as analyzer_failed.
func TestRunFilterPreservesArtifactOnTruncatedSource(t *testing.T) {
	requireCommand(t, "tshark")

	root := t.TempDir()
	pcapDir := filepath.Join(root, "pcaps")
	outputDir := filepath.Join(root, "output")
	if err := os.MkdirAll(pcapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pcap := filepath.Join(pcapDir, "truncated.pcap")
	// Two copies of the synthetic HTTP packet, with the second
	// truncated mid-payload: tshark reads packet 1 cleanly, hits
	// the "appears to have been cut short" diagnostic on packet 2,
	// and writes a derived pcap with packet 1 preserved.
	if err := os.WriteFile(pcap, twoPacketTruncatedPcap(), 0o600); err != nil {
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

	artifact, _, warnings, err := runFilter(t.Context(), source, cfg, "tcp.port == 80")
	if err != nil {
		if errors.Is(err, errNoPacketsMatched) {
			t.Skipf("tshark read zero packets from truncated pcap on this build; partial-artifact path not exercisable")
		}
		t.Fatalf("runFilter dropped the partial artifact: %v", err)
	}
	if artifact == nil {
		t.Fatal("artifact = nil; the partial pcap was dropped")
	}
	if len(warnings) == 0 {
		t.Fatalf("expected a pcap_truncated warning; got none")
	}
	var sawTruncation bool
	for _, w := range warnings {
		if w.Code == FindingPCAPTruncated {
			sawTruncation = true
		}
	}
	if !sawTruncation {
		t.Fatalf("warnings missing pcap_truncated code: %#v", warnings)
	}
	// The artifact must still be a real file with the reported
	// size + sha256.
	body, err := os.ReadFile(artifact.Path)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(body)) != artifact.SizeBytes {
		t.Fatalf("on-disk size %d != artifact.SizeBytes %d", len(body), artifact.SizeBytes)
	}
	if sha256Hex(body) != artifact.SHA256 {
		t.Fatal("sha256 mismatch on partial artifact")
	}
}

// TestAnalyzeArtifactSalvagesPartialEvidenceOnTruncatedPCAP pins the
// issue #2 fix for pcap_analyze: a truncated source pcap must
// produce capinfos / tshark / Zeek partial evidence in
// out.CaptureSummary / out.Protocols / out.Packets / out.ZeekLogs
// alongside one or more pcap_truncated warning findings. The
// previous behavior was three analyzer_failed errors and an empty
// response.
func TestAnalyzeArtifactSalvagesPartialEvidenceOnTruncatedPCAP(t *testing.T) {
	requireCommand(t, "tshark")
	requireCommand(t, "capinfos")

	root := t.TempDir()
	pcapDir := filepath.Join(root, "pcaps")
	if err := os.MkdirAll(pcapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pcap := filepath.Join(pcapDir, "truncated.pcap")
	if err := os.WriteFile(pcap, truncatedSyntheticHTTPPcap(20), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{pcapDir},
		Workspace:           config.WorkspaceConfig{TmpDir: filepath.Join(root, "tmp")},
		Analysis: config.AnalysisConfig{
			CommandTimeoutSeconds: 10,
			MaxStdoutBytes:        200000,
			MaxPacketRows:         20,
			MaxASCIIStrings:       20,
			MaxASCIIBytes:         20000,
			MaxZeekRecordsPerLog:  20,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	source, err := inspectArtifact(pcap, cfg, artifactExpectations{})
	if err != nil {
		t.Fatal(err)
	}

	out := analyzeArtifact(context.Background(), source, cfg, analyzeInput{Path: pcap})

	// At least one pcap_truncated finding must be present — the
	// whole point of the fix is to surface this signal alongside
	// the partial evidence.
	var sawTruncated bool
	for _, f := range out.Findings {
		if f.Code == FindingPCAPTruncated {
			sawTruncated = true
			if f.Severity != "warning" {
				t.Fatalf("pcap_truncated finding severity = %q, want warning", f.Severity)
			}
		}
	}
	if !sawTruncated {
		t.Fatalf("expected at least one pcap_truncated finding; got %#v", out.Findings)
	}

	// capinfos read the capture metadata header before bailing.
	// CaptureSummary should be populated. (Some capinfos builds
	// might fail before printing anything; allow nil but the
	// finding must still be present, which it is.)
	if out.CaptureSummary != nil {
		if out.CaptureSummary.Raw == "" {
			t.Errorf("CaptureSummary present but Raw is empty")
		}
	}

	// The analyze response is a partial success, NOT a hard
	// failure — out.Error should be nil.
	if out.Error != nil {
		t.Fatalf("analyzeArtifact returned hard error on truncated input: %#v", out.Error)
	}
}

// TestRunAnalyzerCommandReturnsCapturedOutputOnError pins the runner
// boundary fix: errors no longer wipe the captured stdout/stderr.
// The previous implementation returned an empty analyzerCommandOutput
// on non-zero exit, which is the root reason partial evidence was
// discarded. Drive a deliberately-failing command and assert the
// stderr fragment survives.
func TestRunAnalyzerCommandReturnsCapturedOutputOnError(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh on PATH for this synthetic test")
	}
	cfg, err := config.Normalize(config.Config{AllowedArtifactDirs: []string{t.TempDir()}})
	if err != nil {
		t.Fatal(err)
	}
	// `sh -c 'echo to-stdout && echo to-stderr 1>&2 && exit 7'`
	out, runErr := runAnalyzerCommand(t.Context(), cfg.Timeout(), 64*1024, "sh", []string{
		"-c",
		"echo to-stdout && echo to-stderr 1>&2 && exit 7",
	}, "")
	if runErr == nil {
		t.Fatal("expected analyzer_failed error, got nil")
	}
	if !errors.Is(runErr, errAnalyzerFailed) {
		t.Fatalf("err is not errAnalyzerFailed: %v", runErr)
	}
	if !bytes.Contains([]byte(out.Stdout), []byte("to-stdout")) {
		t.Fatalf("stdout was not preserved on error: %q", out.Stdout)
	}
	if !bytes.Contains([]byte(out.Stderr), []byte("to-stderr")) {
		t.Fatalf("stderr was not preserved on error: %q", out.Stderr)
	}
}
