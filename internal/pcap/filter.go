package pcap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cute-pcap-mcp/internal/config"
)

// filterInput is the wire shape for pcap_filter. The display filter
// is required: the tool's reason to exist is producing a derived
// pcap with a known scope, so a filter-less call would just be a
// copy.
type filterInput struct {
	Path              string `json:"path" jsonschema:"absolute or relative path to a pcap/pcapng under an allowed artifact directory"`
	DisplayFilter     string `json:"display_filter" jsonschema:"tshark display filter applied to the source capture; the filtered packets are written to the derived pcap"`
	ExpectedSHA256    string `json:"expected_sha256,omitempty" jsonschema:"optional caller-provided sha256 from an external artifact reference; must be exactly 64 hex digits if set; mismatched values return the typed hash_mismatch error"`
	ExpectedSizeBytes *int64 `json:"expected_size_bytes,omitempty" jsonschema:"optional caller-provided file size in bytes from an external artifact reference; must be non-negative if set; mismatched values return the typed size_mismatch error"`
}

// filterOutput is the wire shape for pcap_filter. Source identifies
// the input pcap; Artifact is the derived pcap reference. The path on
// Artifact is server-generated under workspace.output_dir; callers
// cannot pick a destination.
type filterOutput struct {
	SchemaVersion string          `json:"schema_version"`
	Source        ArtifactInfo    `json:"source"`
	Artifact      *OutputArtifact `json:"artifact,omitempty"`
	PacketCount   int64           `json:"packet_count,omitempty"`
	DisplayFilter string          `json:"display_filter,omitempty"`
	Findings      []PacketFinding `json:"findings"`
	Errors        []toolError     `json:"errors,omitempty"`
	Error         *toolError      `json:"error,omitempty"`
}

func filterErrorOutput(source ArtifactInfo, terr toolError) filterOutput {
	return filterOutput{
		SchemaVersion: SchemaVersion,
		Source:        source,
		Error:         &terr,
	}
}

// filterErrorOutputWithFindings is filterErrorOutput plus a list of
// warning findings that must survive even on the error path. The
// no_packets_matched-on-truncated-source case uses this so
// `pcap_truncated` warnings are not silently dropped by the error
// handler — without them a host would see "no matches" without
// knowing the verdict only covers the readable prefix.
func filterErrorOutputWithFindings(source ArtifactInfo, terr toolError, findings []PacketFinding) filterOutput {
	return filterOutput{
		SchemaVersion: SchemaVersion,
		Source:        source,
		Findings:      findings,
		Error:         &terr,
	}
}

// validateFilterInput pins the input shape: path required,
// display_filter required (non-empty), bounded length, no NUL bytes.
// Reuses the shared ValidationReason* tokens.
func validateFilterInput(input filterInput) error {
	if input.Path == "" {
		return missingFieldError("path")
	}
	df := strings.TrimSpace(input.DisplayFilter)
	if df == "" {
		return missingFieldError("display_filter")
	}
	if strings.ContainsRune(df, '\x00') {
		return validationError("display_filter", ValidationReasonContainsNUL, "display_filter must not contain NUL bytes")
	}
	if len(df) > 4096 {
		return validationError("display_filter", ValidationReasonTooLong, "display_filter must be 4096 bytes or less")
	}
	return nil
}

// runFilter is the workhorse for pcap_filter. It writes the filtered
// pcap under workspace.output_dir using a server-generated path
// (operator never picks the destination), then re-stats + hashes the
// file to populate the OutputArtifact wire shape. Packet count is
// best-effort via capinfos -c; if that analyzer is missing the count
// stays at zero and the output still carries the artifact reference.
//
// The third return is the list of pcap_truncated warning findings
// the call should surface alongside the artifact. tshark exits non-
// zero on a truncated source pcap but still writes the readable
// prefix into the derived pcap; runFilter detects that case via the
// known stderr phrase and preserves the partial artifact.
func runFilter(ctx context.Context, source ArtifactInfo, cfg config.Config, displayFilter string) (*OutputArtifact, int64, []PacketFinding, error) {
	if cfg.Workspace.OutputDir == "" {
		return nil, 0, nil, fmt.Errorf("%w: workspace.output_dir is not configured; pcap_filter requires an output workspace", errAnalyzerFailed)
	}
	if err := os.MkdirAll(cfg.Workspace.OutputDir, 0o700); err != nil {
		return nil, 0, nil, fmt.Errorf("%w: prepare workspace.output_dir: %v", errAnalyzerFailed, err)
	}

	now := time.Now().UTC()
	dir, err := makeUniqueCaptureDir(cfg.Workspace.OutputDir, source.SHA256, now)
	if err != nil {
		return nil, 0, nil, err
	}
	outPath := filepath.Join(dir, "filtered.pcap")

	out, err := runAnalyzerCommand(ctx, cfg.Timeout(), cfg.Analysis.MaxStdoutBytes, "tshark", []string{
		"-n",
		"-r", source.Path,
		"-Y", displayFilter,
		// -F pcap forces the legacy pcap (libpcap) write format so the
		// artifact really is what content_type advertises. tshark's
		// -w default is pcapng, which would put pcapng bytes behind a
		// pcap content type.
		"-F", "pcap",
		"-w", outPath,
	}, "")
	var warnings []PacketFinding
	if err != nil {
		// tshark stderr fragments for filter rejection are
		// classified into invalid_filter via isTSharkFilterError so
		// the caller sees a typed input-validation kind, not a
		// generic analyzer_failed.
		if isTSharkFilterError(err) {
			return nil, 0, nil, invalidFilterError(strings.TrimPrefix(err.Error(), errAnalyzerFailed.Error()+": "))
		}
		// Truncated source pcap: tshark exits non-zero (typically
		// status 14 with the "appears to have been cut short"
		// diagnostic), but it still wrote a readable filtered.pcap
		// containing every packet it managed to read before the
		// truncation. Preserve the artifact and surface a typed
		// pcap_truncated warning rather than discarding the partial
		// output as analyzer_failed.
		//
		// Restrict tolerance to errAnalyzerFailed so a timeout or
		// analyzer-unavailable error keeps its typed kind even if
		// stderr happens to contain a truncation phrase.
		if errors.Is(err, errAnalyzerFailed) && isTruncatedPCAPDiagnostic(out.Stderr) {
			warnings = append(warnings, truncationFinding("tshark", out.Stderr))
		} else {
			return nil, 0, nil, err
		}
	}

	info, err := os.Stat(outPath)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("%w: stat filtered pcap: %v", errAnalyzerFailed, err)
	}

	// Check the disk budget against the on-disk size BEFORE reading
	// the file into memory for hashing. Reading first would
	// memory-spike on a large derived pcap before the typed
	// output_limit_reached error returns; the stat-then-budget order
	// keeps the boundary observable without the spike.
	if budget := cfg.Analysis.OutputDiskBudgetBytes; budget > 0 && info.Size() > budget {
		// Remove the over-budget file so the workspace is not left
		// holding it.
		_ = os.Remove(outPath)
		_ = os.Remove(dir)
		return nil, 0, nil, fmt.Errorf("%w: filtered pcap is %d bytes; exceeds analysis.output_disk_budget_bytes (%d)",
			errOutputLimitReached, info.Size(), budget)
	}

	body, err := os.ReadFile(outPath)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("%w: read filtered pcap for hash: %v", errAnalyzerFailed, err)
	}

	// Two-step packet-count flow keeps the no_packets_matched check
	// honest when capinfos is missing:
	//
	//   1. tsharkHasAnyPacket is the *definitive* zero check. We
	//      already require tshark (it just wrote the file), so it's
	//      always available. If tshark reports zero packets, the
	//      filter genuinely matched nothing.
	//   2. countPacketsWithCapinfos is the *best-effort exact count*
	//      reported on the artifact. If capinfos is missing or fails,
	//      packet_count stays at zero — but we never delete the
	//      derived pcap on that signal alone.
	hasAny, err := tsharkHasAnyPacket(ctx, outPath, cfg)
	if err != nil {
		return nil, 0, nil, err
	}
	if !hasAny {
		// Empty filter result: tshark confirmed zero matching packets.
		// Surface as the typed no_packets_matched error so
		// orchestration can branch on "filter didn't hit" without
		// re-reading the file. Remove the empty artifact so the
		// workspace is not littered with header-only files.
		_ = os.Remove(outPath)
		_ = os.Remove(dir)
		// When the source pcap was truncated, "no matches" is only
		// known for the readable prefix — matches after the
		// truncation point are unobservable. Surface the
		// pcap_truncated warning(s) the caller already collected
		// and clarify the message so orchestration does not over-
		// trust a "no match" verdict on a partial input.
		if len(warnings) > 0 {
			return nil, 0, warnings, fmt.Errorf(
				"%w: display filter %q produced zero packets in the readable prefix; matches after the truncation point are unknown",
				errNoPacketsMatched, displayFilter)
		}
		return nil, 0, nil, fmt.Errorf("%w: display filter %q produced zero packets", errNoPacketsMatched, displayFilter)
	}

	packetCount := countPacketsWithCapinfos(ctx, outPath, cfg)

	artifact := &OutputArtifact{
		Path:          outPath,
		SizeBytes:     info.Size(),
		SHA256:        sha256Hex(body),
		ContentType:   "application/vnd.tcpdump.pcap",
		SchemaVersion: SchemaVersion,
		GeneratedAt:   now.Format(time.RFC3339),
		Kind:          OutputArtifactKindFilteredPCAP,
	}
	return artifact, packetCount, warnings, nil
}

// tsharkHasAnyPacket is the definitive zero-packet check for the
// derived pcap. It runs `tshark -r path -c 1 -T fields -e frame.number`,
// which prints exactly one line per matching packet (capped at one).
// Empty stdout means zero packets in the file; non-empty means at
// least one. tshark is always available here because the runFilter
// path just used it to write the file, so this never trips an
// analyzer_unavailable false positive (which would have been the
// problem with using capinfos for the zero check).
func tsharkHasAnyPacket(ctx context.Context, path string, cfg config.Config) (bool, error) {
	out, err := runAnalyzerCommand(ctx, cfg.Timeout(), 64*1024, "tshark", []string{
		"-n",
		"-r", path,
		"-c", "1",
		"-T", "fields",
		"-E", "header=n",
		"-e", "frame.number",
	}, "")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out.Stdout) != "", nil
}

// countPacketsWithCapinfos asks capinfos for the packet count of the
// filtered pcap. Uses `-c` (count only) + `-M` (machine-readable). If
// capinfos is unavailable or the parse fails, the function returns 0
// — the caller treats that as "unknown" and still surfaces the
// artifact reference. The packet count is informational; it does not
// affect the artifact's typed-error contract.
func countPacketsWithCapinfos(ctx context.Context, path string, cfg config.Config) int64 {
	out, err := runAnalyzerCommand(ctx, cfg.Timeout(), 64*1024, "capinfos", []string{
		"-c", "-M", path,
	}, "")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(out.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToLower(line), "number of packets") {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		return parseLeadingInt64(strings.TrimSpace(line[colon+1:]))
	}
	return 0
}
