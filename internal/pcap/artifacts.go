package pcap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cute-pcap-mcp/internal/config"
)

// writeAnalysisArtifacts persists analysis.json and summary.md under
// the configured workspace.output_dir. The directory layout is:
//
//	${output_dir}/<sha256_prefix>-<utc_timestamp>[-<n>]/
//	  analysis.json
//	  summary.md
//
// The prefix-plus-timestamp form keeps re-runs of the same pcap from
// overwriting each other (which would lose evidence diffs across
// runs). When two analyses of the same pcap fire in the same second
// (possible under the default concurrent-analyzer cap), the dir name
// gets an incrementing -<n> suffix via a Mkdir collision-retry loop.
//
// The body is rendered into memory first so the cumulative size can
// be checked against analysis.output_disk_budget_bytes before
// anything is written. If the budget is exceeded the writer emits
// output_limit_reached and skips the write entirely.
//
// When output_dir is empty the caller must skip this; the writer
// returns an error in that case rather than silently using the OS
// default temp.
func writeAnalysisArtifacts(cfg config.Config, out analyzeOutput) ([]OutputArtifact, error) {
	root := cfg.Workspace.OutputDir
	if root == "" {
		return nil, fmt.Errorf("%w: workspace.output_dir is not configured", errAnalyzerFailed)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("%w: prepare workspace.output_dir: %v", errAnalyzerFailed, err)
	}

	now := time.Now().UTC()

	// Render bodies in memory first so we can validate the disk
	// budget before touching the filesystem.
	jsonBody, err := renderAnalysisJSON(out)
	if err != nil {
		return nil, err
	}
	mdBody := []byte(renderMarkdownSummary(out, now))

	if budget := cfg.Analysis.OutputDiskBudgetBytes; budget > 0 {
		total := int64(len(jsonBody) + len(mdBody))
		if total > budget {
			return nil, fmt.Errorf("%w: rendered artifacts would write %d bytes; exceeds analysis.output_disk_budget_bytes (%d)",
				errOutputLimitReached, total, budget)
		}
	}

	dir, err := makeUniqueCaptureDir(root, out.Artifact.SHA256, now)
	if err != nil {
		return nil, err
	}

	jsonArtifact, err := writeArtifactFile(filepath.Join(dir, "analysis.json"), jsonBody, "application/json", OutputArtifactKindAnalysisJSON, now)
	if err != nil {
		return nil, err
	}
	mdArtifact, err := writeArtifactFile(filepath.Join(dir, "summary.md"), mdBody, "text/markdown", OutputArtifactKindSummaryMarkdown, now)
	if err != nil {
		return nil, err
	}

	return []OutputArtifact{jsonArtifact, mdArtifact}, nil
}

// captureIDFor builds the deterministic directory name for one
// analysis run. Same-second collisions are handled at the Mkdir
// layer in makeUniqueCaptureDir; the seed name does not need to
// carry nanosecond precision.
func captureIDFor(sha256Hex string, now time.Time) string {
	prefix := sha256Hex
	if len(prefix) > 12 {
		prefix = prefix[:12]
	}
	if prefix == "" {
		prefix = "nohash"
	}
	return fmt.Sprintf("%s-%s", prefix, now.Format("20060102T150405Z"))
}

// makeUniqueCaptureDir creates ${root}/${captureID}, appending an
// incrementing -<n> suffix if an existing directory would be
// shadowed. os.Mkdir returns os.ErrExist on collision (unlike
// MkdirAll), which is what we want — same-pcap re-runs in the same
// UTC second land in distinct dirs and preserve the evidence diff.
func makeUniqueCaptureDir(root, sha256Hex string, now time.Time) (string, error) {
	base := captureIDFor(sha256Hex, now)
	for attempt := 0; attempt < 1000; attempt++ {
		name := base
		if attempt > 0 {
			name = fmt.Sprintf("%s-%d", base, attempt+1)
		}
		dir := filepath.Join(root, name)
		err := os.Mkdir(dir, 0o700)
		if err == nil {
			return dir, nil
		}
		if !os.IsExist(err) {
			return "", fmt.Errorf("%w: create capture artifact dir: %v", errAnalyzerFailed, err)
		}
	}
	return "", fmt.Errorf("%w: 1000 collisions creating capture artifact dir for %s", errAnalyzerFailed, base)
}

// renderAnalysisJSON serializes out for the persisted analysis.json
// file. The Artifacts list is cleared first because including it
// would force a self-referential record (the file containing its own
// size + sha256, which can't exist before the file is written).
// Hosts that need the OutputArtifact metadata read it from the
// in-memory MCP response, not from the persisted JSON.
func renderAnalysisJSON(out analyzeOutput) ([]byte, error) {
	cleaned := out
	cleaned.Artifacts = nil
	body, err := json.MarshalIndent(cleaned, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("%w: marshal analysis.json: %v", errAnalyzerFailed, err)
	}
	return append(body, '\n'), nil
}

// writeArtifactFile commits a rendered byte slice to disk and
// returns the OutputArtifact wire shape. SHA-256 is computed over
// the bytes that were written, not over the in-memory rendered
// form (the two should match because we only ever write the
// rendered slice once, but stamping after the write keeps the
// invariant honest if a future caller adds a transform).
func writeArtifactFile(path string, body []byte, contentType, kind string, now time.Time) (OutputArtifact, error) {
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return OutputArtifact{}, fmt.Errorf("%w: write %s: %v", errAnalyzerFailed, filepath.Base(path), err)
	}
	return OutputArtifact{
		Path:          path,
		SizeBytes:     int64(len(body)),
		SHA256:        sha256Hex(body),
		ContentType:   contentType,
		SchemaVersion: SchemaVersion,
		GeneratedAt:   now.Format(time.RFC3339),
		Kind:          kind,
	}, nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// renderMarkdownSummary produces the human-readable summary.md body.
// The renderer is intentionally bounded: it lists counts and the
// first few rows per section so the file stays small. For full
// evidence the LLM should read analysis.json.
func renderMarkdownSummary(out analyzeOutput, now time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# PCAP Analysis Summary\n\n")
	fmt.Fprintf(&b, "- Generated: %s\n", now.Format(time.RFC3339))
	fmt.Fprintf(&b, "- Schema version: %s\n", SchemaVersion)
	fmt.Fprintf(&b, "- Source pcap: `%s`\n", out.Artifact.Path)
	fmt.Fprintf(&b, "- SHA-256: `%s`\n", out.Artifact.SHA256)
	fmt.Fprintf(&b, "- Size: %d bytes\n\n", out.Artifact.SizeBytes)

	if cs := out.CaptureSummary; cs != nil {
		b.WriteString("## Capture summary\n\n")
		if cs.PacketCount > 0 {
			fmt.Fprintf(&b, "- Packets: %d\n", cs.PacketCount)
		}
		if cs.DurationSeconds > 0 {
			fmt.Fprintf(&b, "- Duration: %.6fs\n", cs.DurationSeconds)
		}
		if cs.StartTime != "" {
			fmt.Fprintf(&b, "- First packet: %s\n", cs.StartTime)
		}
		if cs.EndTime != "" {
			fmt.Fprintf(&b, "- Last packet: %s\n", cs.EndTime)
		}
		if cs.FileType != "" {
			fmt.Fprintf(&b, "- File type: %s\n", cs.FileType)
		}
		b.WriteString("\n")
	}

	if out.Protocols != nil && out.Protocols.Hierarchy != "" {
		b.WriteString("## Protocols\n\n```\n")
		b.WriteString(out.Protocols.Hierarchy)
		b.WriteString("```\n\n")
	}

	if len(out.DNS) > 0 {
		fmt.Fprintf(&b, "## DNS (%d queries)\n\n", len(out.DNS))
		for i, q := range out.DNS {
			if i >= 10 {
				fmt.Fprintf(&b, "- _… %d more in analysis.json_\n", len(out.DNS)-i)
				break
			}
			fmt.Fprintf(&b, "- `%s` %s → %s\n", q.Query, q.Type, q.Response)
		}
		b.WriteString("\n")
	}

	if len(out.HTTP) > 0 {
		fmt.Fprintf(&b, "## HTTP (%d requests)\n\n", len(out.HTTP))
		for i, r := range out.HTTP {
			if i >= 10 {
				fmt.Fprintf(&b, "- _… %d more in analysis.json_\n", len(out.HTTP)-i)
				break
			}
			fmt.Fprintf(&b, "- %s `%s` `%s` → %d\n", r.Method, r.Host, r.URI, r.StatusCode)
		}
		b.WriteString("\n")
	}

	if len(out.TLS) > 0 {
		fmt.Fprintf(&b, "## TLS (%d handshakes)\n\n", len(out.TLS))
		for i, h := range out.TLS {
			if i >= 10 {
				fmt.Fprintf(&b, "- _… %d more in analysis.json_\n", len(out.TLS)-i)
				break
			}
			fmt.Fprintf(&b, "- %s → %s (%s, %s)\n", h.ServerName, h.Destination, h.Version, h.Cipher)
		}
		b.WriteString("\n")
	}

	if h := out.TCPHealth; h != nil {
		b.WriteString("## TCP health\n\n")
		fmt.Fprintf(&b, "- Resets observed: %d (originator: %d, responder: %d)\n",
			h.ResetCount, h.ResetsByOriginator, h.ResetsByResponder)
		b.WriteString("\n")
	}

	if len(out.Findings) > 0 {
		b.WriteString("## Findings\n\n")
		for _, f := range out.Findings {
			fmt.Fprintf(&b, "- **%s** (%s): %s\n", f.Code, f.Severity, f.Message)
		}
		b.WriteString("\n")
	}

	if len(out.Errors) > 0 {
		b.WriteString("## Per-section errors\n\n")
		for _, e := range out.Errors {
			fmt.Fprintf(&b, "- **%s**: %s\n", e.Kind, e.Message)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Limitations\n\n")
	b.WriteString("- Output is bounded by per-call and server-config limits.\n")
	b.WriteString("- ASCII string redaction is best-effort; do not assume it caught every secret shape.\n")
	b.WriteString("- This summary is for human review; the full evidence is in `analysis.json`.\n")
	return b.String()
}
