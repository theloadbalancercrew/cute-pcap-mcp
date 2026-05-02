package pcap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"cute-pcap-mcp/internal/config"
)

const (
	defaultMinASCIIStringLength = 4
	maxASCIIStringTextBytes     = 4096
)

type analyzeInput struct {
	Path                 string     `json:"path" jsonschema:"absolute or relative path to a pcap/pcapng under an allowed artifact directory"`
	IncludeCapinfos      *bool      `json:"include_capinfos,omitempty" jsonschema:"include capinfos capture metadata; defaults to true"`
	IncludeTShark        *bool      `json:"include_tshark,omitempty" jsonschema:"include tshark protocol, conversation, and packet-row evidence; defaults to true"`
	IncludeZeek          *bool      `json:"include_zeek,omitempty" jsonschema:"include parsed Zeek logs and derived Zeek summaries; defaults to true"`
	IncludeASCII         *bool      `json:"include_ascii,omitempty" jsonschema:"include bounded printable ASCII strings found in the capture file; defaults to true"`
	RedactSecrets        *bool      `json:"redact_secrets,omitempty" jsonschema:"redact common credentials and token-like values from ASCII strings; defaults to true"`
	DisplayFilter        string     `json:"display_filter,omitempty" jsonschema:"optional tshark display filter applied to packet rows"`
	MinStringLength      int        `json:"min_string_length,omitempty" jsonschema:"minimum printable ASCII run length to return; defaults to 4"`
	MaxASCIIStrings      int        `json:"max_ascii_strings,omitempty" jsonschema:"maximum ASCII strings to return, capped by server config"`
	MaxASCIIBytes        int        `json:"max_ascii_bytes,omitempty" jsonschema:"maximum returned ASCII text bytes, capped by server config"`
	MaxPacketRows        int        `json:"max_packet_rows,omitempty" jsonschema:"maximum tshark packet summary rows, capped by server config"`
	MaxZeekRecordsPerLog int        `json:"max_zeek_records_per_log,omitempty" jsonschema:"maximum Zeek records per log, capped by server config"`
	WriteArtifacts       *bool      `json:"write_artifacts,omitempty" jsonschema:"write analysis.json + summary.md under workspace.output_dir; defaults to true when output_dir is configured"`
	ExpectedSHA256       string     `json:"expected_sha256,omitempty" jsonschema:"optional caller-provided sha256 from an external artifact reference; must be exactly 64 hex digits if set; mismatched values return the typed hash_mismatch error"`
	ExpectedSizeBytes    *int64     `json:"expected_size_bytes,omitempty" jsonschema:"optional caller-provided file size in bytes from an external artifact reference; must be non-negative if set; mismatched values return the typed size_mismatch error"`
	AnalysisProfile      string     `json:"analysis_profile,omitempty" jsonschema:"optional named profile that layers extra analysis on top of the generic evidence; today the only registered name is f5_ltm_tls_debug"`
	F5Context            *F5Context `json:"f5_context,omitempty" jsonschema:"optional caller-supplied load-balancer context (VIP, pool, SNAT pool); echoed back and used to classify packet evidence, never to make config claims"`
	TLSKeylogPath        string     `json:"tls_keylog_path,omitempty" jsonschema:"optional path to an SSLKEYLOGFILE under workspace.keylog_dir; enables tshark/Zeek decryption of TLS sessions whose keys appear in the file. Only the decryption status is returned; decrypted payload bytes are never included in the response."`
}

func writeArtifacts(input analyzeInput) bool {
	return input.WriteArtifacts == nil || *input.WriteArtifacts
}

type analyzerStatusInput struct{}

type analyzerStatusOutput struct {
	Analyzers []AnalyzerStatus `json:"analyzers"`
}

type AnalyzerStatus struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Path      string `json:"path,omitempty"`
	Version   string `json:"version,omitempty"`
	Error     string `json:"error,omitempty"`
}

type TSharkReport struct {
	ProtocolHierarchy string                `json:"protocol_hierarchy,omitempty"`
	Conversations     map[string]string     `json:"conversations,omitempty"`
	Packets           []TSharkPacketSummary `json:"packets,omitempty"`
	Errors            []toolError           `json:"errors,omitempty"`
	Metadata          map[string]string     `json:"metadata,omitempty"`
}

type TSharkPacketSummary struct {
	Number       string `json:"number,omitempty"`
	TimeRelative string `json:"time_relative,omitempty"`
	Protocol     string `json:"protocol,omitempty"`
	Source       string `json:"source,omitempty"`
	SourcePort   string `json:"source_port,omitempty"`
	Destination  string `json:"destination,omitempty"`
	DestPort     string `json:"dest_port,omitempty"`
	Info         string `json:"info,omitempty"`
}

type ZeekReport struct {
	Logs     []ZeekLog         `json:"logs,omitempty"`
	Warnings string            `json:"warnings,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

type ZeekLog struct {
	Name      string              `json:"name"`
	Fields    []string            `json:"fields,omitempty"`
	Types     []string            `json:"types,omitempty"`
	Records   []map[string]string `json:"records,omitempty"`
	Truncated bool                `json:"truncated,omitempty"`
}

type ASCIIReport struct {
	MinLength     int           `json:"min_length"`
	BytesReturned int           `json:"bytes_returned"`
	Strings       []ASCIIString `json:"strings,omitempty"`
	Truncated     bool          `json:"truncated,omitempty"`
	Redacted      bool          `json:"redacted,omitempty"`
}

type ASCIIString struct {
	Offset   int64  `json:"offset"`
	Length   int    `json:"length"`
	Text     string `json:"text"`
	Redacted bool   `json:"redacted,omitempty"`
}

type analyzerCommandOutput struct {
	Stdout string
	Stderr string
}

type asciiExtractionOptions struct {
	MinLength     int
	MaxStrings    int
	MaxBytes      int
	RedactSecrets bool
}

func validateAnalyzeInput(input analyzeInput) error {
	if input.Path == "" {
		return missingFieldError("path")
	}
	if strings.ContainsRune(input.DisplayFilter, '\x00') {
		return validationError("display_filter", ValidationReasonContainsNUL, "display_filter must not contain NUL bytes")
	}
	if len(input.DisplayFilter) > 4096 {
		return validationError("display_filter", ValidationReasonTooLong, "display_filter must be 4096 bytes or less")
	}
	if input.MinStringLength < 0 {
		return validationError("min_string_length", ValidationReasonOutOfRange, "min_string_length must be non-negative")
	}
	if err := validateF5Context(input.F5Context); err != nil {
		return err
	}
	return nil
}

// Free-form F5 context field caps. Load-balancer object names are typically
// well under 256 chars; notes can run longer but should still be
// bounded so an oversize caller-supplied value cannot inflate every
// MCP response and persisted artifact that echoes the context back.
const (
	f5ContextNameMaxLen  = 256
	f5ContextNotesMaxLen = 4096
)

// validateF5Context bounds-checks the optional caller-supplied F5
// context. Structurally-typed values are validated (virtual_server_ip
// via net/netip, virtual_server_port range). Free-form fields
// (virtual_server_name, pool_name, snat_pool_name, notes) are
// preserved verbatim but capped in length and rejected for NUL
// bytes — without these caps a caller could echo unbounded text
// into every analyze response and persisted artifact.
func validateF5Context(ctx *F5Context) error {
	if ctx == nil {
		return nil
	}
	if ip := strings.TrimSpace(ctx.VirtualServerIP); ip != "" {
		if _, err := netip.ParseAddr(ip); err != nil {
			return validationError("f5_context.virtual_server_ip", ValidationReasonInvalidFormat,
				"virtual_server_ip is not a valid IP address: "+err.Error())
		}
	}
	if ctx.VirtualServerPort < 0 || ctx.VirtualServerPort > 65535 {
		return validationError("f5_context.virtual_server_port", ValidationReasonOutOfRange,
			"virtual_server_port must be in [0, 65535]")
	}
	for _, slot := range []struct {
		name   string
		value  string
		maxLen int
	}{
		{"f5_context.virtual_server_name", ctx.VirtualServerName, f5ContextNameMaxLen},
		{"f5_context.pool_name", ctx.PoolName, f5ContextNameMaxLen},
		{"f5_context.snat_pool_name", ctx.SNATPoolName, f5ContextNameMaxLen},
		{"f5_context.notes", ctx.Notes, f5ContextNotesMaxLen},
	} {
		if strings.ContainsRune(slot.value, '\x00') {
			return validationError(slot.name, ValidationReasonContainsNUL,
				slot.name+" must not contain NUL bytes")
		}
		if len(slot.value) > slot.maxLen {
			return validationError(slot.name, ValidationReasonTooLong,
				slot.name+" must be "+intToString(slot.maxLen)+" bytes or less")
		}
	}
	return nil
}

func analyzerStatuses(ctx context.Context, cfg config.Config) analyzerStatusOutput {
	checks := []struct {
		name string
		args []string
	}{
		{name: "capinfos", args: []string{"-v"}},
		{name: "tshark", args: []string{"-v"}},
		{name: "zeek", args: []string{"--version"}},
	}
	out := analyzerStatusOutput{Analyzers: make([]AnalyzerStatus, 0, len(checks))}
	for _, check := range checks {
		path, err := exec.LookPath(check.name)
		if err != nil {
			out.Analyzers = append(out.Analyzers, AnalyzerStatus{
				Name:      check.name,
				Available: false,
				Error:     fmt.Sprintf("%s is not available on PATH", check.name),
			})
			continue
		}
		status := AnalyzerStatus{Name: check.name, Available: true, Path: path}
		version, err := runAnalyzerCommand(ctx, cfg.Timeout(), 64*1024, check.name, check.args, "")
		if err != nil {
			status.Error = strings.TrimPrefix(err.Error(), errAnalyzerFailed.Error()+": ")
		} else {
			status.Version = firstNonEmptyLine(version.Stdout, version.Stderr)
		}
		out.Analyzers = append(out.Analyzers, status)
	}
	return out
}

func analyzeArtifact(ctx context.Context, artifact ArtifactInfo, cfg config.Config, input analyzeInput) analyzeOutput {
	out := analyzeOutput{
		SchemaVersion: SchemaVersion,
		Artifact:      artifact,
		Metadata: map[string]string{
			"privacy": "ASCII strings are bounded and common secret-looking values are redacted by default.",
		},
	}

	// Resolve TLS keylog input up-front. The state machine drives
	// what tshark/Zeek do (when the path is valid) and what the
	// final tls_decryption.status reports. Path-validation failures
	// here are not hard tool errors — they map to typed states so
	// the caller learns *why* decryption was unavailable without
	// losing the rest of the analyze surface.
	keylogResolved, keylogStatus, keylogDetail := resolveTLSKeylog(input.TLSKeylogPath, cfg)
	keylogActive := keylogStatus == TLSDecryptionStatusAttempted

	// truncationWarnings collects pcap_truncated findings from any
	// analyzer that produced partial evidence on a cut-short input.
	// They are merged into out.Findings after buildFindings runs so
	// they survive the slice replacement (same pattern as the M4
	// profile-finding merge).
	var truncationWarnings []PacketFinding

	if includeCapinfos(input) {
		capinfosStdout, capinfosTruncated, capinfosStderr, err := runCapinfos(ctx, artifact.Path, cfg.Timeout(), cfg.Analysis.MaxStdoutBytes)
		switch {
		case err != nil:
			out.Errors = append(out.Errors, classify(err))
		case capinfosTruncated:
			// capinfos managed to print partial capture metadata before
			// bailing on the truncation. Parse what we have and surface
			// a typed warning so the host knows the source pcap was
			// cut short.
			if summary := parseCapinfos(capinfosStdout); summary != nil {
				out.CaptureSummary = summary
			}
			truncationWarnings = append(truncationWarnings, truncationFinding("capinfos", capinfosStderr))
		default:
			if summary := parseCapinfos(capinfosStdout); summary != nil {
				out.CaptureSummary = summary
			}
		}
	}

	keylogForAnalyzers := ""
	if keylogActive {
		keylogForAnalyzers = keylogResolved
	}

	// keylogAnalyzerFailed tracks errors from analyzer subprocesses
	// that ACTUALLY received the keylog (tshark + Zeek when the
	// keylog was active). Errors from capinfos / ASCII extraction /
	// unrelated calls must not flip tls_decryption.status to failed.
	keylogAnalyzerFailed := false

	if includeTShark(input) {
		tshark, tsharkTruncated, err := runTSharkReport(ctx, artifact.Path, cfg, packetRowLimit(cfg, input), strings.TrimSpace(input.DisplayFilter), keylogForAnalyzers)
		if err != nil {
			out.Errors = append(out.Errors, classify(err))
			if keylogActive {
				keylogAnalyzerFailed = true
			}
		}
		// Hoist every populated tshark sub-report onto the top-level
		// shape. runTSharkReport may return a partial report when one
		// sub-call (e.g. packet summaries with an invalid filter)
		// fails — the protocol hierarchy and conversation tables are
		// still useful evidence and need to land somewhere visible.
		if tshark.ProtocolHierarchy != "" {
			out.Protocols = &ProtocolsSection{Hierarchy: tshark.ProtocolHierarchy}
		}
		if hasNonEmptyConversations(tshark.Conversations) {
			out.Conversations = tshark.Conversations
		}
		if len(tshark.Packets) > 0 {
			out.Packets = tshark.Packets
		}
		for _, terr := range tshark.Errors {
			out.Errors = append(out.Errors, terr)
			// Nested tshark errors fired during sub-calls that
			// received the keylog count toward the keylog-failure
			// signal too.
			if keylogActive {
				keylogAnalyzerFailed = true
			}
		}
		if tsharkTruncated {
			truncationWarnings = append(truncationWarnings, truncationFinding("tshark", "input pcap appears to have been cut short in the middle of a packet"))
		}
	}

	var zeekSummary *AnalysisSummary
	if includeZeek(input) {
		zeek, zeekTruncated, err := runZeekReport(ctx, artifact.Path, cfg, zeekRecordLimit(cfg, input), keylogForAnalyzers)
		if err != nil {
			out.Errors = append(out.Errors, classify(err))
			if keylogActive {
				keylogAnalyzerFailed = true
			}
		} else {
			zeekSummary = buildAnalysisSummary(zeek)
			if zeekSummary != nil {
				out.DNS = zeekSummary.DNSQueries
				out.HTTP = zeekSummary.HTTPRequests
				out.TLS = zeekSummary.TLSHandshakes
				out.Notices = zeekSummary.Notices
				out.WeirdEvents = zeekSummary.WeirdEvents
				out.TCPHealth = buildTCPHealth(zeekSummary)
			}
			if len(zeek.Logs) > 0 {
				out.ZeekLogs = zeek.Logs
			}
			if zeek.Warnings != "" {
				out.Metadata["zeek_warnings"] = zeek.Warnings
			}
			if zeekTruncated {
				truncationWarnings = append(truncationWarnings, truncationFinding("zeek", zeek.Warnings))
			}
		}
	}

	if includeASCII(input) {
		ascii, err := extractASCIIStrings(artifact.Path, asciiOptions(cfg, input))
		if err != nil {
			out.Errors = append(out.Errors, classify(err))
		} else {
			out.ASCII = &ascii
		}
	}

	var profileFindings []PacketFinding
	if name := strings.TrimSpace(input.AnalysisProfile); name != "" {
		profileFindings = applyAnalysisProfile(&out, zeekSummary, name, input.F5Context)
	}
	out.Findings = buildFindings(out, zeekSummary)
	// Merge profile-level findings AFTER buildFindings so the
	// dispatcher's analysis_profile_applied / analysis_profile_unknown
	// markers and the per-profile finding codes survive. An earlier
	// version appended these inside applyAnalysisProfile and was
	// silently overwritten when buildFindings replaced the slice; the
	// end-to-end test pins the merged shape now.
	out.Findings = append(out.Findings, profileFindings...)
	if out.Profile != nil {
		out.Findings = append(out.Findings, out.Profile.Findings...)
	}
	// Truncation warnings are merged after profile findings (same
	// rationale: buildFindings replaces the slice). Multiple
	// analyzers can detect the same truncation; we only emit the
	// first finding per analyzer because the message is bounded
	// and a host scanning findings.code on pcap_truncated already
	// has the signal it needs.
	if len(truncationWarnings) > 0 {
		seen := map[string]bool{}
		for _, w := range truncationWarnings {
			if seen[w.Message] {
				continue
			}
			seen[w.Message] = true
			out.Findings = append(out.Findings, w)
		}
	}

	// Stamp the TLS decryption status. Even when the caller did not
	// request decryption, the response carries the typed status
	// (`not_requested`) so hosts can switch on it without ambiguity.
	out.TLSDecryption = finalizeTLSDecryptionStatus(keylogStatus, keylogDetail, keylogAnalyzerFailed, keylogPathOrEmpty(keylogStatus, keylogResolved))
	return out
}

// applyAnalysisProfile dispatches on analysis_profile to layer
// per-profile evidence on top of the generic analyzeOutput. Unknown
// profile names are not a hard error: the analyze pipeline still
// returned full generic evidence; the unknown name just produces an
// info-level finding so the host knows the profile name was not
// honored. This mirrors the "truth-over-closure" pattern from the
// flagship — distinct typed outcomes (recognized profile applied vs
// unknown profile name) over a fake success.
//
// Returns dispatcher-level findings (applied / unknown) so the
// caller can merge them after buildFindings; writing them inline
// would be lost when buildFindings replaces the slice.
func applyAnalysisProfile(out *analyzeOutput, summary *AnalysisSummary, name string, ctx *F5Context) []PacketFinding {
	switch name {
	case AnalysisProfileF5LTMTLSDebug:
		profile := buildF5LTMTLSDebugProfile(*out, summary, ctx)
		if profile != nil {
			out.Profile = profile
			return []PacketFinding{{
				Code:     FindingProfileApplied,
				Severity: "info",
				Message:  "Applied analysis_profile=" + name + ".",
			}}
		}
		return nil
	default:
		return []PacketFinding{{
			Code:     FindingProfileUnknown,
			Severity: "warning",
			Message:  "analysis_profile=" + name + " is not registered; generic evidence was returned without profile enrichment.",
		}}
	}
}

// buildTCPHealth derives the tcp_health section from the Zeek
// connection summary. Reset-side classification uses Zeek's
// conn_state field: "RSTO" = originator-side reset, "RSTR" =
// responder-side reset. Other reset-bearing states (RSTOS0, etc.)
// count toward total resets but not toward a side.
func buildTCPHealth(summary *AnalysisSummary) *TCPHealthSection {
	if summary == nil {
		return nil
	}
	var section TCPHealthSection
	for _, conn := range summary.Connections {
		state := strings.ToUpper(conn.ConnState)
		isReset := connectionLooksReset(conn)
		if !isReset {
			continue
		}
		section.ResetCount++
		switch state {
		case "RSTO", "RSTOS0":
			section.ResetsByOriginator++
		case "RSTR", "RSTRH":
			section.ResetsByResponder++
		}
		section.ResetConnections = append(section.ResetConnections, conn)
	}
	if section.ResetCount == 0 {
		return nil
	}
	return &section
}

func includeCapinfos(input analyzeInput) bool {
	return input.IncludeCapinfos == nil || *input.IncludeCapinfos
}

func includeTShark(input analyzeInput) bool {
	return input.IncludeTShark == nil || *input.IncludeTShark
}

func includeZeek(input analyzeInput) bool {
	return input.IncludeZeek == nil || *input.IncludeZeek
}

func includeASCII(input analyzeInput) bool {
	return input.IncludeASCII == nil || *input.IncludeASCII
}

func redactSecrets(input analyzeInput) bool {
	return input.RedactSecrets == nil || *input.RedactSecrets
}

func packetRowLimit(cfg config.Config, input analyzeInput) int {
	return boundedOverride(input.MaxPacketRows, cfg.Analysis.MaxPacketRows)
}

func zeekRecordLimit(cfg config.Config, input analyzeInput) int {
	return boundedOverride(input.MaxZeekRecordsPerLog, cfg.Analysis.MaxZeekRecordsPerLog)
}

func asciiOptions(cfg config.Config, input analyzeInput) asciiExtractionOptions {
	minLength := input.MinStringLength
	if minLength == 0 {
		minLength = defaultMinASCIIStringLength
	}
	if minLength < 1 {
		minLength = defaultMinASCIIStringLength
	}
	if minLength > 1024 {
		minLength = 1024
	}
	return asciiExtractionOptions{
		MinLength:     minLength,
		MaxStrings:    boundedOverride(input.MaxASCIIStrings, cfg.Analysis.MaxASCIIStrings),
		MaxBytes:      boundedOverride(input.MaxASCIIBytes, cfg.Analysis.MaxASCIIBytes),
		RedactSecrets: redactSecrets(input),
	}
}

func boundedOverride(requested, configured int) int {
	if requested <= 0 || requested > configured {
		return configured
	}
	return requested
}

// hasNonEmptyConversations reports whether any tshark conversation
// table actually has rows. analyzeArtifact uses this to decide
// whether the conversations section is worth attaching at the top
// level.
func hasNonEmptyConversations(m map[string]string) bool {
	for _, v := range m {
		if v != "" {
			return true
		}
	}
	return false
}

func buildFindings(out analyzeOutput, summary *AnalysisSummary) []PacketFinding {
	findings := []PacketFinding{{
		Code:     FindingAnalysisGenerated,
		Severity: "info",
		Message:  "Generated bounded pcap evidence from available analyzers.",
	}}
	tsharkSections := tsharkSectionsAvailable(out)
	if len(tsharkSections) > 0 {
		findings = append(findings, PacketFinding{
			Code:     FindingTSharkAnalysisAvail,
			Severity: "info",
			Message:  "tshark evidence is available for: " + strings.Join(tsharkSections, ", ") + ".",
		})
	}
	if len(out.ZeekLogs) > 0 {
		findings = append(findings, PacketFinding{
			Code:     FindingZeekAnalysisAvail,
			Severity: "info",
			Message:  "Zeek log evidence is available.",
		})
	}
	if out.ASCII != nil {
		findings = append(findings, PacketFinding{
			Code:     FindingASCIIStringsExtracted,
			Severity: "info",
			Message:  fmt.Sprintf("Extracted %d printable ASCII strings from the capture with bounded output.", len(out.ASCII.Strings)),
		})
		if out.ASCII.Redacted {
			findings = append(findings, PacketFinding{
				Code:     FindingASCIIStringsRedacted,
				Severity: "warning",
				Message:  "One or more ASCII strings matched common secret patterns and were redacted.",
			})
		}
		if out.ASCII.Truncated {
			findings = append(findings, PacketFinding{
				Code:     FindingASCIIStringsTruncated,
				Severity: "warning",
				Message:  "ASCII extraction hit configured result limits.",
			})
		}
	}
	seenFinding := map[string]bool{}
	for _, terr := range out.Errors {
		key := terr.Kind + "|" + terr.Field + "|" + terr.Reason
		if seenFinding[key] {
			continue
		}
		seenFinding[key] = true
		findings = append(findings, PacketFinding{
			Code:     terr.Kind,
			Severity: "warning",
			Message:  terr.Message,
		})
	}
	findings = append(findings, summaryFindings(summary)...)
	return findings
}

// tsharkSectionsAvailable lists the populated tshark sub-reports for
// the tshark_analysis_available finding. Listing only what is
// actually present keeps the message partial-safe when one sub-call
// (e.g. packet summaries with an invalid filter) failed.
func tsharkSectionsAvailable(out analyzeOutput) []string {
	var sections []string
	if out.Protocols != nil && out.Protocols.Hierarchy != "" {
		sections = append(sections, "protocol hierarchy")
	}
	if hasNonEmptyConversations(out.Conversations) {
		sections = append(sections, "conversation tables")
	}
	if len(out.Packets) > 0 {
		sections = append(sections, "packet summaries")
	}
	return sections
}

// runCapinfos returns capinfos's human-readable text. The third
// return is a `truncated` flag that is true when capinfos exited
// non-zero with a recognized truncated-pcap diagnostic; in that
// case the stdout is the partial output capinfos managed to print
// before bailing (capture metadata is generally complete; only the
// final truncated packet is missing). Callers should still parse
// the partial stdout and emit a pcap_truncated finding.
func runCapinfos(parent context.Context, path string, timeout time.Duration, maxBytes int) (string, bool, string, error) {
	out, truncated, err := runAnalyzerCommandTolerant(parent, timeout, maxBytes, "capinfos", []string{path}, "")
	return out.Stdout, truncated, out.Stderr, err
}

func runTSharkReport(parent context.Context, path string, cfg config.Config, maxPacketRows int, displayFilter string, keylogPath string) (TSharkReport, bool, error) {
	report := TSharkReport{
		Conversations: map[string]string{},
		Metadata: map[string]string{
			"packet_rows_returned_limit": strconv.Itoa(maxPacketRows),
		},
	}
	if displayFilter != "" {
		report.Metadata["display_filter"] = displayFilter
		report.Metadata["display_filter_scope"] = "packet_rows"
	}
	keylogArgs := keylogTSharkArgs(keylogPath)
	// truncated tracks whether ANY tshark sub-call detected a
	// truncated-pcap diagnostic. The caller surfaces this as a
	// single pcap_truncated finding regardless of how many sub-
	// calls saw it.
	truncated := false

	protocolHierarchy, hierarchyTruncated, err := runTShark(parent, path, cfg.Timeout(), cfg.Analysis.MaxStdoutBytes, keylogArgs)
	if err != nil {
		return TSharkReport{}, false, err
	}
	report.ProtocolHierarchy = protocolHierarchy
	if hierarchyTruncated {
		truncated = true
	}

	for _, convType := range []string{"eth", "ip", "tcp", "udp"} {
		args := []string{"-n", "-r", path, "-q", "-z", "conv," + convType}
		args = append(keylogArgs, args...)
		out, convTruncated, err := runAnalyzerCommandTolerant(parent, cfg.Timeout(), cfg.Analysis.MaxStdoutBytes, "tshark", args, "")
		if err != nil {
			report.Errors = append(report.Errors, classify(err))
			continue
		}
		if convTruncated {
			truncated = true
		}
		report.Conversations[convType] = out.Stdout
	}

	packets, packetsTruncated, err := runTSharkPacketSummaries(parent, path, cfg.Timeout(), cfg.Analysis.MaxStdoutBytes, maxPacketRows, displayFilter, keylogArgs)
	if err != nil {
		// invalid_filter is caller-supplied input that we cannot
		// honor. Bubble it up so it lands in the top-level
		// out.Errors[] (and a finding) rather than hiding inside the
		// tshark sub-report. Other tshark failures stay nested as
		// per-section partial errors.
		if errors.Is(err, errInvalidFilter) {
			report.Errors = append(report.Errors, classify(err))
			return report, truncated, err
		}
		report.Errors = append(report.Errors, classify(err))
	} else {
		report.Packets = packets
		if packetsTruncated {
			truncated = true
		}
	}
	return report, truncated, nil
}

func runTSharkPacketSummaries(parent context.Context, path string, timeout time.Duration, maxBytes, maxRows int, displayFilter string, keylogArgs []string) ([]TSharkPacketSummary, bool, error) {
	args := []string{
		"-n",
		"-r", path,
		"-c", strconv.Itoa(maxRows),
		"-T", "fields",
		"-E", "header=y",
		"-E", "separator=/t",
		"-E", "quote=d",
		"-E", "occurrence=f",
		"-e", "frame.number",
		"-e", "frame.time_relative",
		"-e", "_ws.col.Protocol",
		"-e", "ip.src",
		"-e", "ipv6.src",
		"-e", "tcp.srcport",
		"-e", "udp.srcport",
		"-e", "ip.dst",
		"-e", "ipv6.dst",
		"-e", "tcp.dstport",
		"-e", "udp.dstport",
		"-e", "_ws.col.Info",
	}
	if displayFilter != "" {
		args = append([]string{"-Y", displayFilter}, args...)
	}
	args = append(keylogArgs, args...)
	out, truncated, err := runAnalyzerCommandTolerant(parent, timeout, maxBytes, "tshark", args, "")
	if err != nil {
		if displayFilter != "" && isTSharkFilterError(err) {
			return nil, false, invalidFilterError(strings.TrimPrefix(err.Error(), errAnalyzerFailed.Error()+": "))
		}
		return nil, false, err
	}
	parsed, parseErr := parseTSharkPacketSummaries(out.Stdout)
	if parseErr != nil {
		return nil, false, parseErr
	}
	return parsed, truncated, nil
}

// isTSharkFilterError checks whether an analyzer_failed error from
// tshark is specifically a display-filter rejection. tshark's stderr
// uses a stable phrase ("Invalid capture filter" / "Display filter
// isn't a valid display filter") that we match against.
func isTSharkFilterError(err error) bool {
	if !errors.Is(err, errAnalyzerFailed) {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "isn't a valid display filter") ||
		strings.Contains(msg, "invalid display filter") ||
		strings.Contains(msg, "syntax error in filter") ||
		strings.Contains(msg, "is not a valid protocol or protocol field") ||
		strings.Contains(msg, "filter \"") && strings.Contains(msg, "is not a valid")
}

func parseTSharkPacketSummaries(raw string) ([]TSharkPacketSummary, error) {
	reader := csv.NewReader(strings.NewReader(raw))
	reader.Comma = '\t'
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("%w: parse tshark packet fields: %v", errAnalyzerFailed, err)
	}
	if len(records) <= 1 {
		return nil, nil
	}
	packets := make([]TSharkPacketSummary, 0, len(records)-1)
	for _, record := range records[1:] {
		field := func(idx int) string {
			if idx >= len(record) {
				return ""
			}
			return strings.TrimSpace(record[idx])
		}
		packets = append(packets, TSharkPacketSummary{
			Number:       field(0),
			TimeRelative: field(1),
			Protocol:     field(2),
			Source:       firstNonEmpty(field(3), field(4)),
			SourcePort:   firstNonEmpty(field(5), field(6)),
			Destination:  firstNonEmpty(field(7), field(8)),
			DestPort:     firstNonEmpty(field(9), field(10)),
			Info:         redactStructuredEvidence(field(11)),
		})
	}
	return packets, nil
}

func runZeekReport(parent context.Context, path string, cfg config.Config, maxRecordsPerLog int, keylogPath string) (ZeekReport, bool, error) {
	tmpRoot := cfg.Workspace.TmpDir
	if tmpRoot != "" {
		if err := os.MkdirAll(tmpRoot, 0o700); err != nil {
			return ZeekReport{}, false, fmt.Errorf("%w: prepare workspace.tmp_dir: %v", errAnalyzerFailed, err)
		}
	}
	workdir, err := os.MkdirTemp(tmpRoot, "cute-pcap-mcp-zeek-*")
	if err != nil {
		return ZeekReport{}, false, err
	}
	defer os.RemoveAll(workdir)

	var zeekEnv []string
	if keylogPath != "" {
		// Zeek picks up SSLKEYLOGFILE per the upstream Zeek SSL
		// analyzer; we set it on the subprocess env, never the
		// parent process, so the value is scoped to this single
		// analyzer invocation.
		zeekEnv = []string{"SSLKEYLOGFILE=" + keylogPath}
	}
	out, runErr := runAnalyzerCommandWithEnv(parent, cfg.Timeout(), cfg.Analysis.MaxStdoutBytes, "zeek", []string{
		"-C",
		"-r", path,
	}, workdir, zeekEnv)
	// On a truncated input, Zeek exits non-zero AFTER writing
	// per-protocol .log files for the readable prefix of the
	// capture. The workdir is therefore still useful even though
	// the subprocess returned an error. Detect that case via the
	// known stderr phrase and continue into the log-parsing path
	// with a `truncated` flag set; only return the error for
	// non-truncated failures (binary missing, real crash, etc.).
	truncated := false
	if runErr != nil {
		if isTruncatedPCAPDiagnostic(out.Stderr) {
			truncated = true
		} else {
			return ZeekReport{}, false, runErr
		}
	}

	if budget := cfg.Analysis.TmpDiskBudgetBytes; budget > 0 {
		used, walkErr := dirSizeBytes(workdir)
		if walkErr != nil {
			return ZeekReport{}, false, fmt.Errorf("%w: measure tmp_dir use: %v", errAnalyzerFailed, walkErr)
		}
		if used > budget {
			return ZeekReport{}, false, fmt.Errorf("%w: zeek wrote %d bytes; exceeds analysis.tmp_disk_budget_bytes (%d)",
				errTmpBudgetExceeded, used, budget)
		}
	}

	report := ZeekReport{
		Warnings: strings.TrimSpace(out.Stderr),
		Metadata: map[string]string{
			"records_per_log_limit": strconv.Itoa(maxRecordsPerLog),
		},
	}

	matches, err := filepath.Glob(filepath.Join(workdir, "*.log"))
	if err != nil {
		return ZeekReport{}, false, err
	}
	sort.Strings(matches)
	for _, logPath := range matches {
		log, err := parseZeekLog(logPath, maxRecordsPerLog)
		if err != nil {
			return ZeekReport{}, false, fmt.Errorf("%w: parse %s: %v", errAnalyzerFailed, filepath.Base(logPath), err)
		}
		report.Logs = append(report.Logs, log)
	}
	return report, truncated, nil
}

// dirSizeBytes sums the regular-file sizes under root. Used to enforce
// the per-call tmp disk budget after a Zeek run completes; symlinks
// and special files are skipped.
func dirSizeBytes(root string) (int64, error) {
	var total int64
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	return total, err
}

func parseZeekLog(path string, maxRecords int) (ZeekLog, error) {
	file, err := os.Open(path)
	if err != nil {
		return ZeekLog{}, err
	}
	defer file.Close()

	log := ZeekLog{Name: strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))}
	separator := "\t"
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "#separator"):
			if value, ok := zeekDirectiveValue(line, "#separator", " "); ok {
				separator = zeekUnescape(strings.TrimSpace(value))
			}
		case strings.HasPrefix(line, "#path"):
			if value, ok := zeekDirectiveValue(line, "#path", separator); ok {
				log.Name = strings.TrimSpace(value)
			}
		case strings.HasPrefix(line, "#fields"):
			if value, ok := zeekDirectiveValue(line, "#fields", separator); ok {
				log.Fields = strings.Split(value, separator)
			}
		case strings.HasPrefix(line, "#types"):
			if value, ok := zeekDirectiveValue(line, "#types", separator); ok {
				log.Types = strings.Split(value, separator)
			}
		case strings.HasPrefix(line, "#"):
			continue
		default:
			if maxRecords > 0 && len(log.Records) >= maxRecords {
				log.Truncated = true
				continue
			}
			values := strings.Split(line, separator)
			record := make(map[string]string, len(log.Fields))
			for idx, field := range log.Fields {
				if idx < len(values) {
					record[field] = redactStructuredEvidence(values[idx])
				} else {
					record[field] = ""
				}
			}
			log.Records = append(log.Records, record)
		}
	}
	if err := scanner.Err(); err != nil {
		return ZeekLog{}, err
	}
	return log, nil
}

func zeekDirectiveValue(line, directive, separator string) (string, bool) {
	if !strings.HasPrefix(line, directive) {
		return "", false
	}
	rest := strings.TrimPrefix(line, directive)
	switch {
	case rest == "":
		return "", false
	case strings.HasPrefix(rest, " "):
		return strings.TrimPrefix(rest, " "), true
	case separator != "" && strings.HasPrefix(rest, separator):
		return strings.TrimPrefix(rest, separator), true
	default:
		return "", false
	}
}

func zeekUnescape(value string) string {
	replacer := strings.NewReplacer(
		`\\`, `\`,
		`\x09`, "\t",
		`\x20`, " ",
		`\x2c`, ",",
	)
	return replacer.Replace(value)
}

func redactStructuredEvidence(value string) string {
	redacted, _ := redactASCIISecrets(value)
	return redacted
}

func extractASCIIStrings(path string, opts asciiExtractionOptions) (ASCIIReport, error) {
	if opts.MinLength <= 0 {
		opts.MinLength = defaultMinASCIIStringLength
	}
	if opts.MaxStrings <= 0 {
		opts.MaxStrings = 1
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 1024
	}

	file, err := os.Open(path)
	if err != nil {
		return ASCIIReport{}, err
	}
	defer file.Close()

	report := ASCIIReport{MinLength: opts.MinLength}
	buf := make([]byte, 32*1024)
	var (
		offset        int64
		currentOffset int64
		current       []byte
		currentLength int
	)

	flush := func() bool {
		defer func() {
			current = current[:0]
			currentLength = 0
		}()
		if currentLength < opts.MinLength {
			return false
		}
		text := string(current)
		if currentLength > len(current) {
			text += "...[truncated]"
		}
		redacted := false
		if opts.RedactSecrets {
			text, redacted = redactASCIISecrets(text)
			report.Redacted = report.Redacted || redacted
		}
		remaining := opts.MaxBytes - report.BytesReturned
		if remaining <= 0 {
			report.Truncated = true
			return true
		}
		if len(text) > remaining {
			text = text[:remaining]
			report.Truncated = true
		}
		report.Strings = append(report.Strings, ASCIIString{
			Offset:   currentOffset,
			Length:   currentLength,
			Text:     text,
			Redacted: redacted,
		})
		report.BytesReturned += len(text)
		if report.Truncated || len(report.Strings) >= opts.MaxStrings {
			report.Truncated = true
			return true
		}
		return false
	}

	for {
		n, readErr := file.Read(buf)
		for i := 0; i < n; i++ {
			b := buf[i]
			if isPrintableASCII(b) {
				if currentLength == 0 {
					currentOffset = offset + int64(i)
				}
				currentLength++
				if len(current) < maxASCIIStringTextBytes {
					current = append(current, b)
				}
				continue
			}
			if flush() {
				return report, nil
			}
		}
		offset += int64(n)
		if readErr == io.EOF {
			if flush() {
				return report, nil
			}
			break
		}
		if readErr != nil {
			return ASCIIReport{}, readErr
		}
	}

	return report, nil
}

func isPrintableASCII(b byte) bool {
	return b == '\t' || (b >= 0x20 && b <= 0x7e)
}

var asciiSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b((?:proxy-)?authorization\s*:\s*)[^\r\n]+`),
	regexp.MustCompile(`(?i)\b((?:set-cookie|cookie)\s*:\s*)[^\r\n]+`),
	regexp.MustCompile(`(?i)\b((?:password|passwd|token|api[_-]?key|secret|session[_-]?id)=)[^&;\s]+`),
}

func redactASCIISecrets(text string) (string, bool) {
	redacted := false
	for _, pattern := range asciiSecretPatterns {
		next := pattern.ReplaceAllString(text, `${1}[REDACTED]`)
		if next != text {
			redacted = true
			text = next
		}
	}
	return text, redacted
}

func runAnalyzerCommand(parent context.Context, timeout time.Duration, maxBytes int, name string, args []string, dir string) (analyzerCommandOutput, error) {
	return runAnalyzerCommandWithEnv(parent, timeout, maxBytes, name, args, dir, nil)
}

// runAnalyzerCommandWithEnv extends runAnalyzerCommand with extra
// environment variables (in `KEY=value` form) appended to the
// inherited env. Used by runZeekReport to set SSLKEYLOGFILE for
// TLS decryption without leaking the keylog path into the parent
// process's env.
//
// On non-zero exit (including timeouts) the function still returns
// the captured stdout/stderr alongside the error. Earlier versions
// returned an empty analyzerCommandOutput on failure, which threw
// away salvageable partial evidence (see issue #2: truncated pcaps
// that still produced 99% of useful capinfos / tshark / Zeek
// output were classified as analyzer_failed and discarded).
func runAnalyzerCommandWithEnv(parent context.Context, timeout time.Duration, maxBytes int, name string, args []string, dir string, extraEnv []string) (analyzerCommandOutput, error) {
	if _, err := exec.LookPath(name); err != nil {
		return analyzerCommandOutput{}, fmt.Errorf("%w: %s is not available on PATH", errAnalyzerUnavailable, name)
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	if len(extraEnv) > 0 {
		cmd.Env = append(os.Environ(), extraEnv...)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedBuffer{Buffer: &stdout, Limit: maxBytes}
	cmd.Stderr = &limitedBuffer{Buffer: &stderr, Limit: 64 * 1024}
	runErr := cmd.Run()
	captured := analyzerCommandOutput{Stdout: stdout.String(), Stderr: stderr.String()}
	if runErr != nil {
		if ctx.Err() != nil {
			return captured, fmt.Errorf("%w: %s timed out after %s", errAnalyzerTimeout, name, timeout)
		}
		return captured, fmt.Errorf("%w: %s failed: %s", errAnalyzerFailed, name, strings.TrimSpace(stderr.String()))
	}
	return captured, nil
}

// runAnalyzerCommandTolerant runs the command and treats a known
// truncated-PCAP diagnostic as a non-fatal warning. It returns the
// captured stdout/stderr plus a `truncated` flag; callers branch
// on `truncated` to emit a pcap_truncated finding while still using
// the partial stdout. Other failures (analyzer_unavailable,
// analyzer_timeout, unrecognized analyzer_failed) propagate via
// `err` exactly like runAnalyzerCommand. See issue #2.
func runAnalyzerCommandTolerant(parent context.Context, timeout time.Duration, maxBytes int, name string, args []string, dir string) (analyzerCommandOutput, bool, error) {
	out, err := runAnalyzerCommand(parent, timeout, maxBytes, name, args, dir)
	if err != nil && isTruncatedPCAPDiagnostic(out.Stderr) {
		return out, true, nil
	}
	return out, false, err
}

// isTruncatedPCAPDiagnostic recognizes analyzer stderr that indicates
// the input pcap is cut short mid-record. The analyzer typically
// still wrote useful partial output before bailing — capinfos
// prints capture metadata and reads packets up to the truncation
// point, tshark emits packet rows up to the cut, and Zeek writes
// per-protocol .log files for the readable prefix. Callers branch
// on this so the partial evidence survives instead of being
// discarded as analyzer_failed.
//
// Known phrases (case-insensitive substring match):
//   - tshark / capinfos: "appears to have been cut short in the
//     middle of a packet"
//   - Zeek: "truncated dump file"
//   - Zeek (older builds): "failed to read a packet ... only got"
//
// New phrases land here in the same MR that adds a test pinning
// them; this list is the canonical truncation surface the rest of
// the analyze pipeline trusts.
func isTruncatedPCAPDiagnostic(text string) bool {
	if text == "" {
		return false
	}
	lc := strings.ToLower(text)
	if strings.Contains(lc, "appears to have been cut short in the middle of a packet") {
		return true
	}
	if strings.Contains(lc, "truncated dump file") {
		return true
	}
	if strings.Contains(lc, "failed to read a packet") && strings.Contains(lc, "only got") {
		return true
	}
	return false
}

// truncationFinding builds the standard pcap_truncated warning. The
// `analyzer` argument names the binary that reported the truncation
// (capinfos / tshark / zeek) so a host scanning findings can tell
// which sub-analyzer was affected. The stderr fragment is bounded
// to 240 chars so a runaway diagnostic cannot inflate the response.
func truncationFinding(analyzer, stderrText string) PacketFinding {
	excerpt := strings.TrimSpace(stderrText)
	if len(excerpt) > 240 {
		excerpt = excerpt[:240] + "...[truncated]"
	}
	msg := analyzer + " reported a truncated pcap; partial evidence was preserved."
	if excerpt != "" {
		msg = msg + " Diagnostic: " + excerpt
	}
	return PacketFinding{
		Code:     FindingPCAPTruncated,
		Severity: "warning",
		Message:  msg,
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func firstNonEmptyLine(values ...string) string {
	for _, value := range values {
		for _, line := range strings.Split(value, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				return line
			}
		}
	}
	return ""
}
