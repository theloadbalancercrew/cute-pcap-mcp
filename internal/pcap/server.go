package pcap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"cute-pcap-mcp/internal/config"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	serverName    = "cute-pcap-mcp"
	serverVersion = "0.1.0"
)

type ServerOptions struct {
	Logger *slog.Logger
}

func Run(ctx context.Context, cfg config.Config, opts ServerOptions) error {
	return NewServer(cfg, opts).Run(ctx, &mcp.StdioTransport{})
}

func NewServer(cfg config.Config, opts ServerOptions) *mcp.Server {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: serverName, Version: serverVersion}, nil)
	registerTools(srv, newServerState(cfg, opts.Logger))
	return srv
}

// serverState bundles per-server-instance shared state — config,
// logger, and the analyzer concurrency limiter — so all tool
// callbacks close over the same semaphore. Tests construct an
// instance per t.TempDir() so different tests don't share a slot
// pool.
type serverState struct {
	cfg    config.Config
	logger *slog.Logger
	sem    chan struct{}
}

func newServerState(cfg config.Config, logger *slog.Logger) *serverState {
	cap := cfg.Analysis.MaxConcurrentAnalyses
	if cap <= 0 {
		cap = 1
	}
	return &serverState{cfg: cfg, logger: logger, sem: make(chan struct{}, cap)}
}

// acquireAnalyzerSlot is a non-blocking semaphore acquire. Callers
// that fail to get a slot must surface the typed analysis_busy error
// rather than queueing — the host can retry and we want the
// "saturated" state to be observable, not hidden.
func (s *serverState) acquireAnalyzerSlot() error {
	select {
	case s.sem <- struct{}{}:
		return nil
	default:
		return fmt.Errorf("%w: %d concurrent analyzer slot(s) in use", errAnalysisBusy, cap(s.sem))
	}
}

func (s *serverState) releaseAnalyzerSlot() {
	<-s.sem
}

type inspectInput struct {
	Path              string `json:"path" jsonschema:"absolute or relative path to a pcap/pcapng under an allowed artifact directory"`
	ExpectedSHA256    string `json:"expected_sha256,omitempty" jsonschema:"optional caller-provided sha256 from an external artifact reference; must be exactly 64 hex digits if set; mismatched values return the typed hash_mismatch error"`
	ExpectedSizeBytes *int64 `json:"expected_size_bytes,omitempty" jsonschema:"optional caller-provided file size in bytes from an external artifact reference; must be non-negative if set; mismatched values return the typed size_mismatch error"`
}

type inspectOutput struct {
	Artifact ArtifactInfo `json:"artifact"`
	Error    *toolError   `json:"error,omitempty"`
}

type summarizeInput struct {
	Path              string `json:"path" jsonschema:"absolute or relative path to a pcap/pcapng under an allowed artifact directory"`
	ExpectedSHA256    string `json:"expected_sha256,omitempty" jsonschema:"optional caller-provided sha256 from an external artifact reference; must be exactly 64 hex digits if set"`
	ExpectedSizeBytes *int64 `json:"expected_size_bytes,omitempty" jsonschema:"optional caller-provided file size in bytes from an external artifact reference; must be non-negative if set"`
}

type summarizeOutput struct {
	Artifact       ArtifactInfo      `json:"artifact"`
	Analyzer       string            `json:"analyzer"`
	ProtocolReport string            `json:"protocol_report,omitempty"`
	Conversation   string            `json:"conversation_report,omitempty"`
	Findings       []PacketFinding   `json:"findings"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	Error          *toolError        `json:"error,omitempty"`
}

type ArtifactInfo struct {
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
}

type PacketFinding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// inspectHandler is shared by pcap_validate and its legacy alias
// inspect_pcap. The state field on each registration carries the
// model-facing tool name used in the structured logs so a host can
// tell which name was invoked.
func (s *serverState) inspectHandler(toolName string) func(ctx context.Context, _ *mcp.CallToolRequest, input inspectInput) (*mcp.CallToolResult, inspectOutput, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, input inspectInput) (*mcp.CallToolResult, inspectOutput, error) {
		s.logger.InfoContext(ctx, "tool.start", slog.String("tool", toolName))
		if err := validateArtifactExpectations(input.ExpectedSHA256, input.ExpectedSizeBytes); err != nil {
			terr := classify(err)
			s.logger.InfoContext(ctx, "tool.result", slog.String("tool", toolName), slog.String("outcome", "error"), slog.String("error_kind", terr.Kind))
			return &mcp.CallToolResult{IsError: true}, inspectOutput{Error: &terr}, nil
		}
		artifact, err := inspectArtifact(input.Path, s.cfg, artifactExpectations{
			SHA256:    input.ExpectedSHA256,
			SizeBytes: input.ExpectedSizeBytes,
		})
		if err != nil {
			terr := classify(err)
			s.logger.InfoContext(ctx, "tool.result", slog.String("tool", toolName), slog.String("outcome", "error"), slog.String("error_kind", terr.Kind))
			return &mcp.CallToolResult{IsError: true}, inspectOutput{Error: &terr}, nil
		}
		s.logger.InfoContext(ctx, "tool.result", slog.String("tool", toolName), slog.String("outcome", "success"))
		return nil, inspectOutput{Artifact: artifact}, nil
	}
}

// analyzeErrorOutput builds a hard-error analyzeOutput with the
// stable schema_version stamped. Hosts switch on schema_version
// before parsing the rest of the response; an empty value would
// look like an unversioned legacy reply. The tls_decryption field
// is also stamped (status: not_requested) so the field is always
// present on the wire — without that, hosts that switch on
// tls_decryption.status see the field disappear on hard errors,
// breaking the documented "always present" contract.
func analyzeErrorOutput(artifact ArtifactInfo, terr toolError) analyzeOutput {
	return analyzeOutput{
		SchemaVersion: SchemaVersion,
		Artifact:      artifact,
		Error:         &terr,
		TLSDecryption: &TLSDecryptionStatus{Status: TLSDecryptionStatusNotRequested},
	}
}

// analyzeHandler is shared by pcap_analyze and its legacy alias
// analyze_pcap. The handler runs validation, the size budget check,
// the concurrency acquire, the analyzer pipeline, and (when
// configured) the artifact writer in that order.
func (s *serverState) analyzeHandler(toolName string) func(ctx context.Context, _ *mcp.CallToolRequest, input analyzeInput) (*mcp.CallToolResult, analyzeOutput, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, input analyzeInput) (*mcp.CallToolResult, analyzeOutput, error) {
		s.logger.InfoContext(ctx, "tool.start", slog.String("tool", toolName))
		if err := validateAnalyzeInput(input); err != nil {
			terr := classify(err)
			s.logger.InfoContext(ctx, "tool.result", slog.String("tool", toolName), slog.String("outcome", "error"), slog.String("error_kind", terr.Kind))
			return &mcp.CallToolResult{IsError: true}, analyzeErrorOutput(ArtifactInfo{}, terr), nil
		}
		if err := validateArtifactExpectations(input.ExpectedSHA256, input.ExpectedSizeBytes); err != nil {
			terr := classify(err)
			s.logger.InfoContext(ctx, "tool.result", slog.String("tool", toolName), slog.String("outcome", "error"), slog.String("error_kind", terr.Kind))
			return &mcp.CallToolResult{IsError: true}, analyzeErrorOutput(ArtifactInfo{}, terr), nil
		}
		artifact, err := inspectArtifact(input.Path, s.cfg, artifactExpectations{
			SHA256:    input.ExpectedSHA256,
			SizeBytes: input.ExpectedSizeBytes,
		})
		if err != nil {
			terr := classify(err)
			s.logger.InfoContext(ctx, "tool.result", slog.String("tool", toolName), slog.String("outcome", "error"), slog.String("error_kind", terr.Kind))
			return &mcp.CallToolResult{IsError: true}, analyzeErrorOutput(ArtifactInfo{}, terr), nil
		}
		if err := s.acquireAnalyzerSlot(); err != nil {
			terr := classify(err)
			s.logger.InfoContext(ctx, "tool.result", slog.String("tool", toolName), slog.String("outcome", "error"), slog.String("error_kind", terr.Kind))
			return &mcp.CallToolResult{IsError: true}, analyzeErrorOutput(artifact, terr), nil
		}
		defer s.releaseAnalyzerSlot()
		out := analyzeArtifact(ctx, artifact, s.cfg, input)
		if writeArtifacts(input) && s.cfg.Workspace.OutputDir != "" {
			written, werr := writeAnalysisArtifacts(s.cfg, out)
			if werr != nil {
				out.Errors = append(out.Errors, classify(werr))
			} else {
				out.Artifacts = append(out.Artifacts, written...)
			}
		}
		outcome := "success"
		if len(out.Errors) > 0 {
			outcome = "partial_success"
		}
		s.logger.InfoContext(ctx, "tool.result",
			slog.String("tool", toolName),
			slog.String("outcome", outcome),
			slog.Int("error_count", len(out.Errors)),
		)
		return nil, out, nil
	}
}

func registerTools(server *mcp.Server, state *serverState) {
	cfg := state.cfg
	logger := state.logger

	// pcap_validate is the stable name. inspect_pcap is kept as a
	// compatibility alias for older clients.
	for _, name := range []string{"pcap_validate", "inspect_pcap"} {
		mcp.AddTool(server, &mcp.Tool{
			Name:        name,
			Description: "Validate an allowlisted pcap/pcapng artifact and return artifact metadata (path, size, sha256).",
		}, state.inspectHandler(name))
	}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "pcap_analyzer_status",
		Description: "Report local availability and versions for capinfos, tshark, and Zeek.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ analyzerStatusInput) (*mcp.CallToolResult, analyzerStatusOutput, error) {
		logger.InfoContext(ctx, "tool.start", slog.String("tool", "pcap_analyzer_status"))
		out := analyzerStatuses(ctx, cfg)
		logger.InfoContext(ctx, "tool.result", slog.String("tool", "pcap_analyzer_status"), slog.String("outcome", "success"))
		return nil, out, nil
	})

	// pcap_analyze is the new stable name. analyze_pcap is kept as a
	// compatibility alias for one release.
	for _, name := range []string{"pcap_analyze", "analyze_pcap"} {
		mcp.AddTool(server, &mcp.Tool{
			Name:        name,
			Description: "Analyze an allowlisted pcap/pcapng with capinfos, tshark, Zeek, and bounded printable ASCII extraction. Writes analysis.json + summary.md under workspace.output_dir when configured.",
		}, state.analyzeHandler(name))
	}

	// pcap_filter writes a filtered pcap under workspace.output_dir
	// from a tshark display filter. The output path is server-
	// generated; callers cannot pick a destination.
	mcp.AddTool(server, &mcp.Tool{
		Name:        "pcap_filter",
		Description: "Filter an allowlisted pcap with a tshark display filter and write the filtered packets to a derived pcap under workspace.output_dir. Returns an OutputArtifact reference with path, size, sha256, and content_type.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input filterInput) (*mcp.CallToolResult, filterOutput, error) {
		logger.InfoContext(ctx, "tool.start", slog.String("tool", "pcap_filter"))
		if err := validateFilterInput(input); err != nil {
			terr := classify(err)
			logger.InfoContext(ctx, "tool.result", slog.String("tool", "pcap_filter"), slog.String("outcome", "error"), slog.String("error_kind", terr.Kind))
			return &mcp.CallToolResult{IsError: true}, filterErrorOutput(ArtifactInfo{}, terr), nil
		}
		if err := validateArtifactExpectations(input.ExpectedSHA256, input.ExpectedSizeBytes); err != nil {
			terr := classify(err)
			logger.InfoContext(ctx, "tool.result", slog.String("tool", "pcap_filter"), slog.String("outcome", "error"), slog.String("error_kind", terr.Kind))
			return &mcp.CallToolResult{IsError: true}, filterErrorOutput(ArtifactInfo{}, terr), nil
		}
		source, err := inspectArtifact(input.Path, cfg, artifactExpectations{
			SHA256:    input.ExpectedSHA256,
			SizeBytes: input.ExpectedSizeBytes,
		})
		if err != nil {
			terr := classify(err)
			logger.InfoContext(ctx, "tool.result", slog.String("tool", "pcap_filter"), slog.String("outcome", "error"), slog.String("error_kind", terr.Kind))
			return &mcp.CallToolResult{IsError: true}, filterErrorOutput(ArtifactInfo{}, terr), nil
		}
		if err := state.acquireAnalyzerSlot(); err != nil {
			terr := classify(err)
			logger.InfoContext(ctx, "tool.result", slog.String("tool", "pcap_filter"), slog.String("outcome", "error"), slog.String("error_kind", terr.Kind))
			return &mcp.CallToolResult{IsError: true}, filterErrorOutput(source, terr), nil
		}
		defer state.releaseAnalyzerSlot()

		artifact, packetCount, warnings, err := runFilter(ctx, source, cfg, strings.TrimSpace(input.DisplayFilter))
		if err != nil {
			terr := classify(err)
			logger.InfoContext(ctx, "tool.result", slog.String("tool", "pcap_filter"), slog.String("outcome", "error"), slog.String("error_kind", terr.Kind))
			return &mcp.CallToolResult{IsError: true}, filterErrorOutput(source, terr), nil
		}
		logger.InfoContext(ctx, "tool.result", slog.String("tool", "pcap_filter"), slog.String("outcome", "success"), slog.Int64("packet_count", packetCount))
		// On the success path tsharkHasAnyPacket already confirmed the
		// derived pcap is non-empty, so packetCount == 0 here means
		// "capinfos was unavailable or unparseable," not "really zero
		// packets." The finding message must reflect that distinction;
		// otherwise hosts switching on the message would see false
		// evidence of a zero-packet write.
		var message string
		if packetCount > 0 {
			message = fmt.Sprintf("Wrote filtered pcap with %d packets matching the display filter.", packetCount)
		} else {
			message = "Wrote filtered pcap matching the display filter; exact packet count unavailable (capinfos missing or unparseable)."
		}
		findings := []PacketFinding{{
			Code:     FindingFilteredPCAPWritten,
			Severity: "info",
			Message:  message,
		}}
		// Truncation warnings from runFilter (issue #2): tshark
		// reported a truncated source pcap but still wrote the
		// readable prefix into the derived artifact. Surface as
		// findings alongside the success path; the artifact is
		// genuine, just bounded by the source's truncation.
		findings = append(findings, warnings...)
		return nil, filterOutput{
			SchemaVersion: SchemaVersion,
			Source:        source,
			Artifact:      artifact,
			PacketCount:   packetCount,
			DisplayFilter: strings.TrimSpace(input.DisplayFilter),
			Findings:      findings,
		}, nil
	})

	// pcap_explain_connection scopes the analyze pipeline to a single
	// connection identified by zeek_uid, five_tuple, or frame_number.
	// Output is the analyzeOutput shape plus a ResolvedSelector echo.
	mcp.AddTool(server, &mcp.Tool{
		Name:        "pcap_explain_connection",
		Description: "Run the analyze pipeline scoped to one connection identified by zeek_uid, five_tuple, or frame_number. Returns the same shape as pcap_analyze plus a resolved selector echo and a connection_evidence_scoped finding.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input explainInput) (*mcp.CallToolResult, explainOutput, error) {
		logger.InfoContext(ctx, "tool.start", slog.String("tool", "pcap_explain_connection"))
		if err := validateExplainInput(input); err != nil {
			terr := classify(err)
			logger.InfoContext(ctx, "tool.result", slog.String("tool", "pcap_explain_connection"), slog.String("outcome", "error"), slog.String("error_kind", terr.Kind))
			return &mcp.CallToolResult{IsError: true}, explainErrorOutput(ArtifactInfo{}, terr), nil
		}
		if err := validateArtifactExpectations(input.ExpectedSHA256, input.ExpectedSizeBytes); err != nil {
			terr := classify(err)
			logger.InfoContext(ctx, "tool.result", slog.String("tool", "pcap_explain_connection"), slog.String("outcome", "error"), slog.String("error_kind", terr.Kind))
			return &mcp.CallToolResult{IsError: true}, explainErrorOutput(ArtifactInfo{}, terr), nil
		}
		source, err := inspectArtifact(input.Path, cfg, artifactExpectations{
			SHA256:    input.ExpectedSHA256,
			SizeBytes: input.ExpectedSizeBytes,
		})
		if err != nil {
			terr := classify(err)
			logger.InfoContext(ctx, "tool.result", slog.String("tool", "pcap_explain_connection"), slog.String("outcome", "error"), slog.String("error_kind", terr.Kind))
			return &mcp.CallToolResult{IsError: true}, explainErrorOutput(ArtifactInfo{}, terr), nil
		}
		if err := state.acquireAnalyzerSlot(); err != nil {
			terr := classify(err)
			logger.InfoContext(ctx, "tool.result", slog.String("tool", "pcap_explain_connection"), slog.String("outcome", "error"), slog.String("error_kind", terr.Kind))
			return &mcp.CallToolResult{IsError: true}, explainErrorOutput(source, terr), nil
		}
		defer state.releaseAnalyzerSlot()

		out := explainConnection(ctx, source, cfg, input)
		// Hard failures from selector resolution (bad frame_number,
		// missing zeek_uid, etc.) come back with out.Error set. The
		// MCP contract is that hard failures must IsError=true, not
		// be embedded in a non-error response. Skip artifact
		// persistence in that case — there's nothing useful to
		// persist.
		if out.Error != nil {
			logger.InfoContext(ctx, "tool.result",
				slog.String("tool", "pcap_explain_connection"),
				slog.String("outcome", "error"),
				slog.String("error_kind", out.Error.Kind),
			)
			return &mcp.CallToolResult{IsError: true}, out, nil
		}
		// Default-on artifact persistence matches pcap_analyze: write
		// when the operator hasn't opted out and output_dir is
		// configured.
		shouldWrite := input.WriteArtifacts == nil || *input.WriteArtifacts
		if shouldWrite && cfg.Workspace.OutputDir != "" {
			written, werr := writeAnalysisArtifacts(cfg, out.analyzeOutput)
			if werr != nil {
				out.Errors = append(out.Errors, classify(werr))
			} else {
				out.Artifacts = append(out.Artifacts, written...)
			}
		}
		outcome := "success"
		if len(out.Errors) > 0 {
			outcome = "partial_success"
		}
		logger.InfoContext(ctx, "tool.result",
			slog.String("tool", "pcap_explain_connection"),
			slog.String("outcome", outcome),
			slog.String("resolution", out.Selector.Resolution),
			slog.Int("error_count", len(out.Errors)),
		)
		return nil, out, nil
	})

	// summarize_pcap is the legacy tshark-only protocol-hierarchy
	// preview. Kept registered for compatibility; the new pcap_analyze
	// covers a strict superset of what summarize_pcap returns.
	mcp.AddTool(server, &mcp.Tool{
		Name:        "summarize_pcap",
		Description: "Run tshark against an allowlisted pcap/pcapng and return redacted packet evidence summaries, not raw payload bytes.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input summarizeInput) (*mcp.CallToolResult, summarizeOutput, error) {
		logger.InfoContext(ctx, "tool.start", slog.String("tool", "summarize_pcap"))
		if err := validateArtifactExpectations(input.ExpectedSHA256, input.ExpectedSizeBytes); err != nil {
			terr := classify(err)
			logger.InfoContext(ctx, "tool.result", slog.String("tool", "summarize_pcap"), slog.String("outcome", "error"), slog.String("error_kind", terr.Kind))
			return &mcp.CallToolResult{IsError: true}, summarizeOutput{Error: &terr}, nil
		}
		artifact, err := inspectArtifact(input.Path, cfg, artifactExpectations{
			SHA256:    input.ExpectedSHA256,
			SizeBytes: input.ExpectedSizeBytes,
		})
		if err != nil {
			terr := classify(err)
			logger.InfoContext(ctx, "tool.result", slog.String("tool", "summarize_pcap"), slog.String("outcome", "error"), slog.String("error_kind", terr.Kind))
			return &mcp.CallToolResult{IsError: true}, summarizeOutput{Error: &terr}, nil
		}
		if err := state.acquireAnalyzerSlot(); err != nil {
			terr := classify(err)
			logger.InfoContext(ctx, "tool.result", slog.String("tool", "summarize_pcap"), slog.String("outcome", "error"), slog.String("error_kind", terr.Kind))
			return &mcp.CallToolResult{IsError: true}, summarizeOutput{Artifact: artifact, Error: &terr}, nil
		}
		defer state.releaseAnalyzerSlot()
		out, truncated, err := runTShark(ctx, artifact.Path, cfg.Timeout(), cfg.Analysis.MaxStdoutBytes, nil)
		if err != nil {
			terr := classify(err)
			logger.InfoContext(ctx, "tool.result", slog.String("tool", "summarize_pcap"), slog.String("outcome", "error"), slog.String("error_kind", terr.Kind))
			return &mcp.CallToolResult{IsError: true}, summarizeOutput{Artifact: artifact, Error: &terr}, nil
		}
		findings := []PacketFinding{{
			Code:     FindingSummaryGenerated,
			Severity: "info",
			Message:  "Generated protocol hierarchy summary with tshark; packet payload bytes are not returned.",
		}}
		if truncated {
			findings = append(findings, truncationFinding("tshark", "input pcap appears to have been cut short in the middle of a packet"))
		}
		logger.InfoContext(ctx, "tool.result", slog.String("tool", "summarize_pcap"), slog.String("outcome", "success"))
		return nil, summarizeOutput{
			Artifact:       artifact,
			Analyzer:       "tshark",
			ProtocolReport: out,
			Findings:       findings,
		}, nil
	})
}

// artifactExpectations carries optional caller-provided checksums
// for the external artifact reference contract. SHA256 is
// empty when not supplied; SizeBytes is nil when not supplied (the
// pointer distinguishes "no expectation" from "expect a zero-byte
// file"). inspectArtifact enforces only the set fields.
//
// Format validation lives in validateArtifactExpectations and runs
// before inspectArtifact so a malformed expected_sha256 returns the
// typed validation_failed kind, not a misleading hash_mismatch
// computed against random caller input. The validator also keeps the
// untrusted caller value out of the model-facing error message — only
// the actual computed hash is echoed back.
type artifactExpectations struct {
	SHA256    string
	SizeBytes *int64
}

// sha256HexPattern is exactly 64 lowercase or uppercase hex digits.
// Anything else is a structurally bad input and gets validation_failed
// before the server even opens the artifact.
var sha256HexPattern = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// validateArtifactExpectations rejects malformed caller input for the
// expected_sha256 / expected_size_bytes fields. Tool input validators
// call this first thing so the typed error mirrors the field that was
// wrong, not a downstream side-effect.
func validateArtifactExpectations(sha256 string, sizeBytes *int64) error {
	if sha256 != "" && !sha256HexPattern.MatchString(sha256) {
		return validationError("expected_sha256", ValidationReasonInvalidFormat,
			"expected_sha256 must be exactly 64 hex digits")
	}
	if sizeBytes != nil && *sizeBytes < 0 {
		return validationError("expected_size_bytes", ValidationReasonOutOfRange,
			"expected_size_bytes must be non-negative")
	}
	return nil
}

func inspectArtifact(path string, cfg config.Config, expected artifactExpectations) (ArtifactInfo, error) {
	if path == "" {
		return ArtifactInfo{}, missingFieldError("path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return ArtifactInfo{}, err
	}
	abs = filepath.Clean(abs)
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return ArtifactInfo{}, fmt.Errorf("%w: %s", errArtifactNotFound, abs)
		}
		return ArtifactInfo{}, err
	}
	abs = filepath.Clean(resolved)
	if !underAny(abs, cfg.AllowedArtifactDirs) {
		return ArtifactInfo{}, errPathOutsideAllowlist
	}
	info, err := os.Stat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return ArtifactInfo{}, fmt.Errorf("%w: %s", errArtifactNotFound, abs)
		}
		return ArtifactInfo{}, err
	}
	if !info.Mode().IsRegular() {
		return ArtifactInfo{}, errArtifactNotRegular
	}
	if cfg.Analysis.MaxPCAPBytes > 0 && info.Size() > cfg.Analysis.MaxPCAPBytes {
		return ArtifactInfo{}, fmt.Errorf("%w: %d bytes exceeds analysis.max_pcap_bytes (%d)",
			errPCAPTooLarge, info.Size(), cfg.Analysis.MaxPCAPBytes)
	}
	// Cheap size pre-check before reading bytes for the hash. A
	// producer that supplied size_bytes but not sha256 still gets a
	// fail-fast typed error here without paying for the hash read.
	if expected.SizeBytes != nil && info.Size() != *expected.SizeBytes {
		return ArtifactInfo{}, fmt.Errorf("%w: artifact size %d bytes does not match expected_size_bytes (%d)",
			errSizeMismatch, info.Size(), *expected.SizeBytes)
	}
	file, err := os.Open(abs)
	if err != nil {
		return ArtifactInfo{}, err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return ArtifactInfo{}, err
	}
	actualSHA256 := hex.EncodeToString(hash.Sum(nil))
	if expected.SHA256 != "" && !strings.EqualFold(actualSHA256, expected.SHA256) {
		// Echo only the actual hash. The caller-provided value is
		// untrusted: a malformed or absurdly large string would bloat
		// the MCP output if we round-tripped it. Format validation
		// already ran in validateArtifactExpectations, so by the time
		// we reach this branch the input was 64 hex digits — but the
		// caller still has the value they sent and does not need it
		// reflected back.
		return ArtifactInfo{}, fmt.Errorf("%w: artifact sha256 %s does not match expected_sha256",
			errHashMismatch, actualSHA256)
	}
	return ArtifactInfo{
		Path:      abs,
		SizeBytes: info.Size(),
		SHA256:    actualSHA256,
	}, nil
}

func underAny(path string, allowedDirs []string) bool {
	for _, dir := range allowedDirs {
		rel, err := filepath.Rel(dir, path)
		if err == nil && rel != "." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && rel != ".." {
			return true
		}
	}
	return false
}

func runTShark(parent context.Context, path string, timeout time.Duration, maxBytes int, keylogArgs []string) (string, bool, error) {
	args := []string{"-n", "-r", path, "-q", "-z", "io,phs"}
	args = append(keylogArgs, args...)
	out, truncated, err := runAnalyzerCommandTolerant(parent, timeout, maxBytes, "tshark", args, "")
	if err != nil {
		return "", false, err
	}
	return out.Stdout, truncated, nil
}

type limitedBuffer struct {
	*bytes.Buffer
	Limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	originalLen := len(p)
	if b.Buffer.Len() >= b.Limit {
		return originalLen, nil
	}
	remaining := b.Limit - b.Buffer.Len()
	if len(p) > remaining {
		p = p[:remaining]
	}
	_, _ = b.Buffer.Write(p)
	return originalLen, nil
}
