package pcap

import (
	"errors"
	"fmt"
	"strings"
)

// Error kind tokens. These are the stable model-facing identifiers a host
// or LLM may switch on. Never rename; only add. Messages are human
// fallback only and must not be parsed.
//
// Emission status is documented per tool in docs/PCAP_SERVER_CONTRACT.md.
// Kinds defined here without an emission site today exist so future
// milestones (workspace size limits, artifact reference validation,
// concurrent analyzer budgets) can land an emission point without a wire
// change.
const (
	// ErrorKindInvalidRequest is the catch-all kind for malformed input
	// that does not have a more specific token. Prefer a typed kind
	// when one fits.
	ErrorKindInvalidRequest = "invalid_request"

	// ErrorKindMissingField is emitted when a required input field is
	// empty or absent.
	ErrorKindMissingField = "missing_field"

	// ErrorKindValidationFailed is emitted when a per-field input value
	// is the wrong shape. The message carries the offending field and a
	// stable ValidationReason* token.
	ErrorKindValidationFailed = "validation_failed"

	// ErrorKindPathOutsideAllowlist is emitted when a pcap path resolves
	// outside every configured allowlisted directory, including via
	// symlink traversal.
	ErrorKindPathOutsideAllowlist = "path_outside_allowlist"

	// ErrorKindArtifactNotRegularFile is emitted when an allowlisted
	// path points to a directory, device, fifo, or other non-regular
	// file.
	ErrorKindArtifactNotRegularFile = "artifact_not_regular_file"

	// ErrorKindArtifactNotFound is emitted when the resolved path does
	// not exist on disk.
	ErrorKindArtifactNotFound = "artifact_not_found"

	// ErrorKindPCAPTooLarge is emitted when an allowlisted pcap exceeds
	// the configured byte budget. Lands with the workspace work in M1.
	ErrorKindPCAPTooLarge = "pcap_too_large"

	// ErrorKindEmptyCapture is emitted when capinfos or tshark report
	// zero packets in an otherwise valid capture file.
	ErrorKindEmptyCapture = "empty_capture"

	// ErrorKindNoPacketsMatched is emitted when a display filter or
	// connection selector resolves to zero rows. Distinct from
	// empty_capture: the capture has packets, just none after filtering.
	ErrorKindNoPacketsMatched = "no_packets_matched"

	// ErrorKindInvalidFilter is emitted when a display filter fails
	// validation or is rejected by tshark. Distinct from
	// validation_failed because the filter language has its own
	// surface.
	ErrorKindInvalidFilter = "invalid_filter"

	// ErrorKindHashMismatch is emitted when a caller-provided
	// expected_sha256 disagrees with the on-disk artifact. Lands with
	// the external artifact reference work in M3.
	ErrorKindHashMismatch = "hash_mismatch"

	// ErrorKindSizeMismatch is emitted when a caller-provided
	// expected_size_bytes disagrees with the on-disk artifact. Lands
	// with the external artifact reference work in M3.
	ErrorKindSizeMismatch = "size_mismatch"

	// ErrorKindOutputLimitReached is emitted when the per-call output
	// budget is exhausted before all available evidence could be
	// returned. Distinct from per-section truncation flags: this is a
	// hard error that signals "results are incomplete and we stopped."
	ErrorKindOutputLimitReached = "output_limit_reached"

	// ErrorKindTmpBudgetExceeded is emitted when the configured tmp-dir
	// disk budget would be exceeded by a Zeek run or other temp work.
	// Lands with the workspace work in M1.
	ErrorKindTmpBudgetExceeded = "tmp_budget_exceeded"

	// ErrorKindAnalysisBusy is emitted when the configured concurrent
	// analyzer cap is reached and the call cannot proceed. Lands with
	// the workspace work in M1.
	ErrorKindAnalysisBusy = "analysis_busy"

	// ErrorKindAnalyzerUnavailable is emitted when an external analyzer
	// (capinfos, tshark, zeek) is not on PATH. The full evidence set is
	// degraded; partial results may still be returned via output errors.
	ErrorKindAnalyzerUnavailable = "analyzer_unavailable"

	// ErrorKindAnalyzerFailed is emitted when an external analyzer ran
	// but exited non-zero or hit the call timeout. The message carries
	// a bounded fragment of the analyzer's stderr.
	ErrorKindAnalyzerFailed = "analyzer_failed"

	// ErrorKindAnalyzerTimeout is emitted when an external analyzer hit
	// the per-call timeout. Distinct from analyzer_failed because the
	// remediation is "raise the budget or narrow the call," not "fix the
	// capture."
	ErrorKindAnalyzerTimeout = "analyzer_timeout"
)

// ValidationReason tokens describe stable, per-field reasons for a
// validation_failed entry. Each reason is a token the host may switch on.
const (
	ValidationReasonEmpty         = "empty"
	ValidationReasonInvalidFormat = "invalid_format"
	ValidationReasonOutOfRange    = "out_of_range"
	ValidationReasonContainsNUL   = "contains_nul"
	ValidationReasonTooLong       = "too_long"
)

// FindingCode tokens describe stable, model-facing codes that appear in
// PacketFinding.Code. Findings are always informational/warning-level
// signals about the analysis itself, not packet-content claims.
const (
	FindingAnalysisGenerated      = "analysis_generated"
	FindingSummaryGenerated       = "summary_generated"
	FindingTSharkAnalysisAvail    = "tshark_analysis_available"
	FindingZeekAnalysisAvail      = "zeek_analysis_available"
	FindingASCIIStringsExtracted  = "ascii_strings_extracted"
	FindingASCIIStringsRedacted   = "ascii_strings_redacted"
	FindingASCIIStringsTruncated  = "ascii_strings_truncated"
	FindingZeekNoticesPresent     = "zeek_notices_present"
	FindingZeekWeirdEventsPresent = "zeek_weird_events_present"
	FindingHTTPErrorStatuses      = "http_error_statuses_present"
	FindingDNSRejectionsPresent   = "dns_rejections_present"
	FindingTCPResetsPresent       = "tcp_resets_present"
	FindingFilteredPCAPWritten      = "filtered_pcap_written"
	FindingConnectionEvidenceScoped = "connection_evidence_scoped"
	FindingF5ProfileResetsObserved  = "f5_profile_resets_observed"
	FindingF5ProfileTLSObserved     = "f5_profile_tls_observed"
	FindingF5ProfileHTTPObserved    = "f5_profile_http_observed"
	FindingProfileApplied           = "analysis_profile_applied"
	FindingProfileUnknown           = "analysis_profile_unknown"
)

// Sentinel errors used internally and matched via errors.Is. The wire
// kind comes from classify(); these values are not model-facing.
var (
	errPathOutsideAllowlist = errors.New(ErrorKindPathOutsideAllowlist)
	errArtifactNotRegular   = errors.New(ErrorKindArtifactNotRegularFile)
	errArtifactNotFound     = errors.New(ErrorKindArtifactNotFound)
	errAnalyzerUnavailable  = errors.New(ErrorKindAnalyzerUnavailable)
	errAnalyzerFailed       = errors.New(ErrorKindAnalyzerFailed)
	errAnalyzerTimeout      = errors.New(ErrorKindAnalyzerTimeout)
	errMissingField         = errors.New(ErrorKindMissingField)
	errValidationFailed     = errors.New(ErrorKindValidationFailed)
	errInvalidFilter        = errors.New(ErrorKindInvalidFilter)
	errPCAPTooLarge         = errors.New(ErrorKindPCAPTooLarge)
	errTmpBudgetExceeded    = errors.New(ErrorKindTmpBudgetExceeded)
	errAnalysisBusy         = errors.New(ErrorKindAnalysisBusy)
	errOutputLimitReached   = errors.New(ErrorKindOutputLimitReached)
	errNoPacketsMatched     = errors.New(ErrorKindNoPacketsMatched)
	errHashMismatch         = errors.New(ErrorKindHashMismatch)
	errSizeMismatch         = errors.New(ErrorKindSizeMismatch)
)

// validationFailure is the structured validation_failed error. classify
// pulls Field + Reason out via errors.As so the wire shape carries the
// stable per-field tokens promised by the contract.
type validationFailure struct {
	Field   string
	Reason  string
	Message string
}

func (e *validationFailure) Error() string {
	return fmt.Sprintf("%s: %s: %s (%s)", ErrorKindValidationFailed, e.Field, e.Message, e.Reason)
}

// Is wires errors.Is(err, errValidationFailed) to the typed value so
// callers can still pattern-match on the sentinel.
func (e *validationFailure) Is(target error) bool { return target == errValidationFailed }

// toolError is the model-facing error shape. Kind is the stable token,
// Message is human fallback (never parse it), Retryable is a hint for
// orchestration, and Remediation is an optional human-fallback hint.
type toolError struct {
	Kind        string `json:"kind"`
	Message     string `json:"message,omitempty"`
	Retryable   bool   `json:"retryable,omitempty"`
	Remediation string `json:"remediation,omitempty"`
	Field       string `json:"field,omitempty"`
	Reason      string `json:"reason,omitempty"`
}

// classify maps a sentinel-wrapped error to a typed toolError. It is the
// single point that produces a model-facing kind from internal failures,
// so the kind set is exhaustively visible here.
func classify(err error) toolError {
	var vf *validationFailure
	if errors.As(err, &vf) {
		return toolError{
			Kind:    ErrorKindValidationFailed,
			Field:   vf.Field,
			Reason:  vf.Reason,
			Message: vf.Message,
		}
	}
	switch {
	case errors.Is(err, errPathOutsideAllowlist):
		return toolError{
			Kind:        ErrorKindPathOutsideAllowlist,
			Message:     "pcap path is not under an allowed artifact directory",
			Remediation: "place the pcap under a configured allowed_artifact_dirs entry, or extend the allowlist on the server",
		}
	case errors.Is(err, errArtifactNotRegular):
		return toolError{
			Kind:        ErrorKindArtifactNotRegularFile,
			Message:     "pcap path must point to a regular file",
			Remediation: "supply a path to a single pcap/pcapng file, not a directory or device",
		}
	case errors.Is(err, errArtifactNotFound):
		return toolError{
			Kind:        ErrorKindArtifactNotFound,
			Message:     "pcap artifact does not exist on disk",
			Remediation: "verify the path; if this came from an external artifact producer, regenerate or replace the artifact",
		}
	case errors.Is(err, errAnalyzerUnavailable):
		return toolError{
			Kind:        ErrorKindAnalyzerUnavailable,
			Message:     trimSentinelPrefix(err, errAnalyzerUnavailable),
			Remediation: "install the missing analyzer in the server runtime, or use the Docker image which bundles capinfos, tshark, and zeek",
		}
	case errors.Is(err, errAnalyzerTimeout):
		return toolError{
			Kind:        ErrorKindAnalyzerTimeout,
			Message:     trimSentinelPrefix(err, errAnalyzerTimeout),
			Retryable:   true,
			Remediation: "raise analysis.command_timeout_seconds, narrow the display_filter, or lower max_packet_rows",
		}
	case errors.Is(err, errAnalyzerFailed):
		return toolError{
			Kind:    ErrorKindAnalyzerFailed,
			Message: trimSentinelPrefix(err, errAnalyzerFailed),
		}
	case errors.Is(err, errInvalidFilter):
		return toolError{
			Kind:        ErrorKindInvalidFilter,
			Message:     trimSentinelPrefix(err, errInvalidFilter),
			Field:       "display_filter",
			Remediation: "supply a valid tshark display filter (e.g. \"tcp.port == 443\")",
		}
	case errors.Is(err, errMissingField):
		return toolError{
			Kind:    ErrorKindMissingField,
			Message: trimSentinelPrefix(err, errMissingField),
		}
	case errors.Is(err, errValidationFailed):
		return toolError{
			Kind:    ErrorKindValidationFailed,
			Message: trimSentinelPrefix(err, errValidationFailed),
		}
	case errors.Is(err, errPCAPTooLarge):
		return toolError{
			Kind:        ErrorKindPCAPTooLarge,
			Message:     trimSentinelPrefix(err, errPCAPTooLarge),
			Remediation: "raise analysis.max_pcap_bytes if the operator workstation can afford it, or split / decimate the capture before submitting",
		}
	case errors.Is(err, errTmpBudgetExceeded):
		return toolError{
			Kind:        ErrorKindTmpBudgetExceeded,
			Message:     trimSentinelPrefix(err, errTmpBudgetExceeded),
			Remediation: "raise analysis.tmp_disk_budget_bytes, lower max_packet_rows / max_zeek_records_per_log, or set include_zeek=false",
		}
	case errors.Is(err, errAnalysisBusy):
		return toolError{
			Kind:        ErrorKindAnalysisBusy,
			Message:     trimSentinelPrefix(err, errAnalysisBusy),
			Retryable:   true,
			Remediation: "retry after a previous analyze_pcap / summarize_pcap call completes, or raise analysis.max_concurrent_analyses",
		}
	case errors.Is(err, errOutputLimitReached):
		return toolError{
			Kind:        ErrorKindOutputLimitReached,
			Message:     trimSentinelPrefix(err, errOutputLimitReached),
			Remediation: "raise analysis.output_disk_budget_bytes, or lower per-call evidence budgets (max_packet_rows, max_zeek_records_per_log, max_ascii_strings, max_ascii_bytes)",
		}
	case errors.Is(err, errNoPacketsMatched):
		return toolError{
			Kind:        ErrorKindNoPacketsMatched,
			Message:     trimSentinelPrefix(err, errNoPacketsMatched),
			Field:       "display_filter",
			Remediation: "loosen the display filter, or use pcap_validate first to confirm the source pcap has packets in the expected protocol",
		}
	case errors.Is(err, errHashMismatch):
		return toolError{
			Kind:        ErrorKindHashMismatch,
			Message:     trimSentinelPrefix(err, errHashMismatch),
			Field:       "expected_sha256",
			Remediation: "verify the producer wrote the file completely; if the producer did not compute the hash, omit expected_sha256 and the server will compute it",
		}
	case errors.Is(err, errSizeMismatch):
		return toolError{
			Kind:        ErrorKindSizeMismatch,
			Message:     trimSentinelPrefix(err, errSizeMismatch),
			Field:       "expected_size_bytes",
			Remediation: "verify the producer wrote the file completely; if the producer did not measure the size, omit expected_size_bytes and the server will report the actual size",
		}
	default:
		return toolError{Kind: ErrorKindInvalidRequest, Message: err.Error()}
	}
}

// missingFieldError builds a missing_field error for the given input
// field name.
func missingFieldError(field string) error {
	return fmt.Errorf("%w: %s is required", errMissingField, field)
}

// validationError builds a validation_failed error tagged with a
// per-field stable reason token. classify pulls these tokens out via
// errors.As so the wire toolError carries Field + Reason.
func validationError(field, reason, msg string) error {
	return &validationFailure{Field: field, Reason: reason, Message: msg}
}

// invalidFilterError wraps a tshark display-filter rejection in the
// invalid_filter kind. Callers pass a bounded fragment; raw stderr from
// tshark must already be trimmed.
func invalidFilterError(detail string) error {
	return fmt.Errorf("%w: %s", errInvalidFilter, detail)
}

// trimSentinelPrefix strips the "kind: " prefix that the sentinel
// errors carry so the model-facing message starts with the human
// fragment, not the kind token.
func trimSentinelPrefix(err error, sentinel error) string {
	msg := err.Error()
	prefix := sentinel.Error() + ": "
	return strings.TrimPrefix(msg, prefix)
}
