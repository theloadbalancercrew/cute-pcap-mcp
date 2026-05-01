package pcap

import (
	"errors"
	"fmt"
	"testing"
)

// TestClassifyEmitsStableKinds is the truth table for the typed error
// taxonomy. Hosts switch on `Kind` tokens; this test pins the wire
// values so a future refactor cannot rename them silently.
func TestClassifyEmitsStableKinds(t *testing.T) {
	cases := []struct {
		name        string
		err         error
		wantKind    string
		wantField   string
		wantReason  string
		wantRetry   bool
		wantRemHint bool
	}{
		{
			name:        "path_outside_allowlist",
			err:         errPathOutsideAllowlist,
			wantKind:    ErrorKindPathOutsideAllowlist,
			wantRemHint: true,
		},
		{
			name:        "artifact_not_regular_file",
			err:         errArtifactNotRegular,
			wantKind:    ErrorKindArtifactNotRegularFile,
			wantRemHint: true,
		},
		{
			name:        "artifact_not_found",
			err:         fmt.Errorf("%w: /tmp/nope.pcap", errArtifactNotFound),
			wantKind:    ErrorKindArtifactNotFound,
			wantRemHint: true,
		},
		{
			name:        "analyzer_unavailable",
			err:         fmt.Errorf("%w: tshark is not available on PATH", errAnalyzerUnavailable),
			wantKind:    ErrorKindAnalyzerUnavailable,
			wantRemHint: true,
		},
		{
			name:     "analyzer_failed",
			err:      fmt.Errorf("%w: zeek failed: bad input", errAnalyzerFailed),
			wantKind: ErrorKindAnalyzerFailed,
		},
		{
			name:        "analyzer_timeout",
			err:         fmt.Errorf("%w: tshark timed out after 20s", errAnalyzerTimeout),
			wantKind:    ErrorKindAnalyzerTimeout,
			wantRetry:   true,
			wantRemHint: true,
		},
		{
			name:      "missing_field",
			err:       missingFieldError("path"),
			wantKind:  ErrorKindMissingField,
			wantField: "",
		},
		{
			name:       "validation_failed_too_long",
			err:        validationError("display_filter", ValidationReasonTooLong, "must be 4096 bytes or less"),
			wantKind:   ErrorKindValidationFailed,
			wantField:  "display_filter",
			wantReason: ValidationReasonTooLong,
		},
		{
			name:       "validation_failed_contains_nul",
			err:        validationError("display_filter", ValidationReasonContainsNUL, "must not contain NUL bytes"),
			wantKind:   ErrorKindValidationFailed,
			wantField:  "display_filter",
			wantReason: ValidationReasonContainsNUL,
		},
		{
			name:       "validation_failed_out_of_range",
			err:        validationError("min_string_length", ValidationReasonOutOfRange, "must be non-negative"),
			wantKind:   ErrorKindValidationFailed,
			wantField:  "min_string_length",
			wantReason: ValidationReasonOutOfRange,
		},
		{
			name:        "invalid_filter",
			err:         invalidFilterError("tshark: \"foo\" isn't a valid display filter"),
			wantKind:    ErrorKindInvalidFilter,
			wantField:   "display_filter",
			wantRemHint: true,
		},
		{
			name:     "default_invalid_request",
			err:      errors.New("anything else"),
			wantKind: ErrorKindInvalidRequest,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classify(tc.err)
			if got.Kind != tc.wantKind {
				t.Fatalf("classify(%q).Kind = %q, want %q", tc.err, got.Kind, tc.wantKind)
			}
			if got.Field != tc.wantField {
				t.Fatalf("Field = %q, want %q", got.Field, tc.wantField)
			}
			if got.Reason != tc.wantReason {
				t.Fatalf("Reason = %q, want %q", got.Reason, tc.wantReason)
			}
			if got.Retryable != tc.wantRetry {
				t.Fatalf("Retryable = %v, want %v", got.Retryable, tc.wantRetry)
			}
			if tc.wantRemHint && got.Remediation == "" {
				t.Fatal("Remediation is empty, want a non-empty hint")
			}
			if got.Message == "" && tc.wantKind != ErrorKindInvalidRequest {
				t.Fatal("Message is empty; classify should always set a human fallback")
			}
		})
	}
}

func TestValidationErrorCarriesStableTokens(t *testing.T) {
	cases := []struct {
		name   string
		reason string
	}{
		{name: "empty", reason: ValidationReasonEmpty},
		{name: "invalid_format", reason: ValidationReasonInvalidFormat},
		{name: "out_of_range", reason: ValidationReasonOutOfRange},
		{name: "contains_nul", reason: ValidationReasonContainsNUL},
		{name: "too_long", reason: ValidationReasonTooLong},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validationError("some_field", tc.reason, "msg")
			if !errors.Is(err, errValidationFailed) {
				t.Fatalf("err is not validation_failed: %v", err)
			}
			if classify(err).Kind != ErrorKindValidationFailed {
				t.Fatalf("classify Kind = %q", classify(err).Kind)
			}
		})
	}
}

func TestValidateAnalyzeInputRejectsBadFilters(t *testing.T) {
	cases := []struct {
		name     string
		input    analyzeInput
		wantKind string
	}{
		{
			name:     "missing_path",
			input:    analyzeInput{},
			wantKind: ErrorKindMissingField,
		},
		{
			name:     "filter_with_nul",
			input:    analyzeInput{Path: "x", DisplayFilter: "tcp\x00port == 80"},
			wantKind: ErrorKindValidationFailed,
		},
		{
			name:     "filter_too_long",
			input:    analyzeInput{Path: "x", DisplayFilter: tooLong(5000)},
			wantKind: ErrorKindValidationFailed,
		},
		{
			name:     "min_string_length_negative",
			input:    analyzeInput{Path: "x", MinStringLength: -1},
			wantKind: ErrorKindValidationFailed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAnalyzeInput(tc.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if got := classify(err).Kind; got != tc.wantKind {
				t.Fatalf("Kind = %q, want %q", got, tc.wantKind)
			}
		})
	}
}

func tooLong(n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = 'a'
	}
	return string(out)
}
