package pcap

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cute-pcap-mcp/internal/config"
)

// TestInspectArtifactHashAndSizeMatchHappyPath confirms that valid
// caller-provided expected_sha256 and expected_size_bytes pass
// through and the artifact is returned with the actual values.
func TestInspectArtifactHashAndSizeMatchHappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ok.pcap")
	body := []byte("synthetic-pcap-content-for-handoff")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Normalize(config.Config{AllowedArtifactDirs: []string{dir}})
	if err != nil {
		t.Fatal(err)
	}

	// First call without expectations to harvest the actual hash/size,
	// then re-validate with those values supplied.
	got, err := inspectArtifact(path, cfg, artifactExpectations{})
	if err != nil {
		t.Fatal(err)
	}
	size := got.SizeBytes
	got2, err := inspectArtifact(path, cfg, artifactExpectations{
		SHA256:    got.SHA256,
		SizeBytes: &size,
	})
	if err != nil {
		t.Fatalf("inspectArtifact with matching expectations: %v", err)
	}
	if got2.SHA256 != got.SHA256 || got2.SizeBytes != got.SizeBytes {
		t.Fatalf("expected match returned different artifact: %+v vs %+v", got2, got)
	}
}

// TestInspectArtifactRejectsHashMismatch pins the typed
// hash_mismatch error: caller-provided expected_sha256 that does not
// equal the on-disk artifact's hash returns errHashMismatch with
// field=expected_sha256 in the classified output.
func TestInspectArtifactRejectsHashMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ok.pcap")
	if err := os.WriteFile(path, []byte("hello world"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Normalize(config.Config{AllowedArtifactDirs: []string{dir}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = inspectArtifact(path, cfg, artifactExpectations{
		SHA256: "deadbeef0000000000000000000000000000000000000000000000000000feed",
	})
	if !errors.Is(err, errHashMismatch) {
		t.Fatalf("err = %v, want errHashMismatch", err)
	}
	terr := classify(err)
	if terr.Kind != ErrorKindHashMismatch {
		t.Fatalf("classify Kind = %q, want %q", terr.Kind, ErrorKindHashMismatch)
	}
	if terr.Field != "expected_sha256" {
		t.Fatalf("classify Field = %q", terr.Field)
	}
}

// TestInspectArtifactRejectsSizeMismatch pins the typed size_mismatch
// error: caller-provided expected_size_bytes that does not equal the
// on-disk size returns errSizeMismatch and short-circuits the hash
// read (the size check is intentionally before the io.Copy hash pass).
func TestInspectArtifactRejectsSizeMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ok.pcap")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Normalize(config.Config{AllowedArtifactDirs: []string{dir}})
	if err != nil {
		t.Fatal(err)
	}
	bigger := int64(999_999)
	_, err = inspectArtifact(path, cfg, artifactExpectations{
		SizeBytes: &bigger,
	})
	if !errors.Is(err, errSizeMismatch) {
		t.Fatalf("err = %v, want errSizeMismatch", err)
	}
	terr := classify(err)
	if terr.Kind != ErrorKindSizeMismatch {
		t.Fatalf("classify Kind = %q, want %q", terr.Kind, ErrorKindSizeMismatch)
	}
	if terr.Field != "expected_size_bytes" {
		t.Fatalf("classify Field = %q", terr.Field)
	}
}

// TestValidateArtifactExpectationsRejectsBadFormats pins the
// structural validation that runs before inspectArtifact: malformed
// expected_sha256 strings and negative expected_size_bytes values
// return validation_failed with a useful field/reason, not
// hash_mismatch / size_mismatch (which would be a misleading typed
// kind for the actual mistake).
func TestValidateArtifactExpectationsRejectsBadFormats(t *testing.T) {
	negSize := int64(-1)
	zeroSize := int64(0)
	cases := []struct {
		name       string
		sha256     string
		sizeBytes  *int64
		wantField  string
		wantReason string
	}{
		{
			name:       "sha256_too_short",
			sha256:     "abcd",
			wantField:  "expected_sha256",
			wantReason: ValidationReasonInvalidFormat,
		},
		{
			name:       "sha256_non_hex_chars",
			sha256:     strings.Repeat("z", 64),
			wantField:  "expected_sha256",
			wantReason: ValidationReasonInvalidFormat,
		},
		{
			name:       "sha256_too_long",
			sha256:     strings.Repeat("a", 65),
			wantField:  "expected_sha256",
			wantReason: ValidationReasonInvalidFormat,
		},
		{
			name:       "negative_size_bytes",
			sizeBytes:  &negSize,
			wantField:  "expected_size_bytes",
			wantReason: ValidationReasonOutOfRange,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateArtifactExpectations(tc.sha256, tc.sizeBytes)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			terr := classify(err)
			if terr.Kind != ErrorKindValidationFailed {
				t.Fatalf("Kind = %q, want %q", terr.Kind, ErrorKindValidationFailed)
			}
			if terr.Field != tc.wantField {
				t.Fatalf("Field = %q, want %q", terr.Field, tc.wantField)
			}
			if terr.Reason != tc.wantReason {
				t.Fatalf("Reason = %q, want %q", terr.Reason, tc.wantReason)
			}
		})
	}

	// Zero is a legal value (means "expect a zero-byte file"). It
	// must NOT be rejected by the validator.
	if err := validateArtifactExpectations("", &zeroSize); err != nil {
		t.Fatalf("zero-byte expected_size_bytes should be valid: %v", err)
	}

	// Empty / nil values are absent and must pass through.
	if err := validateArtifactExpectations("", nil); err != nil {
		t.Fatalf("absent expectations should be valid: %v", err)
	}
}

// TestHashMismatchMessageDoesNotEchoCallerValue pins the second half
// of the P2 fix on this MR: the model-facing message must not
// reflect the caller-supplied expected_sha256, only the actual hash
// computed by the server. Without this guard a malformed-but-
// 64-hex-char input (or a future change that loosens the format
// validator) could bloat the response with untrusted bytes.
func TestHashMismatchMessageDoesNotEchoCallerValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ok.pcap")
	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Normalize(config.Config{AllowedArtifactDirs: []string{dir}})
	if err != nil {
		t.Fatal(err)
	}

	// 64 hex digits but not the actual hash of "test".
	bogus := strings.Repeat("b", 64)
	_, err = inspectArtifact(path, cfg, artifactExpectations{SHA256: bogus})
	if err == nil {
		t.Fatal("expected hash_mismatch error")
	}
	if strings.Contains(err.Error(), bogus) {
		t.Fatalf("error message echoes caller-provided expected_sha256: %v", err)
	}
}

// TestInspectArtifactSHA256ComparisonIsCaseInsensitive pins that
// caller-provided hex hashes in either case match. SHA-256 hex is
// canonical lowercase, but external producers may upper-case or
// mixed-case the value; rejecting on case alone would be hostile.
func TestInspectArtifactSHA256ComparisonIsCaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ok.pcap")
	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Normalize(config.Config{AllowedArtifactDirs: []string{dir}})
	if err != nil {
		t.Fatal(err)
	}
	first, err := inspectArtifact(path, cfg, artifactExpectations{})
	if err != nil {
		t.Fatal(err)
	}
	upper := strings.ToUpper(first.SHA256)
	if _, err := inspectArtifact(path, cfg, artifactExpectations{SHA256: upper}); err != nil {
		t.Fatalf("upper-case sha256 should match: %v", err)
	}
}
