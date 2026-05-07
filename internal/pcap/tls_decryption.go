package pcap

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cute-pcap-mcp/internal/config"
)

// TLS decryption status tokens. Stable model-facing strings; never
// rename, only add. The state machine is deterministic given the
// inputs:
//
//   - tls_keylog_path empty                 → not_requested
//   - tls_keylog_path set, no KeylogDir     → unavailable
//   - tls_keylog_path set, outside KeylogDir → unavailable (with
//     reason path_outside_keylog_dir; the keylog stays opaque)
//   - tls_keylog_path set, file missing      → keylog_missing
//   - tls_keylog_path set, no usable secret lines → keylog_invalid
//   - tls_keylog_path set, keylog-consuming analyzer (tshark or
//     Zeek) errored → failed
//   - tls_keylog_path set, keylog-consuming analyzers ran clean →
//     attempted
//
// `succeeded` is reserved on the wire but is **not emitted today**.
// The previous implementation promoted attempted → succeeded when a
// TLS handshake summary appeared, but TLS handshakes are unencrypted
// by definition — they appear in Zeek's ssl/tls log even when no
// keylog matches the session. Promoting on that signal would have
// reported succeeded for any random file passed as tls_keylog_path.
// Until the analyze pipeline carries a signal that genuinely proves
// decrypted evidence (e.g. http records that came from inside TLS
// streams), a successful keylog application stays at `attempted` and
// the limitations list documents this honestly. The `succeeded`
// token is left in the constant set so a future emission lands
// without a wire-shape change.
const (
	TLSDecryptionStatusNotRequested  = "not_requested"
	TLSDecryptionStatusUnavailable   = "unavailable"
	TLSDecryptionStatusKeylogMissing = "keylog_missing"
	TLSDecryptionStatusKeylogInvalid = "keylog_invalid"
	TLSDecryptionStatusAttempted     = "attempted"
	TLSDecryptionStatusSucceeded     = "succeeded"
	TLSDecryptionStatusFailed        = "failed"
)

// TLSDecryptionStatus is the wire shape stamped on every
// pcap_analyze response. Status is always set; KeylogPath echoes
// the resolved path only when the keylog was actually applied to
// the analyzers. Detail is a bounded human fallback explaining the
// state when it is anything other than `not_requested`. Limitations
// is the always-included list of why TLS payload decryption
// generally fails — PFS, missing server keys, partial captures.
type TLSDecryptionStatus struct {
	Status      string   `json:"status"`
	KeylogPath  string   `json:"keylog_path,omitempty"`
	Detail      string   `json:"detail,omitempty"`
	Limitations []string `json:"limitations,omitempty"`
}

// tlsDecryptionLimitations is the always-present list when the
// status is anything other than not_requested. Hosts treat these
// as fixed warnings; the list only grows.
var tlsDecryptionLimitations = []string{
	"TLS payload decryption requires premaster-secret material from one of the endpoints; without an SSLKEYLOGFILE captured at the client (or, for non-PFS suites only, the server private key) decryption is not possible from packet bytes alone.",
	"Most modern TLS handshakes (TLS 1.3, ECDHE / DHE in TLS 1.2) use forward-secret key exchange, so the server private key alone cannot decrypt past traffic — only an SSLKEYLOGFILE captured during the session works.",
	"A captured SSLKEYLOGFILE only decrypts the connections whose handshake keys it contains. Connections that started before the keylog began, or that used a different TLS session, remain opaque.",
	"`status: keylog_invalid` means the file was present under workspace.keylog_dir but did not contain a recognized SSLKEYLOGFILE secret line, so it was not handed to the analyzers.",
	"`status: attempted` means the keylog was validated and handed to tshark and Zeek without subprocess errors. It does NOT prove that any session was actually decrypted — TLS handshakes appear in Zeek's ssl/tls log regardless of whether the keylog matched. The `succeeded` token is reserved on the wire for a future implementation that has a reliable decrypted-evidence signal.",
	"This server reports decryption status only. It does not return decrypted HTTP bodies, payload bytes, or headers in tool output, even when the keylog is applied; redacted summaries from Zeek's http.log are the only HTTP evidence the response carries.",
	"Operators MUST treat keylog files as highly sensitive: they grant retroactive decryption of every connection whose keys appear there. They should live under workspace.keylog_dir on a strict allowlist, not under workspace.pcap_dir.",
}

// resolveTLSKeylog validates the caller-supplied keylog path and
// returns the resolved on-disk path plus the initial status. The
// caller drives the rest of the state machine based on whether the
// analyzers ran cleanly.
//
// Path validation mirrors inspectArtifact's rules: absolute, symlink-
// resolved, must resolve under workspace.keylog_dir. Symlink escape is
// rejected. The keylog is read only for secret-safe SSLKEYLOGFILE shape
// validation; key material is never returned, logged, or stored by the
// server.
func resolveTLSKeylog(rawPath string, cfg config.Config) (resolved string, status string, detail string) {
	if strings.TrimSpace(rawPath) == "" {
		return "", TLSDecryptionStatusNotRequested, ""
	}
	if cfg.Workspace.KeylogDir == "" {
		return "", TLSDecryptionStatusUnavailable,
			"workspace.keylog_dir is not configured on this server; TLS decryption support is disabled"
	}
	abs, err := filepath.Abs(rawPath)
	if err != nil {
		return "", TLSDecryptionStatusUnavailable,
			"tls_keylog_path could not be resolved to an absolute path"
	}
	abs = filepath.Clean(abs)
	realPath, err := filepath.EvalSymlinks(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return "", TLSDecryptionStatusKeylogMissing,
				"tls_keylog_path does not exist on disk"
		}
		return "", TLSDecryptionStatusUnavailable,
			"tls_keylog_path symlink resolution failed"
	}
	realPath = filepath.Clean(realPath)
	if !sharedKeylogPath(realPath, cfg.Workspace.KeylogDir) {
		return "", TLSDecryptionStatusUnavailable,
			"tls_keylog_path resolved outside workspace.keylog_dir; keylog material must live under the configured allowlist"
	}
	info, err := os.Stat(realPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", TLSDecryptionStatusKeylogMissing,
				"tls_keylog_path does not exist on disk"
		}
		return "", TLSDecryptionStatusUnavailable, "tls_keylog_path stat failed"
	}
	if !info.Mode().IsRegular() {
		return "", TLSDecryptionStatusUnavailable,
			"tls_keylog_path must be a regular file"
	}
	keylogSummary, err := validateTLSKeylogFile(realPath)
	if err != nil {
		return "", TLSDecryptionStatusUnavailable,
			"tls_keylog_path could not be read for SSLKEYLOGFILE validation"
	}
	if keylogSummary.UsableSecretLines == 0 {
		if keylogSummary.NonCommentLines == 0 {
			return "", TLSDecryptionStatusKeylogInvalid,
				"tls_keylog_path is empty or contains only comments; no SSLKEYLOGFILE secret lines were found"
		}
		return "", TLSDecryptionStatusKeylogInvalid,
			fmt.Sprintf("tls_keylog_path does not contain any recognized SSLKEYLOGFILE secret lines; %d non-comment line(s) were ignored as malformed or unsupported", keylogSummary.NonCommentLines)
	}
	return realPath, TLSDecryptionStatusAttempted,
		fmt.Sprintf("validated %d SSLKEYLOGFILE secret line(s)", keylogSummary.UsableSecretLines)
}

// sharedKeylogPath returns true if `inner` is under `keylogDir`.
// Strict-ancestor check; the dir itself is not allowed as the file.
func sharedKeylogPath(inner, keylogDir string) bool {
	rel, err := filepath.Rel(keylogDir, inner)
	if err != nil {
		return false
	}
	if filepath.IsAbs(rel) || rel == "" || rel == "." || rel == ".." {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

const maxTLSKeylogLineBytes = 1024 * 1024

type tlsKeylogValidationSummary struct {
	NonCommentLines   int
	UsableSecretLines int
}

func validateTLSKeylogFile(path string) (tlsKeylogValidationSummary, error) {
	file, err := os.Open(path)
	if err != nil {
		return tlsKeylogValidationSummary{}, err
	}
	defer file.Close()

	var summary tlsKeylogValidationSummary
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), maxTLSKeylogLineBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		summary.NonCommentLines++
		if isUsableTLSKeylogLine(line) {
			summary.UsableSecretLines++
		}
	}
	if err := scanner.Err(); err != nil {
		return summary, err
	}
	return summary, nil
}

func isUsableTLSKeylogLine(line string) bool {
	parts := strings.Fields(line)
	if len(parts) != 3 {
		return false
	}
	label, clientRandom, secret := parts[0], parts[1], parts[2]
	if !isRecognizedTLSKeylogLabel(label) {
		return false
	}
	if !isEvenHex(clientRandom) || !isEvenHex(secret) {
		return false
	}
	if len(secret) < 64 {
		return false
	}
	if label != "RSA" && len(clientRandom) != 64 {
		return false
	}
	return true
}

func isRecognizedTLSKeylogLabel(label string) bool {
	switch label {
	case "CLIENT_RANDOM",
		"CLIENT_EARLY_TRAFFIC_SECRET",
		"CLIENT_HANDSHAKE_TRAFFIC_SECRET",
		"SERVER_HANDSHAKE_TRAFFIC_SECRET",
		"EXPORTER_SECRET",
		"EARLY_EXPORTER_SECRET",
		"RSA":
		return true
	}
	for _, prefix := range []string{"CLIENT_TRAFFIC_SECRET_", "SERVER_TRAFFIC_SECRET_"} {
		if strings.HasPrefix(label, prefix) {
			suffix := strings.TrimPrefix(label, prefix)
			if suffix == "" {
				return false
			}
			for _, r := range suffix {
				if r < '0' || r > '9' {
					return false
				}
			}
			return true
		}
	}
	return false
}

func isEvenHex(value string) bool {
	if value == "" || len(value)%2 != 0 {
		return false
	}
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// finalizeTLSDecryptionStatus is called after the analyze pipeline
// runs. It demotes attempted → failed when a keylog-consuming
// analyzer (tshark or Zeek) errored. It does NOT promote attempted →
// succeeded — see the const block above for why; the analyze
// pipeline does not currently produce a signal that genuinely proves
// decrypted evidence, and the previous handshake-presence heuristic
// would have falsely reported succeeded for any random file passed
// as tls_keylog_path.
//
// The keylogAnalyzerFailed parameter is the SCOPED failure signal:
// only tshark and Zeek runs that actually received the keylog count.
// Errors from capinfos / ASCII extraction / unrelated tshark sub-
// calls do not mark the keylog attempt as failed.
func finalizeTLSDecryptionStatus(initialStatus, initialDetail string, keylogAnalyzerFailed bool, keylogPath string) *TLSDecryptionStatus {
	status := initialStatus
	detail := initialDetail
	if status == TLSDecryptionStatusAttempted {
		if keylogAnalyzerFailed {
			status = TLSDecryptionStatusFailed
			detail = appendTLSDecryptionDetail(detail, "tshark or Zeek returned an error while the keylog was applied; see errors[] for the per-analyzer kind")
		} else {
			detail = appendTLSDecryptionDetail(detail, "keylog applied to tshark and Zeek; the analyzers ran without subprocess errors. This does NOT prove any session was decrypted — see limitations.")
		}
	}
	out := &TLSDecryptionStatus{Status: status}
	if status != TLSDecryptionStatusNotRequested {
		out.Limitations = append([]string{}, tlsDecryptionLimitations...)
		if status == TLSDecryptionStatusAttempted ||
			status == TLSDecryptionStatusSucceeded ||
			status == TLSDecryptionStatusFailed {
			out.KeylogPath = keylogPath
		}
		if detail != "" {
			out.Detail = detail
		}
	}
	return out
}

func appendTLSDecryptionDetail(prefix, suffix string) string {
	if prefix == "" {
		return suffix
	}
	if suffix == "" {
		return prefix
	}
	return prefix + "; " + suffix
}

// keylogPathOrEmpty is a small helper to keep the analyzer caller
// readable. Returns the resolved keylog path only when it is in use.
func keylogPathOrEmpty(status string, resolved string) string {
	switch status {
	case TLSDecryptionStatusAttempted,
		TLSDecryptionStatusSucceeded,
		TLSDecryptionStatusFailed:
		return resolved
	}
	return ""
}

// keylogTSharkArgs returns the tshark `-o tls.keylog_file:<path>`
// flags when a resolved keylog path is in use. Empty path returns
// nil so the caller can append unconditionally.
func keylogTSharkArgs(resolvedPath string) []string {
	if resolvedPath == "" {
		return nil
	}
	return []string{"-o", fmt.Sprintf("tls.keylog_file:%s", resolvedPath)}
}
