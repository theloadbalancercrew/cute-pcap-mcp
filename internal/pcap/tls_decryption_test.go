package pcap

import (
	"os"
	"path/filepath"
	"testing"

	"cute-pcap-mcp/internal/config"
)

// TestResolveTLSKeylogStateMachine pins every state the keylog
// resolver can return. Each row drives the resolver with a specific
// caller input + server config and asserts the typed status string
// hosts switch on.
func TestResolveTLSKeylogStateMachine(t *testing.T) {
	keylogRoot := t.TempDir()
	realKeylog := filepath.Join(keylogRoot, "keys.log")
	if err := os.WriteFile(realKeylog, []byte("CLIENT_RANDOM AAA BBB\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outsideRoot := t.TempDir()
	outsideKeylog := filepath.Join(outsideRoot, "stolen.log")
	if err := os.WriteFile(outsideKeylog, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgWithKeylog, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{t.TempDir()},
		Workspace:           config.WorkspaceConfig{KeylogDir: keylogRoot},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfgNoKeylog, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{t.TempDir()},
	})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name       string
		path       string
		cfg        config.Config
		wantStatus string
		wantHasDetail bool
	}{
		{
			name:       "not_requested_when_path_empty",
			path:       "",
			cfg:        cfgWithKeylog,
			wantStatus: TLSDecryptionStatusNotRequested,
		},
		{
			name:          "unavailable_when_keylog_dir_unset",
			path:          realKeylog,
			cfg:           cfgNoKeylog,
			wantStatus:    TLSDecryptionStatusUnavailable,
			wantHasDetail: true,
		},
		{
			name:          "unavailable_when_path_outside_keylog_dir",
			path:          outsideKeylog,
			cfg:           cfgWithKeylog,
			wantStatus:    TLSDecryptionStatusUnavailable,
			wantHasDetail: true,
		},
		{
			name:          "keylog_missing_when_file_absent",
			path:          filepath.Join(keylogRoot, "nope.log"),
			cfg:           cfgWithKeylog,
			wantStatus:    TLSDecryptionStatusKeylogMissing,
			wantHasDetail: true,
		},
		{
			name:       "attempted_when_real_file_under_keylog_dir",
			path:       realKeylog,
			cfg:        cfgWithKeylog,
			wantStatus: TLSDecryptionStatusAttempted,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolved, status, detail := resolveTLSKeylog(tc.path, tc.cfg)
			if status != tc.wantStatus {
				t.Fatalf("status = %q, want %q (detail=%q)", status, tc.wantStatus, detail)
			}
			if status == TLSDecryptionStatusAttempted && resolved == "" {
				t.Fatal("attempted status with empty resolved path")
			}
			if status != TLSDecryptionStatusAttempted && resolved != "" {
				t.Fatalf("non-attempted status returned a path: %q", resolved)
			}
			if tc.wantHasDetail && detail == "" {
				t.Fatal("expected non-empty detail for non-trivial states")
			}
		})
	}
}

// TestResolveTLSKeylogRejectsSymlinkEscape pins the security
// boundary: a symlink under workspace.keylog_dir that points outside
// must NOT be treated as inside. Path resolution uses EvalSymlinks
// before the prefix check, so the real target governs the decision.
func TestResolveTLSKeylogRejectsSymlinkEscape(t *testing.T) {
	keylogRoot := t.TempDir()
	outsideRoot := t.TempDir()
	target := filepath.Join(outsideRoot, "real_keys.log")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(keylogRoot, "link.log")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{t.TempDir()},
		Workspace:           config.WorkspaceConfig{KeylogDir: keylogRoot},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, status, _ := resolveTLSKeylog(link, cfg)
	if status != TLSDecryptionStatusUnavailable {
		t.Fatalf("symlink escape returned status %q, want unavailable", status)
	}
}

// TestFinalizeTLSDecryptionStatus pins the demote-only behavior. The
// previous round promoted attempted → succeeded when a TLS handshake
// summary appeared; that signal is unsound because handshakes are
// unencrypted by definition and present in Zeek output regardless of
// keylog match. The current finalizer demotes attempted → failed
// only when a keylog-consuming analyzer subprocess errored, and
// otherwise leaves the status at attempted with a detail message
// stating the limitation honestly.
func TestFinalizeTLSDecryptionStatus(t *testing.T) {
	cases := []struct {
		name              string
		initialStatus     string
		keylogFailed      bool
		wantStatus        string
		wantKeylogPath    string
		wantHasLimitation bool
	}{
		{
			name:              "attempted_with_keylog_failure_demotes_to_failed",
			initialStatus:     TLSDecryptionStatusAttempted,
			keylogFailed:      true,
			wantStatus:        TLSDecryptionStatusFailed,
			wantKeylogPath:    "/keylog/keys.log",
			wantHasLimitation: true,
		},
		{
			name:              "attempted_clean_run_stays_attempted",
			initialStatus:     TLSDecryptionStatusAttempted,
			wantStatus:        TLSDecryptionStatusAttempted,
			wantKeylogPath:    "/keylog/keys.log",
			wantHasLimitation: true,
		},
		{
			name:          "not_requested_carries_no_limitations",
			initialStatus: TLSDecryptionStatusNotRequested,
			wantStatus:    TLSDecryptionStatusNotRequested,
		},
		{
			name:              "unavailable_carries_limitations_no_keylog_path",
			initialStatus:     TLSDecryptionStatusUnavailable,
			wantStatus:        TLSDecryptionStatusUnavailable,
			wantHasLimitation: true,
		},
		{
			name:              "keylog_missing_carries_limitations_no_keylog_path",
			initialStatus:     TLSDecryptionStatusKeylogMissing,
			wantStatus:        TLSDecryptionStatusKeylogMissing,
			wantHasLimitation: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := finalizeTLSDecryptionStatus(tc.initialStatus, "initial detail", tc.keylogFailed, tc.wantKeylogPath)
			if out.Status != tc.wantStatus {
				t.Fatalf("Status = %q, want %q", out.Status, tc.wantStatus)
			}
			if out.KeylogPath != tc.wantKeylogPath {
				t.Fatalf("KeylogPath = %q, want %q", out.KeylogPath, tc.wantKeylogPath)
			}
			if tc.wantHasLimitation && len(out.Limitations) == 0 {
				t.Fatalf("status %q must carry the limitations list", out.Status)
			}
			if !tc.wantHasLimitation && len(out.Limitations) != 0 {
				t.Fatalf("status %q must NOT carry limitations; got %d", out.Status, len(out.Limitations))
			}
		})
	}
}

// TestFinalizeTLSDecryptionDoesNotPromoteOnHandshakeOnly pins the
// conservative TLS status contract. Even when the analyze pass surfaces
// TLS handshake summaries (which it always does for any pcap with TLS,
// regardless of decryption), the finalizer must NOT promote attempted
// to succeeded.
func TestFinalizeTLSDecryptionDoesNotPromoteOnHandshakeOnly(t *testing.T) {
	out := finalizeTLSDecryptionStatus(TLSDecryptionStatusAttempted, "", false, "/keylog/keys.log")
	if out.Status == TLSDecryptionStatusSucceeded {
		t.Fatal("finalizer falsely promoted to succeeded")
	}
	if out.Status != TLSDecryptionStatusAttempted {
		t.Fatalf("Status = %q, want %q (clean keylog run stays at attempted)", out.Status, TLSDecryptionStatusAttempted)
	}
}

// TestExplainConnectionPassesKeylogToAnalyzePipeline pins that
// pcap_explain_connection carries tls_keylog_path through the
// synthesized analyzeInput.
func TestExplainConnectionPassesKeylogToAnalyzePipeline(t *testing.T) {
	root := t.TempDir()
	pcapDir := filepath.Join(root, "pcaps")
	keylogRoot := filepath.Join(root, "keylog")
	if err := os.MkdirAll(pcapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(keylogRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	keylog := filepath.Join(keylogRoot, "keys.log")
	if err := os.WriteFile(keylog, []byte("CLIENT_RANDOM A B\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// libpcap header only; analyzers will fail-fast on it but the
	// keylog plumbing is what this test cares about.
	pcap := filepath.Join(pcapDir, "empty.pcap")
	if err := os.WriteFile(pcap, libpcapHeaderOnly(), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{pcapDir},
		Workspace:           config.WorkspaceConfig{KeylogDir: keylogRoot},
	})
	if err != nil {
		t.Fatal(err)
	}
	source, err := inspectArtifact(pcap, cfg, artifactExpectations{})
	if err != nil {
		t.Fatal(err)
	}

	// Feed a five_tuple selector so resolveSelector doesn't itself
	// try to run analyzers that aren't on PATH locally.
	out := explainConnection(t.Context(), source, cfg, explainInput{
		Path: pcap,
		FiveTuple: &FiveTuple{
			SourceIP:   "10.0.0.1",
			DestIP:     "10.0.0.2",
			SourcePort: 1024,
			DestPort:   443,
			Protocol:   "tcp",
		},
		TLSKeylogPath: keylog,
	})

	if out.TLSDecryption == nil {
		t.Fatal("explainOutput.TLSDecryption = nil; the keylog plumbing is broken")
	}
	switch out.TLSDecryption.Status {
	case TLSDecryptionStatusAttempted, TLSDecryptionStatusFailed:
		// Either is fine — the keylog reached the analyzers. Local
		// runs without tshark/zeek will end up at failed because the
		// analyzer subprocess can't run; CI will see attempted.
	default:
		t.Fatalf("TLSDecryption.Status = %q; expected attempted or failed (keylog reached pipeline)", out.TLSDecryption.Status)
	}
}

// TestAnalyzeErrorOutputStampsTLSDecryptionField pins that hard-error
// responses always carry the tls_decryption field (status:
// not_requested) so hosts can switch on it without the field
// disappearing on validation/path/busy errors.
func TestAnalyzeErrorOutputStampsTLSDecryptionField(t *testing.T) {
	terr := toolError{Kind: ErrorKindMissingField, Message: "x"}
	out := analyzeErrorOutput(ArtifactInfo{}, terr)
	if out.TLSDecryption == nil {
		t.Fatal("analyzeErrorOutput dropped tls_decryption field")
	}
	if out.TLSDecryption.Status != TLSDecryptionStatusNotRequested {
		t.Fatalf("Status = %q, want %q", out.TLSDecryption.Status, TLSDecryptionStatusNotRequested)
	}
}

// TestExplainErrorOutputStampsTLSDecryptionField pins the same
// always-present TLS status guarantee on the explain helper. The
// previous round only stamped it on analyzeErrorOutput, so explain
// validation / path / busy / selector failures returned responses
// with no tls_decryption.status — breaking the documented
// always-present surface for the explain tool.
func TestExplainErrorOutputStampsTLSDecryptionField(t *testing.T) {
	terr := toolError{Kind: ErrorKindValidationFailed, Message: "selector_required"}
	out := explainErrorOutput(ArtifactInfo{}, terr)
	if out.TLSDecryption == nil {
		t.Fatal("explainErrorOutput dropped tls_decryption field")
	}
	if out.TLSDecryption.Status != TLSDecryptionStatusNotRequested {
		t.Fatalf("Status = %q, want %q", out.TLSDecryption.Status, TLSDecryptionStatusNotRequested)
	}
}

// TestKeylogTSharkArgsEmittedOnlyWhenSet pins the helper so an empty
// keylog input yields no extra tshark args (avoids -o flags with
// trailing colons).
func TestKeylogTSharkArgsEmittedOnlyWhenSet(t *testing.T) {
	if got := keylogTSharkArgs(""); len(got) != 0 {
		t.Fatalf("empty keylog returned args: %v", got)
	}
	got := keylogTSharkArgs("/keylog/keys.log")
	if len(got) != 2 {
		t.Fatalf("len(args) = %d, want 2", len(got))
	}
	if got[0] != "-o" {
		t.Fatalf("args[0] = %q", got[0])
	}
	if got[1] != "tls.keylog_file:/keylog/keys.log" {
		t.Fatalf("args[1] = %q", got[1])
	}
}
