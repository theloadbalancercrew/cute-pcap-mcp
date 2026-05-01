package pcap

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cute-pcap-mcp/internal/config"
)

// TestNoSecretLeaksAcrossEntireResponse pins the M2 redaction
// contract (issue #1): a synthetic pcap stuffed with fake credentials
// drives the full analyze pipeline (capinfos / tshark / Zeek / ASCII)
// and the test asserts that none of the unredacted secret values
// appear in the persisted analysis.json, summary.md, ASCII strings,
// findings, or top-level evidence sections.
//
// The fake credentials are flagged so a future regression that
// disables redaction or routes payload bytes into a new section
// fails this test loudly, not silently.
func TestNoSecretLeaksAcrossEntireResponse(t *testing.T) {
	requireCommand(t, "tshark")

	root := t.TempDir()
	pcapDir := filepath.Join(root, "pcaps")
	outputDir := filepath.Join(root, "output")
	if err := os.MkdirAll(pcapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pcap := filepath.Join(pcapDir, "secrets.pcap")
	if err := os.WriteFile(pcap, syntheticSecretsPcap(), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{pcapDir},
		Workspace:           config.WorkspaceConfig{OutputDir: outputDir},
		Analysis: config.AnalysisConfig{
			CommandTimeoutSeconds: 10,
			MaxStdoutBytes:        200000,
			MaxPacketRows:         50,
			MaxASCIIStrings:       100,
			MaxASCIIBytes:         50000,
			MaxZeekRecordsPerLog:  50,
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

	// Marshal the in-memory response (this is what hosts see) and
	// scan for the unredacted credentials that the synthetic pcap
	// embeds. Each of these must be replaced with [REDACTED] in any
	// surface where the bytes survive.
	leakedSecrets := []string{
		"super-secret-bearer-token-do-not-leak",
		"abcd1234sessionvalue",
		"plaintext-password-leak",
		"top-level-api-key-leak",
	}
	body, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range leakedSecrets {
		if bytes.Contains(body, []byte(secret)) {
			t.Errorf("unredacted secret %q leaked into in-memory analyze response", secret)
		}
	}

	// Persisted artifacts: analysis.json + summary.md must also be
	// secret-free.
	written, err := writeAnalysisArtifacts(cfg, out)
	if err != nil {
		t.Fatalf("writeAnalysisArtifacts: %v", err)
	}
	for _, art := range written {
		fileBody, err := os.ReadFile(art.Path)
		if err != nil {
			t.Fatalf("read %s: %v", art.Path, err)
		}
		for _, secret := range leakedSecrets {
			if bytes.Contains(fileBody, []byte(secret)) {
				t.Errorf("unredacted secret %q leaked into persisted artifact %s", secret, art.Path)
			}
		}
	}

	// Findings carry stable codes and bounded messages — assert they
	// don't contain the secrets either.
	for _, f := range out.Findings {
		for _, secret := range leakedSecrets {
			if strings.Contains(f.Message, secret) {
				t.Errorf("unredacted secret %q leaked into finding code=%s message=%q", secret, f.Code, f.Message)
			}
		}
	}

	// At least one [REDACTED] marker must be present in the response;
	// otherwise the redactor never ran and the test would pass
	// vacuously on a pcap that happens not to match the patterns.
	if !strings.Contains(string(body), "[REDACTED]") {
		t.Fatalf("no [REDACTED] marker in response; the redactor did not run on the synthetic secrets pcap")
	}
}

// TestRedactSecretsFalseStillScrubsZeekHTTPURI pins the privacy-
// invariant claim that Zeek HTTP URI redaction is unconditional. Even
// when redact_secrets=false (operator opt-out for ASCII), the URI
// pass still runs.
func TestRedactSecretsFalseStillScrubsZeekHTTPURI(t *testing.T) {
	requireCommand(t, "zeek")
	requireCommand(t, "tshark")

	root := t.TempDir()
	pcapDir := filepath.Join(root, "pcaps")
	if err := os.MkdirAll(pcapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pcap := filepath.Join(pcapDir, "secrets.pcap")
	if err := os.WriteFile(pcap, syntheticSecretsPcap(), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{pcapDir},
		Workspace:           config.WorkspaceConfig{TmpDir: filepath.Join(root, "tmp")},
		Analysis: config.AnalysisConfig{
			CommandTimeoutSeconds: 10,
			MaxStdoutBytes:        200000,
			MaxPacketRows:         50,
			MaxASCIIStrings:       100,
			MaxASCIIBytes:         50000,
			MaxZeekRecordsPerLog:  50,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	source, err := inspectArtifact(pcap, cfg, artifactExpectations{})
	if err != nil {
		t.Fatal(err)
	}

	redactFalse := false
	out := analyzeArtifact(context.Background(), source, cfg, analyzeInput{
		Path:          pcap,
		RedactSecrets: &redactFalse,
	})

	// The Zeek http.log URI for our synthetic capture contains
	// `?token=top-level-api-key-leak`. With redact_secrets=false the
	// ASCII output keeps the literal value, but the HTTP URI pass
	// must still scrub the `token=...` substring.
	for _, http := range out.HTTP {
		if strings.Contains(http.URI, "top-level-api-key-leak") {
			t.Fatalf("Zeek HTTP URI redaction skipped under redact_secrets=false: %q", http.URI)
		}
	}
}

// syntheticSecretsPcap produces a single-frame TCP pcap whose payload
// is a fake HTTP request containing every secret shape the redactor
// is expected to catch:
//
//   - Authorization: Bearer ...
//   - Cookie: session=...
//   - URL parameters password=, token=, api_key=
//
// The frame is wrapped in a libpcap file (LINKTYPE_ETHERNET, magic
// 0xa1b2c3d4) the same way syntheticHTTPPcap does.
func syntheticSecretsPcap() []byte {
	payload := []byte(strings.Join([]string{
		"GET /login?password=plaintext-password-leak&token=top-level-api-key-leak HTTP/1.1",
		"Host: example.test",
		"User-Agent: redaction-test",
		"Authorization: Bearer super-secret-bearer-token-do-not-leak",
		"Cookie: session=abcd1234sessionvalue",
		"",
		"",
	}, "\r\n"))
	ipLen := 20 + 20 + len(payload)
	frame := make([]byte, 14+ipLen)

	copy(frame[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	copy(frame[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)

	ip := frame[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipLen))
	binary.BigEndian.PutUint16(ip[4:6], 1)
	binary.BigEndian.PutUint16(ip[6:8], 0x4000)
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], []byte{192, 0, 2, 10})
	copy(ip[16:20], []byte{198, 51, 100, 20})
	binary.BigEndian.PutUint16(ip[10:12], ipv4Checksum(ip))

	tcp := frame[34:54]
	binary.BigEndian.PutUint16(tcp[0:2], 55555)
	binary.BigEndian.PutUint16(tcp[2:4], 80)
	binary.BigEndian.PutUint32(tcp[4:8], 1)
	binary.BigEndian.PutUint32(tcp[8:12], 1)
	tcp[12] = 0x50
	tcp[13] = 0x18
	binary.BigEndian.PutUint16(tcp[14:16], 4096)
	copy(frame[54:], payload)

	var buf bytes.Buffer
	writeLE := func(v any) { _ = binary.Write(&buf, binary.LittleEndian, v) }
	writeLE(uint32(0xa1b2c3d4))
	writeLE(uint16(2))
	writeLE(uint16(4))
	writeLE(int32(0))
	writeLE(uint32(0))
	writeLE(uint32(65535))
	writeLE(uint32(1))
	writeLE(uint32(1))
	writeLE(uint32(0))
	writeLE(uint32(len(frame)))
	writeLE(uint32(len(frame)))
	buf.Write(frame)
	return buf.Bytes()
}
