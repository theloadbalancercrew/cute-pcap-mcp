package pcap

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"cute-pcap-mcp/internal/config"
)

func TestExtractASCIIStringsRedactsAndBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.pcap")
	raw := []byte{
		0x00, 'a', 'b', 'c', 0x00,
		'G', 'E', 'T', ' ', '/', 'l', 'o', 'g', 'i', 'n', ' ', 'H', 'T', 'T', 'P', '/', '1', '.', '1', 0x00,
		'A', 'u', 't', 'h', 'o', 'r', 'i', 'z', 'a', 't', 'i', 'o', 'n', ':', ' ', 'B', 'e', 'a', 'r', 'e', 'r', ' ', 's', 'e', 'c', 'r', 'e', 't', 0x00,
		't', 'o', 'k', 'e', 'n', '=', 'a', 'b', 'c', 'd', '&', 'x', '=', '1',
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := extractASCIIStrings(path, asciiExtractionOptions{
		MinLength:     4,
		MaxStrings:    10,
		MaxBytes:      1024,
		RedactSecrets: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := len(report.Strings), 3; got != want {
		t.Fatalf("len(Strings) = %d, want %d: %#v", got, want, report.Strings)
	}
	if report.Strings[0].Text != "GET /login HTTP/1.1" {
		t.Fatalf("first string = %q", report.Strings[0].Text)
	}
	joined := report.Strings[1].Text + "\n" + report.Strings[2].Text
	if !strings.Contains(joined, "Authorization: [REDACTED]") {
		t.Fatalf("authorization was not redacted: %q", joined)
	}
	if !strings.Contains(joined, "token=[REDACTED]&x=1") {
		t.Fatalf("token was not redacted: %q", joined)
	}
	if !report.Redacted {
		t.Fatal("report.Redacted = false, want true")
	}
}

func TestExtractASCIIStringsTruncatesOnStringLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.pcap")
	if err := os.WriteFile(path, []byte("first\x00second\x00third"), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := extractASCIIStrings(path, asciiExtractionOptions{
		MinLength:  4,
		MaxStrings: 1,
		MaxBytes:   1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(report.Strings), 1; got != want {
		t.Fatalf("len(Strings) = %d, want %d", got, want)
	}
	if !report.Truncated {
		t.Fatal("report.Truncated = false, want true")
	}
}

func TestParseZeekLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conn.log")
	raw := strings.Join([]string{
		`#separator \x09`,
		"#path conn",
		"#fields ts\tuid\tid.orig_h\tid.orig_p",
		"#types time\tstring\taddr\tport",
		"1.000000\tC1\t192.0.2.10\t12345",
		"2.000000\tC2\t192.0.2.11\t23456",
		"#close 2026-04-28-03-00-00",
	}, "\n")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	log, err := parseZeekLog(path, 1)
	if err != nil {
		t.Fatal(err)
	}
	if log.Name != "conn" {
		t.Fatalf("Name = %q, want conn", log.Name)
	}
	if got, want := len(log.Records), 1; got != want {
		t.Fatalf("len(Records) = %d, want %d", got, want)
	}
	if got := log.Records[0]["id.orig_h"]; got != "192.0.2.10" {
		t.Fatalf("id.orig_h = %q", got)
	}
	if !log.Truncated {
		t.Fatal("Truncated = false, want true")
	}
}

func TestParseZeekLogAcceptsSeparatorDelimitedDirectives(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ssl.log")
	raw := strings.Join([]string{
		`#separator \x09`,
		"#set_separator\t,",
		"#empty_field\t(empty)",
		"#unset_field\t-",
		"#path\tssl",
		"#fields\tts\tuid\tid.orig_h\tid.resp_h\tserver_name\tversion\tcipher",
		"#types\ttime\tstring\taddr\taddr\tstring\tstring\tstring",
		"1.000000\tC1\t192.0.2.10\t198.51.100.20\ttls.example\tTLSv12\tTLS_AES_128_GCM_SHA256",
		"#close\t2026-04-30-01-49-25",
	}, "\n")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	log, err := parseZeekLog(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	if log.Name != "ssl" {
		t.Fatalf("Name = %q, want ssl", log.Name)
	}
	if got, want := len(log.Fields), 7; got != want {
		t.Fatalf("len(Fields) = %d, want %d: %#v", got, want, log.Fields)
	}
	if got := log.Records[0]["server_name"]; got != "tls.example" {
		t.Fatalf("server_name = %q", got)
	}
	if got := log.Records[0]["cipher"]; got != "TLS_AES_128_GCM_SHA256" {
		t.Fatalf("cipher = %q", got)
	}
}

func TestParseZeekLogRedactsStructuredSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "http.log")
	raw := strings.Join([]string{
		`#separator \x09`,
		"#path http",
		"#fields ts\tuid\turi",
		"#types time\tstring\tstring",
		"1.000000\tC1\t/login?password=plaintext-password-leak&token=top-level-api-key-leak",
		"#close 2026-04-28-03-00-00",
	}, "\n")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	log, err := parseZeekLog(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	got := log.Records[0]["uri"]
	for _, secret := range []string{"plaintext-password-leak", "top-level-api-key-leak"} {
		if strings.Contains(got, secret) {
			t.Fatalf("Zeek raw record leaked %q in %q", secret, got)
		}
	}
	if !strings.Contains(got, "password=[REDACTED]&token=[REDACTED]") {
		t.Fatalf("Zeek raw record did not preserve redaction markers: %q", got)
	}
}

func TestParseTSharkPacketSummaries(t *testing.T) {
	raw := strings.Join([]string{
		"frame.number\tframe.time_relative\t_ws.col.Protocol\tip.src\tipv6.src\ttcp.srcport\tudp.srcport\tip.dst\tipv6.dst\ttcp.dstport\tudp.dstport\t_ws.col.Info",
		"1\t0.000000\tHTTP\t192.0.2.10\t\t55555\t\t198.51.100.20\t\t80\t\tGET /login?token=packet-secret HTTP/1.1",
	}, "\n")

	packets, err := parseTSharkPacketSummaries(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(packets), 1; got != want {
		t.Fatalf("len(packets) = %d, want %d", got, want)
	}
	packet := packets[0]
	if packet.Source != "192.0.2.10" || packet.Destination != "198.51.100.20" {
		t.Fatalf("unexpected endpoints: %#v", packet)
	}
	if packet.SourcePort != "55555" || packet.DestPort != "80" {
		t.Fatalf("unexpected ports: %#v", packet)
	}
	if strings.Contains(packet.Info, "packet-secret") {
		t.Fatalf("packet Info leaked secret: %q", packet.Info)
	}
	if !strings.Contains(packet.Info, "token=[REDACTED]") {
		t.Fatalf("packet Info was not redacted: %q", packet.Info)
	}
}

func TestIsTSharkFilterErrorMatchesProtocolFieldWording(t *testing.T) {
	err := fmt.Errorf("%w: tshark failed: Running as user \"root\" and group \"root\". This could be dangerous.\ntshark: \"bad_field\" is not a valid protocol or protocol field.", errAnalyzerFailed)
	if !isTSharkFilterError(err) {
		t.Fatalf("isTSharkFilterError = false for current tshark invalid-field wording: %v", err)
	}
}

func TestInspectArtifactRejectsSymlinkOutsideAllowlist(t *testing.T) {
	allowedDir := t.TempDir()
	outsideDir := t.TempDir()
	outsidePath := filepath.Join(outsideDir, "outside.pcap")
	if err := os.WriteFile(outsidePath, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(allowedDir, "link.pcap")
	if err := os.Symlink(outsidePath, linkPath); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Normalize(config.Config{AllowedArtifactDirs: []string{allowedDir}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = inspectArtifact(linkPath, cfg, artifactExpectations{})
	if !errors.Is(err, errPathOutsideAllowlist) {
		t.Fatalf("inspectArtifact err = %v, want %v", err, errPathOutsideAllowlist)
	}
}

func TestAnalyzeArtifactBubblesInvalidFilterToTopLevel(t *testing.T) {
	requireCommand(t, "tshark")

	dir := t.TempDir()
	path := filepath.Join(dir, "http.pcap")
	if err := os.WriteFile(path, syntheticHTTPPcap(), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{dir},
		Analysis: config.AnalysisConfig{
			CommandTimeoutSeconds: 10,
			MaxStdoutBytes:        200000,
			MaxPacketRows:         20,
			MaxASCIIStrings:       20,
			MaxASCIIBytes:         20000,
			MaxZeekRecordsPerLog:  20,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := inspectArtifact(path, cfg, artifactExpectations{})
	if err != nil {
		t.Fatal(err)
	}

	out := analyzeArtifact(context.Background(), artifact, cfg, analyzeInput{
		IncludeZeek:   ptrBool(false),
		IncludeASCII:  ptrBool(false),
		DisplayFilter: "this_is_not_a_real_filter_field == 1",
	})

	var found bool
	for _, terr := range out.Errors {
		if terr.Kind == ErrorKindInvalidFilter {
			found = true
			if terr.Field != "display_filter" {
				t.Fatalf("invalid_filter Field = %q, want display_filter", terr.Field)
			}
			break
		}
	}
	if !found {
		t.Fatalf("top-level out.Errors[] did not include invalid_filter; got %#v", out.Errors)
	}

	var findingFound bool
	for _, f := range out.Findings {
		if f.Code == ErrorKindInvalidFilter {
			findingFound = true
			break
		}
	}
	if !findingFound {
		t.Fatalf("findings did not mirror invalid_filter; got %#v", out.Findings)
	}
}

func ptrBool(v bool) *bool { return &v }

func TestTSharkSectionsAvailableIsPartialSafe(t *testing.T) {
	cases := []struct {
		name string
		out  analyzeOutput
		want []string
	}{
		{
			name: "all_sections",
			out: analyzeOutput{
				Protocols:     &ProtocolsSection{Hierarchy: "frame:1\n"},
				Conversations: map[string]string{"tcp": "..."},
				Packets:       []TSharkPacketSummary{{Number: "1"}},
			},
			want: []string{"protocol hierarchy", "conversation tables", "packet summaries"},
		},
		{
			name: "only_protocol_hierarchy",
			out: analyzeOutput{
				Protocols: &ProtocolsSection{Hierarchy: "frame:1\n"},
			},
			want: []string{"protocol hierarchy"},
		},
		{
			name: "no_packets_after_invalid_filter",
			out: analyzeOutput{
				Protocols:     &ProtocolsSection{Hierarchy: "frame:1\n"},
				Conversations: map[string]string{"tcp": "..."},
			},
			want: []string{"protocol hierarchy", "conversation tables"},
		},
		{
			name: "empty",
			out:  analyzeOutput{},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tsharkSectionsAvailable(tc.out)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i, section := range got {
				if section != tc.want[i] {
					t.Fatalf("section[%d] = %q, want %q", i, section, tc.want[i])
				}
			}
		})
	}
}

func TestAnalyzeArtifactIntegrationWithPacketTools(t *testing.T) {
	requireCommand(t, "capinfos")
	requireCommand(t, "tshark")
	requireCommand(t, "zeek")

	dir := t.TempDir()
	path := filepath.Join(dir, "http.pcap")
	if err := os.WriteFile(path, syntheticHTTPPcap(), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{dir},
		Analysis: config.AnalysisConfig{
			CommandTimeoutSeconds: 10,
			MaxStdoutBytes:        200000,
			MaxPacketRows:         20,
			MaxASCIIStrings:       20,
			MaxASCIIBytes:         20000,
			MaxZeekRecordsPerLog:  20,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := inspectArtifact(path, cfg, artifactExpectations{})
	if err != nil {
		t.Fatal(err)
	}

	out := analyzeArtifact(context.Background(), artifact, cfg, analyzeInput{
		DisplayFilter: "tcp.port == 80",
	})
	if out.SchemaVersion != SchemaVersion {
		t.Fatalf("SchemaVersion = %q, want %q", out.SchemaVersion, SchemaVersion)
	}
	if out.CaptureSummary == nil || out.CaptureSummary.Raw == "" {
		t.Fatalf("missing capture_summary: %#v", out.CaptureSummary)
	}
	if len(out.Packets) == 0 {
		t.Fatalf("missing tshark packet rows: %#v", out.Packets)
	}
	if len(out.ZeekLogs) == 0 {
		t.Fatalf("missing zeek_logs; errors: %#v", out.Errors)
	}
	if out.ASCII == nil || !asciiContains(out.ASCII, "GET /hello?token=[REDACTED]") {
		t.Fatalf("missing redacted ASCII HTTP request: %#v", out.ASCII)
	}
	if out.ReportCharts == nil || out.ReportCharts.PacketTiming == nil || len(out.ReportCharts.ProtocolDistribution) == 0 {
		t.Fatalf("missing report_charts: %#v", out.ReportCharts)
	}
}

func requireCommand(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s not available on PATH", name)
	}
}

func asciiContains(report *ASCIIReport, needle string) bool {
	for _, s := range report.Strings {
		if strings.Contains(s.Text, needle) {
			return true
		}
	}
	return false
}

func syntheticHTTPPcap() []byte {
	payload := []byte("GET /hello?token=secret HTTP/1.1\r\nHost: example.test\r\nUser-Agent: cute-pcap-mcp-test\r\n\r\n")
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
	writeLE := func(v any) {
		_ = binary.Write(&buf, binary.LittleEndian, v)
	}
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

func ipv4Checksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
