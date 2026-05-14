package pcap

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"cute-pcap-mcp/internal/config"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestDiagnoseV1SymptomContracts(t *testing.T) {
	fixtures := diagnoseSyntheticFixtures()
	for _, code := range diagnoseSymptomCodes() {
		t.Run(code, func(t *testing.T) {
			fixture, ok := fixtures[code]
			if !ok {
				t.Fatalf("missing fixture for %s", code)
			}
			symptoms, findings := diagnoseSymptomsFromPackets(fixture.positive, diagnoseRunOptions{
				enabled: map[string]bool{code: true},
			})
			if len(findings) != 0 {
				t.Fatalf("positive fixture produced findings: %+v", findings)
			}
			got := findDiagnoseSymptom(symptoms, code)
			if got == nil {
				t.Fatalf("positive fixture did not produce %s; symptoms=%+v", code, symptoms)
			}
			assertDiagnoseContract(t, *got)

			negative, negativeFindings := diagnoseSymptomsFromPackets(fixture.negative, diagnoseRunOptions{
				enabled: map[string]bool{code: true},
			})
			if len(negativeFindings) != 0 {
				t.Fatalf("negative fixture produced findings: %+v", negativeFindings)
			}
			if got := findDiagnoseSymptom(negative, code); got != nil {
				t.Fatalf("negative fixture produced %s: %+v", code, *got)
			}
		})
	}
}

func TestDiagnoseFixtureRegistryCoversClosedVocabulary(t *testing.T) {
	fixtures := diagnoseSyntheticFixtures()
	for _, code := range diagnoseSymptomCodes() {
		fixture, ok := fixtures[code]
		if !ok {
			t.Fatalf("missing fixture pair for %s", code)
		}
		if len(fixture.positive) == 0 {
			t.Fatalf("positive fixture for %s is empty", code)
		}
		if len(fixture.negative) == 0 {
			t.Fatalf("negative fixture for %s is empty", code)
		}
	}
	for code := range fixtures {
		if !isDiagnoseSymptomCode(code) {
			t.Fatalf("fixture exists for unregistered symptom code %q", code)
		}
	}
}

func TestDiagnoseFindingVocabularyIsClosed(t *testing.T) {
	seen := map[string]bool{}
	for _, code := range diagnoseFindingCodes() {
		if code == "" {
			t.Fatal("finding vocabulary contains empty token")
		}
		if seen[code] {
			t.Fatalf("finding vocabulary contains duplicate token %q", code)
		}
		seen[code] = true
	}
	for _, code := range []string{
		FindingDiagnoseFlowUnparseable,
		FindingDiagnoseCaptureTruncated,
		FindingDiagnoseWindowTooShort,
		FindingDiagnoseParseTimeout,
		FindingDiagnoseLacksInterfaceMetadata,
		FindingDiagnoseUnrecognizedPattern,
		FindingDiagnoseInputInvalid,
		FindingDiagnosePathInvalid,
		FindingDiagnoseArtifactMismatch,
	} {
		if !seen[code] {
			t.Fatalf("finding vocabulary missing %s", code)
		}
	}
}

func TestDiagnoseUnrecognizedPatternIsFindingOnly(t *testing.T) {
	if isDiagnoseSymptomCode(FindingDiagnoseUnrecognizedPattern) {
		t.Fatalf("%s must not be accepted as a symptom token", FindingDiagnoseUnrecognizedPattern)
	}
	finding := diagnoseUnrecognizedPatternFinding("extractor=candidate_without_promoted_symptom")
	if finding.Code != FindingDiagnoseUnrecognizedPattern {
		t.Fatalf("Code = %q, want %q", finding.Code, FindingDiagnoseUnrecognizedPattern)
	}
	if finding.Severity != "info" {
		t.Fatalf("Severity = %q, want info", finding.Severity)
	}
	if finding.Detail == "" {
		t.Fatal("Detail is empty, want bounded structural detail")
	}
}

func TestDiagnoseNarrativesStayVendorNeutralAndObservableOnly(t *testing.T) {
	banned := []string{
		"bigip", "big-ip", "f5", "palo", "paloalto", "cisco", "nlb", "haproxy", "nginx",
		"root cause", "caused by", "misconfigured", "down", "closed", "monitor", "plain port",
	}
	fixtures := diagnoseSyntheticFixtures()
	for _, code := range diagnoseSymptomCodes() {
		symptoms, _ := diagnoseSymptomsFromPackets(fixtures[code].positive, diagnoseRunOptions{
			enabled: map[string]bool{code: true},
		})
		got := findDiagnoseSymptom(symptoms, code)
		if got == nil {
			t.Fatalf("positive fixture did not produce %s", code)
		}
		lower := strings.ToLower(got.Narrative)
		for _, word := range banned {
			if strings.Contains(lower, word) {
				t.Fatalf("narrative for %s contains vendor token %q: %q", code, word, got.Narrative)
			}
		}
	}
}

func TestDetectSymptomsDocsAvoidRootCauseClaimsAndOldNames(t *testing.T) {
	section := toolReferenceSection(t, "pcap_detect_symptoms")
	for _, forbidden := range []string{
		"pcap_diagnose_symptoms",
		"tls_handshake_attempted_on_plain_port",
		"monitor_probe_returns_rst",
		"root cause is",
		"caused by",
		"misconfigured",
		"server is down",
		"port is closed",
	} {
		if strings.Contains(strings.ToLower(section), forbidden) {
			t.Fatalf("pcap_detect_symptoms docs contain forbidden phrase %q", forbidden)
		}
	}
}

func TestDiagnoseOutputDoesNotExposeRawPayloadBytes(t *testing.T) {
	symptoms, findings := diagnoseSymptomsFromPackets(diagnoseSyntheticFixtures()[SymptomTLSAlertAfterClientHello].positive, diagnoseRunOptions{
		enabled: map[string]bool{SymptomTLSAlertAfterClientHello: true},
	})
	out := diagnoseOutput{
		SchemaVersion: DiagnoseSchemaVersion,
		Path:          "/safe/fixtures/tls-on-plain-port.pcap",
		SizeBytes:     1234,
		SHA256:        strings.Repeat("a", 64),
		Symptoms:      symptoms,
		Findings:      findings,
	}
	body, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"GET /hello", "token=secret", "HTTP/1.1", "Host: example.test"} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("diagnose output exposed raw payload fragment %q: %s", forbidden, string(body))
		}
	}
}

func TestDiagnoseFailClosedValidationResponses(t *testing.T) {
	root := t.TempDir()
	pcapDir := filepath.Join(root, "pcaps")
	if err := os.MkdirAll(pcapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pcapPath := filepath.Join(pcapDir, "http.pcap")
	if err := os.WriteFile(pcapPath, syntheticHTTPPcap(), 0o600); err != nil {
		t.Fatal(err)
	}

	session, cleanup := newDiagnoseTestSession(t, pcapDir)
	defer cleanup()

	cases := []struct {
		name        string
		args        map[string]any
		wantFinding string
	}{
		{
			name:        "missing_path",
			args:        map[string]any{},
			wantFinding: FindingDiagnoseInputInvalid,
		},
		{
			name: "malformed_sha",
			args: map[string]any{
				"path":            pcapPath,
				"expected_sha256": "not-hex",
			},
			wantFinding: FindingDiagnoseInputInvalid,
		},
		{
			name: "negative_size",
			args: map[string]any{
				"path":                pcapPath,
				"expected_size_bytes": -1,
			},
			wantFinding: FindingDiagnoseInputInvalid,
		},
		{
			name: "bad_scope",
			args: map[string]any{
				"path": pcapPath,
				"scope": map[string]any{
					"src_ip": "not-an-ip",
				},
			},
			wantFinding: FindingDiagnoseInputInvalid,
		},
		{
			name: "unknown_filter",
			args: map[string]any{
				"path":           pcapPath,
				"symptom_filter": []string{"not_registered"},
			},
			wantFinding: FindingDiagnoseInputInvalid,
		},
		{
			name: "path_outside_allowlist",
			args: map[string]any{
				"path": "/var/empty/definitely-not-allowlisted.pcap",
			},
			wantFinding: FindingDiagnosePathInvalid,
		},
		{
			name: "artifact_mismatch",
			args: map[string]any{
				"path":                pcapPath,
				"expected_size_bytes": 999999,
			},
			wantFinding: FindingDiagnoseArtifactMismatch,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
				Name:      "pcap_detect_symptoms",
				Arguments: tc.args,
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if result.IsError {
				t.Fatalf("pcap_detect_symptoms returned MCP error for fail-closed validation: %+v", result)
			}
			var out diagnoseOutput
			body, _ := json.Marshal(result.StructuredContent)
			if err := json.Unmarshal(body, &out); err != nil {
				t.Fatalf("unmarshal diagnose output: %v body=%s", err, string(body))
			}
			if out.SchemaVersion != DiagnoseSchemaVersion {
				t.Fatalf("schema_version = %q, want %q", out.SchemaVersion, DiagnoseSchemaVersion)
			}
			if len(out.Symptoms) != 0 {
				t.Fatalf("fail-closed response returned symptoms: %+v", out.Symptoms)
			}
			if !diagnoseFindingsContain(out.Findings, tc.wantFinding) {
				t.Fatalf("findings = %+v, want %s", out.Findings, tc.wantFinding)
			}
		})
	}
}

func TestDiagnoseIntegrationDoesNotExposeSyntheticHTTPPayload(t *testing.T) {
	requireCommand(t, "tshark")

	root := t.TempDir()
	pcapDir := filepath.Join(root, "pcaps")
	if err := os.MkdirAll(pcapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pcapPath := filepath.Join(pcapDir, "http.pcap")
	if err := os.WriteFile(pcapPath, syntheticHTTPPcap(), 0o600); err != nil {
		t.Fatal(err)
	}

	session, cleanup := newDiagnoseTestSession(t, pcapDir)
	defer cleanup()

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "pcap_detect_symptoms",
		Arguments: map[string]any{
			"path": pcapPath,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("diagnose returned IsError=true: %+v", result)
	}
	body, _ := json.Marshal(result.StructuredContent)
	for _, forbidden := range []string{"GET /hello", "token=secret", "HTTP/1.1", "Host: example.test"} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("diagnose integration exposed raw payload fragment %q: %s", forbidden, string(body))
		}
	}
}

func TestRunDiagnosePacketRowsIntegration(t *testing.T) {
	requireCommand(t, "tshark")

	root := t.TempDir()
	pcapDir := filepath.Join(root, "pcaps")
	if err := os.MkdirAll(pcapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pcapPath := filepath.Join(pcapDir, "http.pcap")
	if err := os.WriteFile(pcapPath, syntheticHTTPPcap(), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{pcapDir},
		Analysis: config.AnalysisConfig{
			CommandTimeoutSeconds: 10,
			MaxStdoutBytes:        200000,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := inspectArtifact(pcapPath, cfg, artifactExpectations{})
	if err != nil {
		t.Fatal(err)
	}

	packets, truncated, err := runDiagnosePacketRows(context.Background(), artifact, cfg)
	if err != nil {
		t.Fatalf("runDiagnosePacketRows: %v", err)
	}
	if truncated {
		t.Fatal("synthetic HTTP pcap reported truncated")
	}
	if len(packets) != 1 {
		t.Fatalf("len(packets) = %d, want 1: %+v", len(packets), packets)
	}
	got := packets[0]
	if got.Protocol != "tcp" {
		t.Fatalf("Protocol = %q, want tcp", got.Protocol)
	}
	if got.SrcIP != "192.0.2.10" || got.DstIP != "198.51.100.20" {
		t.Fatalf("flow IPs = %s -> %s, want synthetic HTTP tuple", got.SrcIP, got.DstIP)
	}
	if got.SrcPort != 55555 || got.DstPort != 80 {
		t.Fatalf("flow ports = %d -> %d, want 55555 -> 80", got.SrcPort, got.DstPort)
	}
	if got.TCPLen == 0 {
		t.Fatal("TCPLen = 0, want payload length metadata")
	}
	if !got.HTTPPlaintext {
		t.Fatal("HTTPPlaintext = false, want true")
	}
}

type diagnoseFixturePair struct {
	positive []diagnosePacket
	negative []diagnosePacket
}

func diagnoseSyntheticFixtures() map[string]diagnoseFixturePair {
	return map[string]diagnoseFixturePair{
		SymptomTLSAlertAfterClientHello: {
			positive: tlsAlertAfterClientHelloPositive(),
			negative: tlsAlertAfterClientHelloNegative(),
		},
		SymptomTCPRSTAfterSYNACKNoAppData: {
			positive: rstAfterSynackPositive(),
			negative: rstAfterSynackNegative(),
		},
		SymptomTCPHandshakeCompletedNoAppData: {
			positive: handshakeCompletedNoAppDataPositive(),
			negative: handshakeCompletedNoAppDataNegative(),
		},
		SymptomTCPRepeatedShortFlowsReturnRST: {
			positive: repeatedShortFlowsRSTPositive(),
			negative: repeatedShortFlowsRSTNegative(),
		},
		SymptomHTTPErrorStatusObserved: {
			positive: httpErrorStatusPositive(),
			negative: httpErrorStatusNegative(),
		},
		SymptomAsymmetricReturnPathObserved: {
			positive: asymmetricReturnPathPositive(),
			negative: asymmetricReturnPathNegative(),
		},
	}
}

func tlsAlertAfterClientHelloPositive() []diagnosePacket {
	return []diagnosePacket{
		diagPkt(1, 0, "", "192.0.2.10", 50000, "198.51.100.20", 80, "S", 0),
		diagPkt(2, 10, "", "198.51.100.20", 80, "192.0.2.10", 50000, "SA", 0),
		diagPkt(3, 20, "", "192.0.2.10", 50000, "198.51.100.20", 80, "A", 0),
		withTLSClientHello(diagPkt(4, 30, "", "192.0.2.10", 50000, "198.51.100.20", 80, "A", 120)),
		withTLSAlert(diagPkt(5, 40, "", "198.51.100.20", 80, "192.0.2.10", 50000, "A", 7), "fatal", "handshake_failure"),
	}
}

func tlsAlertAfterClientHelloNegative() []diagnosePacket {
	return []diagnosePacket{
		diagPkt(1, 0, "", "192.0.2.10", 50000, "198.51.100.20", 443, "S", 0),
		diagPkt(2, 10, "", "198.51.100.20", 443, "192.0.2.10", 50000, "SA", 0),
		diagPkt(3, 20, "", "192.0.2.10", 50000, "198.51.100.20", 443, "A", 0),
		withTLSClientHello(diagPkt(4, 30, "", "192.0.2.10", 50000, "198.51.100.20", 443, "A", 120)),
		withTLSServerHello(diagPkt(5, 40, "", "198.51.100.20", 443, "192.0.2.10", 50000, "A", 96)),
	}
}

func rstAfterSynackPositive() []diagnosePacket {
	return []diagnosePacket{
		diagPkt(1, 0, "", "192.0.2.10", 50001, "198.51.100.20", 8080, "S", 0),
		diagPkt(2, 10, "", "198.51.100.20", 8080, "192.0.2.10", 50001, "SA", 0),
		diagPkt(3, 20, "", "192.0.2.10", 50001, "198.51.100.20", 8080, "A", 0),
		diagPkt(4, 31, "", "198.51.100.20", 8080, "192.0.2.10", 50001, "R", 0),
	}
}

func rstAfterSynackNegative() []diagnosePacket {
	return []diagnosePacket{
		diagPkt(1, 0, "", "192.0.2.10", 50001, "198.51.100.20", 8080, "S", 0),
		diagPkt(2, 10, "", "198.51.100.20", 8080, "192.0.2.10", 50001, "SA", 0),
		diagPkt(3, 20, "", "192.0.2.10", 50001, "198.51.100.20", 8080, "A", 0),
		diagPkt(4, 30, "", "192.0.2.10", 50001, "198.51.100.20", 8080, "PA", 24),
		diagPkt(5, 40, "", "198.51.100.20", 8080, "192.0.2.10", 50001, "R", 0),
	}
}

func handshakeCompletedNoAppDataPositive() []diagnosePacket {
	return []diagnosePacket{
		diagPkt(1, 0, "", "192.0.2.11", 50002, "198.51.100.21", 8443, "S", 0),
		diagPkt(2, 10, "", "198.51.100.21", 8443, "192.0.2.11", 50002, "SA", 0),
		diagPkt(3, 20, "", "192.0.2.11", 50002, "198.51.100.21", 8443, "A", 0),
		diagPkt(4, 200, "", "192.0.2.11", 50002, "198.51.100.21", 8443, "FA", 0),
		diagPkt(5, 210, "", "198.51.100.21", 8443, "192.0.2.11", 50002, "FA", 0),
	}
}

func handshakeCompletedNoAppDataNegative() []diagnosePacket {
	return []diagnosePacket{
		diagPkt(1, 0, "", "192.0.2.11", 50002, "198.51.100.21", 8443, "S", 0),
		diagPkt(2, 10, "", "198.51.100.21", 8443, "192.0.2.11", 50002, "SA", 0),
		diagPkt(3, 20, "", "192.0.2.11", 50002, "198.51.100.21", 8443, "A", 0),
		diagPkt(4, 40, "", "192.0.2.11", 50002, "198.51.100.21", 8443, "PA", 32),
		diagPkt(5, 200, "", "192.0.2.11", 50002, "198.51.100.21", 8443, "FA", 0),
	}
}

func repeatedShortFlowsRSTPositive() []diagnosePacket {
	var packets []diagnosePacket
	num := 1
	for i, ms := range []int64{0, 30_000, 60_000, 90_000} {
		srcPort := 51000 + i
		packets = append(packets,
			diagPkt(num, ms, "", "192.0.2.30", srcPort, "198.51.100.40", 8080, "S", 0),
			diagPkt(num+1, ms+10, "", "198.51.100.40", 8080, "192.0.2.30", srcPort, "R", 0),
		)
		num += 2
	}
	return packets
}

func repeatedShortFlowsRSTNegative() []diagnosePacket {
	return []diagnosePacket{
		diagPkt(1, 0, "", "192.0.2.30", 51000, "198.51.100.40", 8080, "S", 0),
		diagPkt(2, 10, "", "198.51.100.40", 8080, "192.0.2.30", 51000, "R", 0),
		diagPkt(3, 40_000, "", "192.0.2.30", 51001, "198.51.100.40", 8080, "S", 0),
		diagPkt(4, 40_010, "", "198.51.100.40", 8080, "192.0.2.30", 51001, "R", 0),
		diagPkt(5, 80_000, "", "192.0.2.30", 51002, "198.51.100.40", 8080, "S", 0),
		diagPkt(6, 80_010, "", "198.51.100.40", 8080, "192.0.2.30", 51002, "R", 0),
		diagPkt(7, 120_000, "", "192.0.2.30", 51003, "198.51.100.40", 8080, "S", 0),
		diagPkt(8, 120_010, "", "198.51.100.40", 8080, "192.0.2.30", 51003, "R", 0),
	}
}

func httpErrorStatusPositive() []diagnosePacket {
	return []diagnosePacket{
		diagPkt(1, 0, "", "192.0.2.70", 53000, "198.51.100.80", 80, "S", 0),
		diagPkt(2, 10, "", "198.51.100.80", 80, "192.0.2.70", 53000, "SA", 0),
		diagPkt(3, 20, "", "192.0.2.70", 53000, "198.51.100.80", 80, "A", 0),
		withHTTPRequest(diagPkt(4, 30, "", "192.0.2.70", 53000, "198.51.100.80", 80, "PA", 64)),
		withHTTPStatus(diagPkt(5, 45, "", "198.51.100.80", 80, "192.0.2.70", 53000, "PA", 128), 503),
	}
}

func httpErrorStatusNegative() []diagnosePacket {
	return []diagnosePacket{
		diagPkt(1, 0, "", "192.0.2.70", 53000, "198.51.100.80", 80, "S", 0),
		diagPkt(2, 10, "", "198.51.100.80", 80, "192.0.2.70", 53000, "SA", 0),
		diagPkt(3, 20, "", "192.0.2.70", 53000, "198.51.100.80", 80, "A", 0),
		withHTTPRequest(diagPkt(4, 30, "", "192.0.2.70", 53000, "198.51.100.80", 80, "PA", 64)),
		withHTTPStatus(diagPkt(5, 45, "", "198.51.100.80", 80, "192.0.2.70", 53000, "PA", 128), 200),
	}
}

func asymmetricReturnPathPositive() []diagnosePacket {
	return []diagnosePacket{
		diagPkt(1, 0, "client-side", "192.0.2.50", 52000, "198.51.100.60", 443, "S", 0),
		diagPkt(2, 20, "server-side", "198.51.100.60", 443, "192.0.2.50", 52000, "SA", 0),
	}
}

func asymmetricReturnPathNegative() []diagnosePacket {
	return []diagnosePacket{
		diagPkt(1, 0, "client-side", "192.0.2.50", 52000, "198.51.100.60", 443, "S", 0),
		diagPkt(2, 20, "client-side", "198.51.100.60", 443, "192.0.2.50", 52000, "SA", 0),
	}
}

func diagPkt(num int, timeMS int64, iface, srcIP string, srcPort int, dstIP string, dstPort int, flags string, tcpLen int) diagnosePacket {
	return diagnosePacket{
		Number:        num,
		TimeMS:        timeMS,
		InterfaceName: iface,
		SrcIP:         srcIP,
		DstIP:         dstIP,
		SrcPort:       srcPort,
		DstPort:       dstPort,
		Protocol:      "tcp",
		SYN:           strings.Contains(flags, "S"),
		ACK:           strings.Contains(flags, "A"),
		RST:           strings.Contains(flags, "R"),
		FIN:           strings.Contains(flags, "F"),
		TCPLen:        tcpLen,
	}
}

func withTLSClientHello(packet diagnosePacket) diagnosePacket {
	packet.TLSHandshakeTypes = []int{1}
	packet.TLSRecordVersion = "TLS1.2"
	return packet
}

func withTLSAlert(packet diagnosePacket, level, desc string) diagnosePacket {
	packet.TLSAlertLevel = level
	packet.TLSAlertDesc = desc
	return packet
}

func withTLSServerHello(packet diagnosePacket) diagnosePacket {
	packet.TLSHandshakeTypes = []int{2}
	packet.TLSRecordVersion = "TLS1.2"
	return packet
}

func withHTTPRequest(packet diagnosePacket) diagnosePacket {
	packet.HTTPPlaintext = true
	return packet
}

func withHTTPStatus(packet diagnosePacket, status int) diagnosePacket {
	packet.HTTPPlaintext = true
	packet.HTTPResponseCode = status
	return packet
}

func findDiagnoseSymptom(symptoms []diagnoseSymptom, code string) *diagnoseSymptom {
	for i := range symptoms {
		if symptoms[i].Code == code {
			return &symptoms[i]
		}
	}
	return nil
}

func assertDiagnoseContract(t *testing.T, symptom diagnoseSymptom) {
	t.Helper()
	if symptom.Evidence.Flow == nil {
		t.Fatalf("%s evidence.flow = nil", symptom.Code)
	}
	if symptom.Evidence.PacketCount == 0 {
		t.Fatalf("%s evidence.packet_count = 0", symptom.Code)
	}
	if len(symptom.Evidence.PacketNumbers) == 0 {
		t.Fatalf("%s evidence.packet_numbers empty", symptom.Code)
	}
	if len(symptom.Limitations) == 0 {
		t.Fatalf("%s limitations empty", symptom.Code)
	}
	switch symptom.Code {
	case SymptomTLSAlertAfterClientHello:
		if symptom.Severity != "warning" || symptom.Confidence != "high" {
			t.Fatalf("severity/confidence = %s/%s, want warning/high", symptom.Severity, symptom.Confidence)
		}
		if symptom.Evidence.ClientHelloObserved == nil || !*symptom.Evidence.ClientHelloObserved {
			t.Fatalf("client_hello_observed = %v, want true", symptom.Evidence.ClientHelloObserved)
		}
		if symptom.Evidence.ServerResponseKind != "tls_alert" {
			t.Fatalf("server_response_kind = %q, want tls_alert", symptom.Evidence.ServerResponseKind)
		}
		if symptom.Evidence.TLSVersionOffered != "TLS1.2" {
			t.Fatalf("tls_version_offered = %q, want TLS1.2", symptom.Evidence.TLSVersionOffered)
		}
		if symptom.Evidence.TLSAlertLevel != "fatal" || symptom.Evidence.TLSAlertDescription != "handshake_failure" {
			t.Fatalf("tls alert = %q/%q, want fatal/handshake_failure", symptom.Evidence.TLSAlertLevel, symptom.Evidence.TLSAlertDescription)
		}
	case SymptomTCPRSTAfterSYNACKNoAppData:
		if symptom.Severity != "warning" || symptom.Confidence != "high" {
			t.Fatalf("severity/confidence = %s/%s, want warning/high", symptom.Severity, symptom.Confidence)
		}
		if symptom.Evidence.HandshakeCompleted == nil || !*symptom.Evidence.HandshakeCompleted {
			t.Fatalf("handshake_completed = %v, want true", symptom.Evidence.HandshakeCompleted)
		}
		if symptom.Evidence.AppBytesClientToServer != 0 || symptom.Evidence.AppBytesServerToClient != 0 {
			t.Fatalf("app bytes = %d/%d, want 0/0", symptom.Evidence.AppBytesClientToServer, symptom.Evidence.AppBytesServerToClient)
		}
		if symptom.Evidence.TimeToRSTMS <= 0 {
			t.Fatalf("time_to_rst_ms = %d, want > 0", symptom.Evidence.TimeToRSTMS)
		}
	case SymptomTCPHandshakeCompletedNoAppData:
		if symptom.Severity != "info" || symptom.Confidence != "medium" {
			t.Fatalf("severity/confidence = %s/%s, want info/medium", symptom.Severity, symptom.Confidence)
		}
		if symptom.Evidence.HandshakeCompleted == nil || !*symptom.Evidence.HandshakeCompleted {
			t.Fatalf("handshake_completed = %v, want true", symptom.Evidence.HandshakeCompleted)
		}
		if symptom.Evidence.AppBytesClientToServer != 0 || symptom.Evidence.AppBytesServerToClient != 0 {
			t.Fatalf("app bytes = %d/%d, want 0/0", symptom.Evidence.AppBytesClientToServer, symptom.Evidence.AppBytesServerToClient)
		}
		if symptom.Evidence.TerminationKind != "fin" {
			t.Fatalf("termination_kind = %q, want fin", symptom.Evidence.TerminationKind)
		}
	case SymptomTCPRepeatedShortFlowsReturnRST:
		if symptom.Severity != "info" || symptom.Confidence != "medium" {
			t.Fatalf("severity/confidence = %s/%s, want info/medium", symptom.Severity, symptom.Confidence)
		}
		if symptom.Evidence.FlowCount < diagnoseMinShortFlowCount {
			t.Fatalf("flow_count = %d, want >= %d", symptom.Evidence.FlowCount, diagnoseMinShortFlowCount)
		}
		if symptom.Evidence.CadenceSecondsP50 > 30 {
			t.Fatalf("cadence_seconds_p50 = %f, want <= 30", symptom.Evidence.CadenceSecondsP50)
		}
		if symptom.Evidence.RSTRatio < 0.9 {
			t.Fatalf("rst_ratio = %f, want >= 0.9", symptom.Evidence.RSTRatio)
		}
	case SymptomHTTPErrorStatusObserved:
		if symptom.Severity != "warning" || symptom.Confidence != "high" {
			t.Fatalf("severity/confidence = %s/%s, want warning/high", symptom.Severity, symptom.Confidence)
		}
		if got, want := symptom.Evidence.HTTPStatusCodes, []int{503}; !reflect.DeepEqual(got, want) {
			t.Fatalf("http_status_codes = %v, want %v", got, want)
		}
		if symptom.Evidence.HTTPErrorCount != 1 {
			t.Fatalf("http_error_count = %d, want 1", symptom.Evidence.HTTPErrorCount)
		}
	case SymptomAsymmetricReturnPathObserved:
		if symptom.Severity != "warning" || symptom.Confidence != "medium" {
			t.Fatalf("severity/confidence = %s/%s, want warning/medium", symptom.Severity, symptom.Confidence)
		}
		if symptom.Evidence.SYNSeen == nil || !*symptom.Evidence.SYNSeen {
			t.Fatalf("syn_seen = %v, want true", symptom.Evidence.SYNSeen)
		}
		if symptom.Evidence.SYNACKSeen == nil || !*symptom.Evidence.SYNACKSeen {
			t.Fatalf("syn_ack_seen = %v, want true", symptom.Evidence.SYNACKSeen)
		}
		if len(symptom.Evidence.InterfacesObserved) < 2 {
			t.Fatalf("interfaces_observed = %v, want at least 2", symptom.Evidence.InterfacesObserved)
		}
		if symptom.Evidence.FlowCompleteViaOtherInterface == nil || !*symptom.Evidence.FlowCompleteViaOtherInterface {
			t.Fatalf("flow_complete_via_other_interface = %v, want true", symptom.Evidence.FlowCompleteViaOtherInterface)
		}
	default:
		t.Fatalf("unhandled symptom code %q", symptom.Code)
	}
}

func newDiagnoseTestSession(t *testing.T, pcapDir string) (*mcp.ClientSession, func()) {
	t.Helper()
	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{pcapDir},
		Analysis: config.AnalysisConfig{
			CommandTimeoutSeconds: 10,
			MaxStdoutBytes:        200000,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	server := NewServer(cfg, ServerOptions{Logger: slog.New(slog.NewTextHandler(discardWriter{}, nil))})
	go func() { _ = server.Run(ctx, serverTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		cancel()
		t.Fatalf("client.Connect: %v", err)
	}
	return session, func() {
		_ = session.Close()
		cancel()
	}
}

func diagnoseFindingsContain(findings []diagnoseFinding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}

func toolReferenceSection(t *testing.T, toolName string) string {
	t.Helper()
	src := readToolReference(t)
	startMarker := "### `" + toolName + "`"
	start := strings.Index(src, startMarker)
	if start == -1 {
		t.Fatalf("TOOL_REFERENCE.md missing section %s", startMarker)
	}
	rest := src[start+len(startMarker):]
	end := strings.Index(rest, "\n### `")
	if end == -1 {
		return rest
	}
	return rest[:end]
}
