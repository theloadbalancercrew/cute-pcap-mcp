package pcap

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cute-pcap-mcp/internal/config"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestDiagnoseSymptomFixtureRatchet(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "symptoms")
	for _, token := range diagnoseSymptomVocabulary {
		dir := filepath.Join(root, token)
		for _, name := range []string{"positive.pcap", "negative.pcap", "README.md", "generate.sh"} {
			if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
				t.Fatalf("%s fixture missing %s: %v", token, name, err)
			}
		}
	}
}

func TestDiagnoseSymptomFixtures(t *testing.T) {
	requireCommand(t, "tshark")

	cases := []struct {
		code       string
		severity   string
		confidence string
		assert     func(t *testing.T, symptom DiagnoseSymptom)
	}{
		{
			code:       DiagnoseSymptomTLSHandshakeAttemptedOnPlainPort,
			severity:   "warning",
			confidence: "high",
			assert: func(t *testing.T, symptom DiagnoseSymptom) {
				if symptom.Evidence.ClientHelloObserved == nil || !*symptom.Evidence.ClientHelloObserved {
					t.Fatalf("ClientHelloObserved = %v, want true", symptom.Evidence.ClientHelloObserved)
				}
				if symptom.Evidence.ServerResponseKind != "rst" {
					t.Fatalf("ServerResponseKind = %q, want rst", symptom.Evidence.ServerResponseKind)
				}
				if symptom.Evidence.TLSVersionOffered != "TLS1.2" {
					t.Fatalf("TLSVersionOffered = %q, want TLS1.2", symptom.Evidence.TLSVersionOffered)
				}
			},
		},
		{
			code:       DiagnoseSymptomTCPRSTAfterSYNACKNoAppData,
			severity:   "warning",
			confidence: "high",
			assert: func(t *testing.T, symptom DiagnoseSymptom) {
				if symptom.Evidence.HandshakeCompleted == nil || !*symptom.Evidence.HandshakeCompleted {
					t.Fatalf("HandshakeCompleted = %v, want true", symptom.Evidence.HandshakeCompleted)
				}
				if symptom.Evidence.AppBytesClientToServer == nil || *symptom.Evidence.AppBytesClientToServer != 0 {
					t.Fatalf("AppBytesClientToServer = %v, want 0", symptom.Evidence.AppBytesClientToServer)
				}
				if symptom.Evidence.AppBytesServerToClient == nil || *symptom.Evidence.AppBytesServerToClient != 0 {
					t.Fatalf("AppBytesServerToClient = %v, want 0", symptom.Evidence.AppBytesServerToClient)
				}
				if symptom.Evidence.TimeToRSTMS == nil || *symptom.Evidence.TimeToRSTMS != 1 {
					t.Fatalf("TimeToRSTMS = %v, want 1", symptom.Evidence.TimeToRSTMS)
				}
			},
		},
		{
			code:       DiagnoseSymptomMonitorProbeReturnsRST,
			severity:   "info",
			confidence: "medium",
			assert: func(t *testing.T, symptom DiagnoseSymptom) {
				if symptom.Evidence.ProbeCount != 4 {
					t.Fatalf("ProbeCount = %d, want 4", symptom.Evidence.ProbeCount)
				}
				if symptom.Evidence.ProbeCadenceSecondsP50 != 30 {
					t.Fatalf("ProbeCadenceSecondsP50 = %v, want 30", symptom.Evidence.ProbeCadenceSecondsP50)
				}
				if symptom.Evidence.RSTRatio != 1 {
					t.Fatalf("RSTRatio = %v, want 1", symptom.Evidence.RSTRatio)
				}
			},
		},
		{
			code:       DiagnoseSymptomAsymmetricReturnPathObserved,
			severity:   "warning",
			confidence: "medium",
			assert: func(t *testing.T, symptom DiagnoseSymptom) {
				if symptom.Evidence.SynSeen == nil || !*symptom.Evidence.SynSeen {
					t.Fatalf("SynSeen = %v, want true", symptom.Evidence.SynSeen)
				}
				if symptom.Evidence.SynAckSeen == nil || !*symptom.Evidence.SynAckSeen {
					t.Fatalf("SynAckSeen = %v, want true", symptom.Evidence.SynAckSeen)
				}
				if symptom.Evidence.FlowCompleteViaOtherInterface == nil || !*symptom.Evidence.FlowCompleteViaOtherInterface {
					t.Fatalf("FlowCompleteViaOtherInterface = %v, want true", symptom.Evidence.FlowCompleteViaOtherInterface)
				}
				want := []string{"client_vlan", "server_vlan"}
				if strings.Join(symptom.Evidence.InterfacesObserved, ",") != strings.Join(want, ",") {
					t.Fatalf("InterfacesObserved = %v, want %v", symptom.Evidence.InterfacesObserved, want)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.code+"_positive", func(t *testing.T) {
			out := runDiagnoseFixture(t, tc.code, "positive.pcap")
			if out.SchemaVersion != DiagnoseSchemaVersion {
				t.Fatalf("SchemaVersion = %q, want %q", out.SchemaVersion, DiagnoseSchemaVersion)
			}
			got := symptomsWithCode(out.Symptoms, tc.code)
			if len(got) != 1 {
				body, _ := json.MarshalIndent(out, "", "  ")
				t.Fatalf("symptoms with code %q = %d, want 1. output=%s", tc.code, len(got), string(body))
			}
			if got[0].Severity != tc.severity {
				t.Fatalf("Severity = %q, want %q", got[0].Severity, tc.severity)
			}
			if got[0].Confidence != tc.confidence {
				t.Fatalf("Confidence = %q, want %q", got[0].Confidence, tc.confidence)
			}
			tc.assert(t, got[0])
			assertVendorNeutralNarrative(t, got[0].Narrative)
			assertDiagnoseOutputCarriesNoRawBytes(t, out)
		})

		t.Run(tc.code+"_negative", func(t *testing.T) {
			out := runDiagnoseFixture(t, tc.code, "negative.pcap")
			if got := symptomsWithCode(out.Symptoms, tc.code); len(got) != 0 {
				body, _ := json.MarshalIndent(out, "", "  ")
				t.Fatalf("negative fixture emitted %q: %s", tc.code, string(body))
			}
			assertDiagnoseOutputCarriesNoRawBytes(t, out)
		})
	}
}

func TestDiagnoseFailClosedValidationResponses(t *testing.T) {
	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{filepath.Join("..", "..", "testdata", "symptoms")},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	server := NewServer(cfg, ServerOptions{Logger: slog.New(slog.NewTextHandler(discardWriter{}, nil))})
	go func() { _ = server.Run(ctx, serverTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	for _, tc := range []struct {
		name        string
		args        map[string]any
		wantFinding string
		wantIsError bool
	}{
		{
			name:        "unknown_filter_token",
			args:        map[string]any{"path": "ignored.pcap", "symptom_filter": []string{"future_vendor_guess"}},
			wantFinding: DiagnoseFindingInputInvalid,
		},
		{
			name:        "malformed_expected_sha256",
			args:        map[string]any{"path": "ignored.pcap", "expected_sha256": "bad"},
			wantFinding: DiagnoseFindingInputInvalid,
		},
		{
			name:        "missing_path",
			args:        map[string]any{"path": ""},
			wantFinding: DiagnoseFindingInputInvalid,
		},
		{
			name:        "invalid_scope_field",
			args:        map[string]any{"path": "ignored.pcap", "scope": map[string]any{"src_port": 70000}},
			wantFinding: DiagnoseFindingInputInvalid,
		},
		{
			name:        "path_outside_allowlist",
			args:        map[string]any{"path": "/var/empty/definitely-not-allowlisted.pcap"},
			wantFinding: DiagnoseFindingPathInvalid,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := session.CallTool(ctx, &mcp.CallToolParams{
				Name:      "pcap_diagnose_symptoms",
				Arguments: tc.args,
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if result.IsError != tc.wantIsError {
				t.Fatalf("IsError = %v, want %v", result.IsError, tc.wantIsError)
			}
			var out diagnoseOutput
			body, _ := json.Marshal(result.StructuredContent)
			if err := json.Unmarshal(body, &out); err != nil {
				t.Fatalf("unmarshal structured content: %v body=%s", err, string(body))
			}
			if out.SchemaVersion != DiagnoseSchemaVersion {
				t.Fatalf("SchemaVersion = %q, want %q", out.SchemaVersion, DiagnoseSchemaVersion)
			}
			if len(out.Symptoms) != 0 {
				t.Fatalf("Symptoms = %#v, want empty", out.Symptoms)
			}
			if !diagnoseFindingPresent(out.Findings, tc.wantFinding) {
				t.Fatalf("missing finding %q in %#v", tc.wantFinding, out.Findings)
			}
		})
	}
}

func TestDiagnoseArtifactMismatchFinding(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "symptoms", DiagnoseSymptomTCPRSTAfterSYNACKNoAppData)
	pcapPath := filepath.Join(root, "positive.pcap")
	info, err := os.Stat(pcapPath)
	if err != nil {
		t.Fatal(err)
	}
	wrongSize := info.Size() + 1
	out := callDiagnoseTool(t, root, map[string]any{
		"path":                pcapPath,
		"expected_size_bytes": wrongSize,
	})
	if len(out.Symptoms) != 0 {
		t.Fatalf("Symptoms = %#v, want empty", out.Symptoms)
	}
	if !diagnoseFindingPresent(out.Findings, DiagnoseFindingArtifactMismatch) {
		t.Fatalf("missing artifact mismatch finding in %#v", out.Findings)
	}
}

func TestDiagnoseVocabularyDocumented(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "docs", "TOOL_REFERENCE.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, token := range diagnoseSymptomVocabulary {
		if !strings.Contains(text, "`"+token+"`") {
			t.Fatalf("TOOL_REFERENCE.md missing diagnose symptom token %q", token)
		}
	}
	for _, token := range diagnoseFindingVocabulary {
		if !strings.Contains(text, "`"+token+"`") {
			t.Fatalf("TOOL_REFERENCE.md missing diagnose finding token %q", token)
		}
	}
}

func runDiagnoseFixture(t *testing.T, token, filename string) diagnoseOutput {
	t.Helper()
	root := filepath.Join("..", "..", "testdata", "symptoms", token)
	return callDiagnoseTool(t, root, map[string]any{
		"path":           filepath.Join(root, filename),
		"symptom_filter": []string{token},
	})
}

func callDiagnoseTool(t *testing.T, allowedRoot string, args map[string]any) diagnoseOutput {
	t.Helper()
	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{allowedRoot},
		Analysis: config.AnalysisConfig{
			MaxStdoutBytes:        500000,
			MaxConcurrentAnalyses: 1,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := inspectArtifact(args["path"].(string), cfg, artifactExpectations{})
	_, hasExpectedSize := args["expected_size_bytes"]
	_, hasExpectedHash := args["expected_sha256"]
	if err == nil && !hasExpectedSize && !hasExpectedHash {
		input := diagnoseInput{Path: artifact.Path}
		if filters, ok := args["symptom_filter"].([]string); ok {
			input.SymptomFilter = filters
		}
		return diagnoseSymptoms(context.Background(), artifact, cfg, input)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	server := NewServer(cfg, ServerOptions{Logger: slog.New(slog.NewTextHandler(discardWriter{}, nil))})
	go func() { _ = server.Run(ctx, serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "pcap_diagnose_symptoms", Arguments: args})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	var out diagnoseOutput
	body, _ := json.Marshal(result.StructuredContent)
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("unmarshal structured content: %v body=%s", err, string(body))
	}
	return out
}

func symptomsWithCode(symptoms []DiagnoseSymptom, code string) []DiagnoseSymptom {
	var out []DiagnoseSymptom
	for _, symptom := range symptoms {
		if symptom.Code == code {
			out = append(out, symptom)
		}
	}
	return out
}

func diagnoseFindingPresent(findings []DiagnoseFinding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}

func assertVendorNeutralNarrative(t *testing.T, narrative string) {
	t.Helper()
	lower := strings.ToLower(narrative)
	for _, banned := range []string{"bigip", "f5", "palo", "paloalto", "cisco", "nlb", "haproxy", "nginx"} {
		if strings.Contains(lower, banned) {
			t.Fatalf("narrative %q contains vendor token %q", narrative, banned)
		}
	}
}

func assertDiagnoseOutputCarriesNoRawBytes(t *testing.T, out diagnoseOutput) {
	t.Helper()
	body, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(body))
	for _, banned := range []string{
		"160301002f",
		"474554202f6f6b",
		"get /ok",
		"1111111111111111",
		"2222222222222222",
	} {
		if strings.Contains(text, banned) {
			t.Fatalf("diagnose output leaked raw packet bytes marker %q: %s", banned, string(body))
		}
	}
}
