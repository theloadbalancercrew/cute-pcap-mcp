package pcap

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"

	"cute-pcap-mcp/internal/config"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestExplainConnectionSelectorFailureSetsIsError pins that a
// selector resolution failure (e.g. zeek_uid missing from conn.log,
// frame_number on a non-stream frame) propagates as IsError=true on
// the tool result. Without this, MCP clients would see a successful
// pcap_explain_connection call with an embedded error, breaking
// orchestration that branches on result.IsError.
func TestExplainConnectionSelectorFailureSetsIsError(t *testing.T) {
	requireCommand(t, "tshark")

	root := t.TempDir()
	pcapDir := root + "/pcaps"
	if err := os.MkdirAll(pcapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pcap := pcapDir + "/http.pcap"
	if err := os.WriteFile(pcap, syntheticHTTPPcap(), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{pcapDir},
		Workspace:           config.WorkspaceConfig{OutputDir: root + "/output"},
		Analysis: config.AnalysisConfig{
			CommandTimeoutSeconds: 10,
			MaxStdoutBytes:        200000,
		},
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

	// frame_number 999 is past the end of the synthetic 1-frame pcap;
	// the resolver returns errFrameOutOfRange, which classify wraps as
	// the typed frame_number_out_of_range kind. The handler must
	// surface that as IsError=true (not a successful call with an
	// embedded error) and the typed kind must survive the MCP round
	// trip so hosts can switch on it without parsing the message.
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "pcap_explain_connection",
		Arguments: map[string]any{
			"path":         pcap,
			"frame_number": 999,
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		body, _ := json.Marshal(result.StructuredContent)
		t.Fatalf("expected IsError=true on selector failure; got false. structured=%s", string(body))
	}
	body, _ := json.Marshal(result.StructuredContent)
	var got explainOutput
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal structured content: %v (body=%s)", err, string(body))
	}
	if got.Error == nil {
		t.Fatalf("expected non-nil Error on selector failure; structured=%s", string(body))
	}
	if got.Error.Kind != ErrorKindFrameNumberOutOfRange {
		t.Fatalf("Error.Kind = %q, want %q (message=%q)", got.Error.Kind, ErrorKindFrameNumberOutOfRange, got.Error.Message)
	}
	if got.Error.Field != "frame_number" {
		t.Fatalf("Error.Field = %q, want %q", got.Error.Field, "frame_number")
	}

	// Persisted artifacts must NOT have been written for the failed
	// selector — the workspace is otherwise littered with empty
	// directories.
	matches, _ := os.ReadDir(root + "/output")
	if len(matches) != 0 {
		t.Fatalf("selector failure left artifacts under output_dir: %v", matches)
	}
}

// TestAnalyzeHardErrorResponsesCarrySchemaVersion pins that
// pcap_analyze (and analyze_pcap alias) hard-error responses include
// a populated schema_version. Hosts switch on schema_version before
// parsing; an empty value would look like an unversioned legacy
// response.
func TestAnalyzeHardErrorResponsesCarrySchemaVersion(t *testing.T) {
	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{t.TempDir()},
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

	// Use a path outside the allowlist. This passes the SDK-level
	// input-schema validation (path is non-empty) but trips
	// inspectArtifact's allowlist check, which is the earliest
	// hard-error return inside analyzeHandler. The earlier
	// missing-path case is intercepted by the SDK's required-fields
	// check and never reaches our handler — that path is owned by the
	// SDK and returns a TextContent error with no structured content.
	for _, name := range []string{"pcap_analyze", "analyze_pcap"} {
		t.Run(name, func(t *testing.T) {
			result, err := session.CallTool(ctx, &mcp.CallToolParams{
				Name:      name,
				Arguments: map[string]any{"path": "/var/empty/definitely-not-allowlisted.pcap"},
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if !result.IsError {
				t.Fatalf("expected IsError=true; got %v", result)
			}
			body, err := json.Marshal(result.StructuredContent)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			t.Logf("StructuredContent: %s", string(body))
			var got analyzeOutput
			if err := json.Unmarshal(body, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got.SchemaVersion != SchemaVersion {
				t.Fatalf("schema_version = %q, want %q", got.SchemaVersion, SchemaVersion)
			}
			if got.Error == nil {
				t.Fatalf("expected non-nil Error on hard failure")
			}
			if got.Error.Kind == "" {
				t.Fatalf("expected typed error.kind, got empty")
			}
		})
	}
}
