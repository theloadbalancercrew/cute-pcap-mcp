package pcap

// Per #4: tests for the read-only `get_server_info` MCP tool.
//
// Four load-bearing ratchets land here:
//
//   - TestGetServerInfoMatchesCliVersion verifies the tool reuses the
//     same `internal/buildinfo` source `--version` does. Both call
//     `buildinfo.Get()`; the test asserts the wire output's
//     build_version / commit / build_time / go_version match the
//     directly-read package values verbatim. A future MR that
//     duplicates buildinfo plumbing on the tool side fails this
//     test before it lands.
//
//   - TestGetServerInfoOutputHasRequiredFields reflects over the
//     output type and asserts the required fields (Name,
//     BuildVersion, Commit, BuildTime, GoVersion, MCPServerVersion,
//     SchemaVersion) are present with the documented json tags. The
//     issue's acceptance criterion explicitly enumerates these.
//
//   - TestGetServerInfoOutputCarriesNoBannedFields is the load-
//     bearing reflective structural-redaction ratchet: walks the
//     output type tree and rejects any field whose name or json tag
//     contains a banned secret/path/identity/artifact token. New
//     fields carrying paths, hostnames, usernames, env vars,
//     packet artifacts, or credentials fail the test before they
//     land.
//
//   - TestGetServerInfoToolRegisteredAndCallable round-trips an
//     empty-input call against the in-memory MCP transport and
//     asserts the handler returns valid output (no error, all
//     required fields populated, schema_version and
//     mcp_server_version match the package constants).

import (
	"context"
	"encoding/json"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"cute-pcap-mcp/internal/buildinfo"
	"cute-pcap-mcp/internal/config"
)

// TestGetServerInfoMatchesCliVersion asserts the build-info source
// the tool uses is identical to the source `--version` prints.
// Both call `buildinfo.Get()`; if a future MR routes one of them
// through a duplicate symbol surface, the version / commit /
// build_time / go_version they return will diverge and this test
// fires.
func TestGetServerInfoMatchesCliVersion(t *testing.T) {
	out := callGetServerInfo(t)

	want := buildinfo.Get()

	if out.BuildVersion != want.Version {
		t.Errorf("get_server_info.build_version = %q; buildinfo.Get().Version = %q (must be identical — same source as --version)", out.BuildVersion, want.Version)
	}
	if out.Commit != want.Commit {
		t.Errorf("get_server_info.commit = %q; buildinfo.Get().Commit = %q (must be identical — same source as --version)", out.Commit, want.Commit)
	}
	if out.BuildTime != want.BuildTime {
		t.Errorf("get_server_info.build_time = %q; buildinfo.Get().BuildTime = %q (must be identical — same source as --version)", out.BuildTime, want.BuildTime)
	}
	if out.GoVersion != want.GoVersion {
		t.Errorf("get_server_info.go_version = %q; buildinfo.Get().GoVersion = %q (must be identical — same source as --version)", out.GoVersion, want.GoVersion)
	}

	// Per #14: mcp_server_version is just the product version of
	// *this* server — same source as build_version. A future MR
	// that re-introduces a stale literal (e.g. hardcoded "0.1.0"),
	// or invents a separate "MCP generation" identifier on this
	// field, fails this assertion.
	if out.MCPServerVersion != want.Version {
		t.Errorf("get_server_info.mcp_server_version = %q; buildinfo.Get().Version = %q (must be identical — same source as build_version per #14)", out.MCPServerVersion, want.Version)
	}

	// Also pin the static identity fields so a future rename
	// fails this test.
	if out.Name != serverName {
		t.Errorf("get_server_info.name = %q; want %q (serverName constant)", out.Name, serverName)
	}
	if out.SchemaVersion != SchemaVersion {
		t.Errorf("get_server_info.schema_version = %q; want %q (pcap.SchemaVersion constant)", out.SchemaVersion, SchemaVersion)
	}
}

// TestGetServerInfoOutputHasRequiredFields is the field-presence
// ratchet (#4 acceptance criterion: tool includes
// name/build_version/commit/build_time/go_version/mcp_server_version/
// schema_version). Reflects over the output type so a future field
// rename fires this test.
func TestGetServerInfoOutputHasRequiredFields(t *testing.T) {
	required := map[string]string{
		"Name":             "name",
		"BuildVersion":     "build_version",
		"Commit":           "commit",
		"BuildTime":        "build_time",
		"GoVersion":        "go_version",
		"MCPServerVersion": "mcp_server_version",
		"SchemaVersion":    "schema_version",
	}

	typ := reflect.TypeOf(GetServerInfoOutput{})
	seenGo := map[string]string{}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		jsonTag := strings.SplitN(f.Tag.Get("json"), ",", 2)[0]
		seenGo[f.Name] = jsonTag
	}

	for goName, wantJSON := range required {
		gotJSON, ok := seenGo[goName]
		if !ok {
			t.Errorf("GetServerInfoOutput is missing required field %q (expected json:%q)", goName, wantJSON)
			continue
		}
		if gotJSON != wantJSON {
			t.Errorf("GetServerInfoOutput field %s json tag = %q; want %q", goName, gotJSON, wantJSON)
		}
	}
}

// TestGetServerInfoOutputCarriesNoBannedFields is the load-bearing
// reflective ratchet (per #4): NO field name or json tag on
// GetServerInfoOutput may contain any of the banned identity /
// path / credential / packet-artifact tokens. The whitelist below
// pins the explicit safe field names; any new field is rejected
// unless it joins the whitelist intentionally.
//
// A new field carrying a config file path, capture filename,
// output directory, hostname, username, env var value, sha256, or
// raw artifact reference fails the test before it lands.
func TestGetServerInfoOutputCarriesNoBannedFields(t *testing.T) {
	bannedTokens := []string{
		"path",
		"dir",
		"file",
		"host",
		"address",
		"username",
		"password",
		"secret",
		"token",
		"pem",
		"key",
		"passphrase",
		"env",
		"pcap_filename",
		"sha256",
		"artifact",
		"device",
	}
	// Whitelist: explicit safe field names that are bounded
	// closed-vocabulary metadata. Any new whitelist entry MUST be
	// a typed scalar carrying redaction-safe identity / version
	// metadata; the issue's hard rule forbids carrying paths,
	// filenames, hostnames, usernames, env values, secrets, or
	// packet artifacts here.
	whitelistedFieldNames := map[string]bool{
		"Name":                    true, // product identity, always "cute-pcap-mcp"
		"BuildVersion":            true, // link-time release version from buildinfo
		"Commit":                  true, // VCS revision from buildinfo
		"BuildTime":               true, // link-time timestamp from buildinfo
		"GoVersion":               true, // Go toolchain version from runtime.Version()
		"MCPServerVersion":        true, // this server's product version (same as build_version per #14)
		"SchemaVersion":           true, // PCAP analysis output schema version
		"ConfigSource":            true, // closed enum: file | env | default; never a path
		"AnalyzerStatusAvailable": true, // bool; in-process registration check, no probe
	}

	typ := reflect.TypeOf(GetServerInfoOutput{})
	assertNoServerInfoBannedFields(t, typ, bannedTokens, whitelistedFieldNames)
}

// assertNoServerInfoBannedFields walks typ recursively and fails
// if any field's Go name or json tag contains a banned token,
// unless the field appears in the whitelist. Also rejects []byte
// anywhere in the type tree so a future "raw bytes" field fails
// the same ratchet.
func assertNoServerInfoBannedFields(t *testing.T, typ reflect.Type, banned []string, whitelist map[string]bool) {
	t.Helper()
	switch typ.Kind() {
	case reflect.Ptr, reflect.Slice, reflect.Array, reflect.Chan:
		if typ.Kind() == reflect.Slice && typ.Elem().Kind() == reflect.Uint8 {
			t.Fatalf("wire type %s contains []byte slot — no get_server_info wire-output type may carry raw bytes", typ.String())
		}
		assertNoServerInfoBannedFields(t, typ.Elem(), banned, whitelist)
		return
	case reflect.Map:
		assertNoServerInfoBannedFields(t, typ.Elem(), banned, whitelist)
		return
	case reflect.Struct:
		// fall through
	default:
		return
	}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		nameLower := strings.ToLower(f.Name)
		jsonTag := strings.ToLower(strings.SplitN(f.Tag.Get("json"), ",", 2)[0])
		if f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() == reflect.Uint8 {
			t.Fatalf("wire type %s.%s is []byte — no get_server_info wire-output type may carry raw bytes", typ.Name(), f.Name)
		}
		if whitelist[f.Name] {
			// Whitelist still recurses into the field type so a
			// nested struct with a banned field doesn't sneak in.
			if f.Type.Kind() == reflect.Struct && f.Type.PkgPath() == typ.PkgPath() {
				assertNoServerInfoBannedFields(t, f.Type, banned, whitelist)
			}
			continue
		}
		for _, token := range banned {
			if strings.Contains(nameLower, token) || strings.Contains(jsonTag, token) {
				t.Fatalf("wire type %s.%s field name=%q json=%q contains banned token %q; the get_server_info surface MUST NOT carry paths, filenames, hostnames, usernames, env values, secrets, or packet artifacts",
					typ.Name(), f.Name, f.Name, jsonTag, token)
			}
		}
		if f.Type.Kind() == reflect.Struct && f.Type.PkgPath() == typ.PkgPath() {
			assertNoServerInfoBannedFields(t, f.Type, banned, whitelist)
		}
	}
}

// TestGetServerInfoToolRegisteredAndCallable asserts the tool is
// registered and round-trips a real MCP call with empty input. The
// handler must return non-error structured output with the required
// fields populated. This is the issue's "registered and callable
// with empty input" acceptance criterion.
func TestGetServerInfoToolRegisteredAndCallable(t *testing.T) {
	out := callGetServerInfo(t)

	if out.Name == "" {
		t.Errorf("get_server_info returned empty Name; expected the product identity constant")
	}
	if out.BuildVersion == "" {
		t.Errorf("get_server_info returned empty BuildVersion; expected at least the buildinfo sentinel")
	}
	if out.Commit == "" {
		t.Errorf("get_server_info returned empty Commit; expected at least the buildinfo sentinel")
	}
	if out.BuildTime == "" {
		t.Errorf("get_server_info returned empty BuildTime; expected at least the buildinfo sentinel")
	}
	if out.GoVersion == "" {
		t.Errorf("get_server_info returned empty GoVersion; runtime.Version() never returns empty")
	}
	if out.MCPServerVersion == "" {
		t.Errorf("get_server_info returned empty MCPServerVersion; expected at least the buildinfo sentinel (same source as build_version per #14)")
	}
	if out.SchemaVersion == "" {
		t.Errorf("get_server_info returned empty SchemaVersion; expected the pcap.SchemaVersion constant")
	}
}

// callGetServerInfo invokes the registered get_server_info tool
// against an in-memory MCP session and unmarshals the structured
// output. Mirrors the server-construction pattern in
// error_response_test.go.
func callGetServerInfo(t *testing.T) GetServerInfoOutput {
	t.Helper()

	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{t.TempDir()},
	})
	if err != nil {
		t.Fatalf("config.Normalize: %v", err)
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

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_server_info",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("session.CallTool(get_server_info): %v", err)
	}
	if res.IsError {
		t.Fatalf("get_server_info returned IsError=true: %+v", res.Content)
	}

	if res.StructuredContent == nil {
		t.Fatalf("get_server_info returned no structured content")
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("json.Marshal structured content: %v", err)
	}
	var out GetServerInfoOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("json.Unmarshal into GetServerInfoOutput: %v (raw=%s)", err, string(raw))
	}
	return out
}
