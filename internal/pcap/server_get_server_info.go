package pcap

// Per #4: read-only `get_server_info` MCP tool exposing
// build/runtime metadata to MCP hosts so an operator can answer
// "what version of this MCP server am I connected to?" from the
// tool surface itself.
//
// Pure in-process: NO analyzer call, NO file read, NO subprocess.
// The handler reads the same `internal/buildinfo` package symbols
// the `--version` flag prints, plus the PCAP analysis-contract
// `SchemaVersion`. Per #14, `mcp_server_version` carries the same
// product version as `build_version` — both come from
// `buildinfo.Get().Version`, the same value the MCP handshake's
// `serverInfo.version` advertises during initialize. There is no
// invented "MCP generation" or protocol-identifier semantic on
// this field; it just answers "what version of this specific
// server am I connected to?" `get_server_info` is the richer
// support/debug surface around the same identity.
//
// Hard rules (#4):
//
//   - NO secrets, paths, capture filenames, output directories,
//     hostnames, usernames, env values, or packet artifacts are
//     returned. The reflective ratchet
//     `TestGetServerInfoOutputCarriesNoBannedFields` pins this by
//     walking GetServerInfoOutput's field names and json tags and
//     rejecting any token in the banned-substring list.
//   - NO duplicated buildinfo plumbing. The handler reuses
//     `buildinfo.Get()` — the same call `--version` makes — so
//     a future buildinfo refactor only needs to touch one symbol
//     surface.
//   - NO analyzer dispatch. `pcap_analyzer_status` remains the
//     authoritative analyzer-version tool. This handler does not
//     run `tshark --version`, `capinfos -v`, or `zeek --version`.
//     The optional AnalyzerStatusAvailable field is a static
//     in-process boolean — it reflects "is pcap_analyzer_status
//     registered on this server" — not a runtime probe of any
//     external analyzer.

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"cute-pcap-mcp/internal/buildinfo"
)

// getServerInfoDescription is the schema text the MCP host renders
// when listing tools. It MUST mention the closed-vocabulary output
// fields so a client / model can decide whether the tool answers
// the question without first calling it.
const getServerInfoDescription = "Get this PCAP MCP server's build and runtime metadata. Read-only; no analyzer call; no file read; available in every server profile. Output fields: name (product identity, always cute-pcap-mcp), build_version, commit, build_time, go_version (build/runtime metadata sourced from the same internal/buildinfo symbols the --version CLI flag prints), mcp_server_version (this server's product version, identical to build_version; the MCP handshake serverInfo.version advertises the same value), schema_version (PCAP analysis output schema version), config_source (closed enum: file | env | default; never a path), analyzer_status_available (true when pcap_analyzer_status is registered on this server; does NOT probe tshark/capinfos/zeek — pcap_analyzer_status remains the authoritative analyzer-version tool)."

// getServerInfoInput is the empty input shape for the tool. The
// MCP host calls `get_server_info` with no arguments.
type getServerInfoInput struct{}

// GetServerInfoOutput is the typed wire payload the tool returns.
// Every field is bounded, redaction-safe metadata. NEVER add a
// field whose name (or json tag) contains any of the banned
// substrings the reflective ratchet rejects (`path`, `dir`,
// `file`, `host`, `address`, `username`, `password`, `secret`,
// `token`, `pem`, `key`, `passphrase`, `env`, `pcap_filename`,
// `sha256`, `artifact`, `device`).
type GetServerInfoOutput struct {
	// Name is the product identity. Always "cute-pcap-mcp".
	Name string `json:"name" jsonschema:"product / server identity, always cute-pcap-mcp"`
	// BuildVersion is the link-time release version sourced from
	// `internal/buildinfo`. Falls back to the sentinel "unknown"
	// when the linker did not inject it.
	BuildVersion string `json:"build_version" jsonschema:"link-time release version from internal/buildinfo"`
	// Commit is the VCS revision sourced from `internal/buildinfo`.
	Commit string `json:"commit" jsonschema:"VCS revision from internal/buildinfo"`
	// BuildTime is the link-time build timestamp sourced from
	// `internal/buildinfo`.
	BuildTime string `json:"build_time" jsonschema:"link-time build timestamp from internal/buildinfo"`
	// GoVersion is the Go toolchain version that compiled the
	// binary. Sourced from `internal/buildinfo` via runtime.Version().
	GoVersion string `json:"go_version" jsonschema:"Go toolchain version from runtime.Version()"`
	// MCPServerVersion is this server's product version — identical
	// to BuildVersion. Both are sourced from `buildinfo.Get().Version`,
	// the same value the MCP handshake's `serverInfo.version`
	// advertises during initialize. Per #14 this field carries no
	// "MCP generation" or protocol-identifier semantic; it just
	// answers "what version of this specific server am I connected
	// to?" If a future need arises to version a separate concept
	// (e.g. a shared cute-family file/spec contract), it gets its
	// own field — we do not overload this one.
	MCPServerVersion string `json:"mcp_server_version" jsonschema:"this server's product version (identical to build_version); also the value advertised in the MCP handshake serverInfo.version"`
	// SchemaVersion is the current PCAP analysis output schema
	// version (the same value `pcap_analyze` /
	// `pcap_explain_connection` stamp on every response and on
	// every persisted OutputArtifact). Hosts can pair the server
	// build version with the analysis-contract version.
	SchemaVersion string `json:"schema_version" jsonschema:"PCAP analysis output schema version (pcap.SchemaVersion)"`
	// ConfigSource is the closed-enum token describing where the
	// server resolved its config from. Today the binary requires
	// -c/--config and there is no env / default fallback, so this
	// is always "file"; the field exists so a future env-var or
	// default-config fallback can surface its source without
	// changing the wire shape. NEVER a file path.
	ConfigSource string `json:"config_source" jsonschema:"closed enum describing where config was resolved from: file | env | default. Never a path."`
	// AnalyzerStatusAvailable is true when the pcap_analyzer_status
	// tool is registered on this server (the in-process check —
	// not a runtime probe of tshark / capinfos / zeek). False would
	// signal a future build that disables the analyzer-status tool;
	// today this is always true. Hosts MUST call
	// pcap_analyzer_status itself for actual analyzer availability
	// and version strings — that tool remains authoritative.
	AnalyzerStatusAvailable bool `json:"analyzer_status_available" jsonschema:"true when pcap_analyzer_status is registered on this server; does NOT probe analyzers — pcap_analyzer_status remains the authoritative analyzer-version tool"`
}

// registerGetServerInfoTool wires the read-only `get_server_info`
// tool. The closure captures only static identity values — no
// config, no logger, no semaphore — so the handler is pure: it
// returns the same payload on every call without touching any
// mutable state.
//
// Tool placement: registered at top-level registerTools (alongside
// pcap_analyzer_status) so the tool is exposed in every server
// invocation. Diagnostic metadata is risk-free; gating it would
// regress the tool's "answer the version question from any MCP
// host" purpose.
//
// Capture-time values:
//
//   - analyzerStatusAvailable is captured at registration time.
//     Today the parent registerTools always also registers the
//     pcap_analyzer_status tool, so this is always true; the
//     parameter exists so a future build that disables the
//     analyzer-status tool can flip the bit without changing
//     this function's signature.
func registerGetServerInfoTool(server *mcp.Server, analyzerStatusAvailable bool) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_server_info",
		Description: getServerInfoDescription,
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ getServerInfoInput) (*mcp.CallToolResult, GetServerInfoOutput, error) {
		// Reuse the same buildinfo source `--version` prints.
		// `Get()` is idempotent, allocates a small struct, and
		// makes no syscalls beyond reading runtime.Version() —
		// safe to call on every tool invocation.
		info := buildinfo.Get()

		out := GetServerInfoOutput{
			Name:                    serverName,
			BuildVersion:            info.Version,
			Commit:                  info.Commit,
			BuildTime:               info.BuildTime,
			GoVersion:               info.GoVersion,
			MCPServerVersion:        info.Version,
			SchemaVersion:           SchemaVersion,
			ConfigSource:            "file",
			AnalyzerStatusAvailable: analyzerStatusAvailable,
		}
		return nil, out, nil
	})
}
