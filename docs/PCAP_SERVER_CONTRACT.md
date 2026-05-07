# PCAP Server Contract

This document is the wire-shape and error-taxonomy contract for the
`cute-pcap-mcp` MCP server. Per-tool inputs/outputs/error sets are in
[`TOOL_REFERENCE.md`](./TOOL_REFERENCE.md). This doc covers the
cross-tool patterns that orchestration code (Claude Code, Codex, MCP
hosts) is allowed to switch on.

The contract keeps `cute-pcap-mcp` packet-capture first while allowing
composition with `cute-bigip-mcp` and other artifact producers:

- typed error tokens beat prose parsing
- unknown stays unknown
- bounded inputs reject unsafe values instead of silently widening
- private artifacts are references, not prompt content
- partial results stay distinguishable from full success and from
  total failure

## Transport

The server speaks MCP over **stdio only**. There is no HTTP listener,
no metrics endpoint, no web UI. Operators run the binary directly or
inside the Docker image; the MCP host is the user-facing surface.

Structured logs are written to **stderr in JSON-text format**. Tool
inputs and outputs are not logged at info level. See the
implementation in [`server.go`](../internal/pcap/server.go).

## Workspace and resource controls

The server takes pcap inputs from operator-configured workspace roots
and treats every external analyzer call as a bounded operation:

- **Inputs** must resolve under `allowed_artifact_dirs` or
  `workspace.pcap_dir`. The configured `pcap_dir` is implicitly added
  to the input allowlist. All paths are symlink-resolved before the
  allowlist check; symlink escape is rejected.
- **`workspace.root` is a containment boundary, not just a default
  source.** When set, `pcap_dir`, `output_dir`, and `tmp_dir` must
  all resolve strictly under root. A config that sets
  `workspace.root: /work` and `workspace.tmp_dir: /tmp` is rejected
  at config-load time. Operators who legitimately need subdirs in
  unrelated locations should leave root empty and configure each
  subdir explicitly.
- **Outputs** may only be written under `workspace.output_dir`. The
  `pcap_analyze` tool emits `analysis.json` and `summary.md` under
  `${output_dir}/<sha256_prefix>-<utc_timestamp>[-<n>]/` and returns
  `OutputArtifact` references in the response. The output path is
  always server-generated; callers cannot pick a destination. Same-
  second re-runs of the same pcap get an incrementing `-<n>` suffix
  via a `Mkdir` collision-retry loop so re-runs never overwrite the
  prior evidence diff.
- **Output disk budget**: the rendered `analysis.json` + `summary.md`
  total size is checked against `analysis.output_disk_budget_bytes`
  before any bytes are written. Over-budget calls return the typed
  `output_limit_reached` error in `errors[]` and skip the write.
  The in-memory MCP response is still returned with full evidence.
- **Temp work** for Zeek (and any future temp-bearing analyzer) lands
  under `workspace.tmp_dir`. After each run the per-call temp size is
  measured against `analysis.tmp_disk_budget_bytes`; over-budget
  Zeek runs return `tmp_budget_exceeded`.
- **PCAP size budget**: a file strictly larger than
  `analysis.max_pcap_bytes` is rejected with `pcap_too_large` before
  any external analyzer runs.
- **Concurrency budget**: `analysis.max_concurrent_analyses` slots
  back the analyzer-bearing tools (`analyze_pcap`, `summarize_pcap`).
  A non-blocking acquire is used; saturated callers get the typed
  `analysis_busy` error rather than queueing, so the saturated state
  is observable to the host.

## Server identity

Two surfaces report this server's identity to MCP hosts:

- The **MCP handshake** carries the static implementation identity in
  `serverInfo` — `name = cute-pcap-mcp` and a stable `version`
  constant (`mcp_server_version`). This is the wire-protocol
  identity, not the release artifact's injected version.
- The **`get_server_info`** tool ([TOOL_REFERENCE.md](./TOOL_REFERENCE.md#get_server_info))
  is the richer support/debug surface. It returns the link-time
  `build_version`, `commit`, `build_time`, and `go_version` from
  `internal/buildinfo` (the same source the CLI `--version` flag
  reads, so the two surfaces cannot drift), plus `schema_version`
  (the analysis-output schema below) and a `config_source` closed
  enum. The handler is pure in-process: no analyzer dispatch, no
  file read.

`get_server_info` does NOT report analyzer (`tshark`, `capinfos`,
`zeek`) availability or version strings. That is the
[`pcap_analyzer_status`](./TOOL_REFERENCE.md#pcap_analyzer_status)
tool's job; it remains the authoritative analyzer-version answer.

## Schema versioning

`pcap_analyze` (and its `analyze_pcap` alias) stamp the response with
a `schema_version` field. The current value is **`1.1.0`**, defined
as `SchemaVersion` in [`output.go`](../internal/pcap/output.go).

- **Patch** bumps (`x.y.z`) are bug fixes that do not change the wire
  shape.
- **Minor** bumps (`1.x.0`) are additive: new optional fields, new
  finding codes, new error kinds, or new status tokens. Hosts are
  expected to ignore unknown optional fields and handle unknown token
  values conservatively.
- **Major** bumps (`x.0.0`) are reserved for breaking changes
  (removed fields, renamed tokens, retyped values). They will land
  with a roadmap entry and a deprecation window.

The same `schema_version` value is also stamped into every
`OutputArtifact` (so persisted JSON / Markdown carries its own
version), and into the JSON body of `analysis.json` itself, so a
host reading a saved artifact can verify compatibility before
parsing.

## `pcap_analyze` top-level sections

The `pcap_analyze` response uses these stable top-level keys, in
this order. Sections are nil/absent when the operator opted out via
the `include_*` flags or when the source capture had no matching
evidence.

| Key | Type | Description |
| --- | --- | --- |
| `schema_version` | string | This contract's wire version. |
| `artifact` | object | The input pcap reference (path, size, sha256). |
| `capture_summary` | object | Parsed capinfos metadata + raw text. |
| `protocols` | object | tshark `-z io,phs` protocol hierarchy table. |
| `conversations` | map | tshark `-z conv,*` per-protocol tables. |
| `packets` | array | Bounded tshark packet rows. |
| `dns` | array | Zeek DNS query summaries. |
| `http` | array | Zeek HTTP request summaries (URI redacted). |
| `tls` | array | Zeek SSL/TLS handshake summaries. |
| `tcp_health` | object | Reset-bearing connections + reset-side counts. |
| `notices` | array | Zeek notice records. |
| `weird_events` | array | Zeek weird-event records. |
| `zeek_logs` | array | Raw bounded Zeek log bodies. |
| `ascii` | object | Bounded printable-ASCII extraction. |
| `tls_decryption` | object | Always-present typed status for SSLKEYLOGFILE handling. |
| `profile` | object | Optional `analysis_profile` result (today: `f5_ltm_tls_debug`). |
| `findings` | array | Stable finding codes (analysis itself, not packet content). |
| `artifacts` | array | `OutputArtifact` references for written JSON/Markdown. |
| `errors` | array | Per-section partial-failure errors. |
| `metadata` | map | Privacy and bounding notes. |

## External artifact references

`cute-pcap-mcp` does not capture traffic, copy files from devices, or
call other MCP servers. External producers (humans, scripts, CI
pipelines, companion MCP servers, anything with filesystem access)
write pcap files into the configured `workspace.pcap_dir` and pass
**references** to those files into the MCP host. The host calls the
PCAP MCP tools with the relevant fields from the reference.

The recommended exchange shape between an external producer and the
MCP host is the **ArtifactReference** object:

```json
{
  "artifact_id": "opaque-correlation-id",
  "pcap_path": "/work/pcaps/capture.pcap",
  "sha256": "<hex>",
  "size_bytes": 12345,
  "source": {
    "kind": "free-form producer label",
    "context": { "producer-specific": "free-form" }
  }
}
```

| Field | Required | Used by the server |
| --- | --- | --- |
| `artifact_id` | no | Producer-supplied correlation token. Opaque to the server. |
| `pcap_path` | yes | Mapped to the `path` input on every PCAP tool. |
| `sha256` | no | Mapped to `expected_sha256`. The server computes the actual hash and emits `hash_mismatch` on disagreement. |
| `size_bytes` | no | Mapped to `expected_size_bytes`. Cheap pre-check before the hash read; emits `size_mismatch` on disagreement. |
| `source` | no | Producer-specific context. Opaque to the server; the host may log or surface it however it likes. |

The PCAP MCP server only consumes `pcap_path`, `sha256`, and
`size_bytes` from this shape — and only `pcap_path` is required.
Producers that cannot compute the hash or size omit those fields and
the server reports its own values back. **Producers MUST NOT
embed the file's bytes** in the reference; pcap bytes never enter
MCP input.

### What this server explicitly does NOT do

- No capture acquisition (`tcpdump`, appliance packet capture, port
  mirrors).
- No remote file copy (SSH, SCP, SFTP, HTTP transfer).
- No device API clients (vendor REST, vendor SSH, control-plane APIs).
- No MCP-to-MCP calls; this server is invoked by an MCP host only.

These boundaries are enforced by absence: the binary contains no
network client code beyond stdio MCP, and tool inputs only accept
local filesystem paths.

### Tools that accept artifact-reference fields

Every tool that takes `path` also accepts the optional
`expected_sha256` and `expected_size_bytes` inputs:

- `pcap_validate` / `inspect_pcap`
- `pcap_analyze` / `analyze_pcap`
- `pcap_diagnose_symptoms`
- `pcap_filter`
- `pcap_explain_connection`
- `summarize_pcap` (legacy)

Validation order is:

1. **Format check on the expectations themselves** —
   `expected_sha256` must be exactly 64 hex digits if set;
   `expected_size_bytes` must be non-negative if set. Bad inputs
   return `validation_failed` with `field` + `reason` tokens, not
   `hash_mismatch` / `size_mismatch` (which would misclassify the
   actual mistake).
2. Path → allowlist check (`path_outside_allowlist`).
3. Stat → file presence + regular-file check (`artifact_not_found`,
   `artifact_not_regular_file`).
4. Size budget (`pcap_too_large`).
5. `expected_size_bytes` match (`size_mismatch`).
6. SHA-256 read.
7. `expected_sha256` match, case-insensitive (`hash_mismatch`).

Each check fires before the next, so a host that only knows the size
still gets a fast typed error without paying for the hash read. The
`hash_mismatch` message echoes only the actual computed hash; the
caller-provided `expected_sha256` is never reflected back into the
response (an untrusted value should not bloat MCP output even if it
technically passed format validation).

## Analysis profiles

`pcap_analyze` and `pcap_explain_connection` accept an optional
`analysis_profile` input that layers extra analysis on top of the
generic evidence. Profiles **never replace or suppress** the generic
sections — they are additive. Selecting a profile that is not
registered emits the typed `analysis_profile_unknown` finding and
returns the full generic evidence; the profile section stays absent.

### Profile result shape

```json
{
  "profile": {
    "name": "<stable-profile-name>",
    "limitations": ["<always-present human strings>"],
    "<profile-name>": { /* per-profile structured evidence */ }
  }
}
```

- `name` — stable token. Switch on this. Never rename, only add.
- `limitations` — the always-present human-readable list of what
  the profile *cannot* prove from packets alone. Hosts treat these
  as fixed warnings. The list only grows.
- `<profile-name>` — discriminated nested object containing the
  per-profile structured evidence. Future profiles add their own
  named field; the wire shape is additive.

### Registered profiles

| Name | Status | Description |
| --- | --- | --- |
| `f5_ltm_tls_debug` | yes | Restates resets (with side classification), TLS handshakes (SNI / version / cipher), HTTP status-class buckets, and SNAT/clientside/serverside hints derived from optional `f5_context`. Clientside classification requires `f5_context.virtual_server_ip`; without it the profile reports the unknown rather than guessing sides. |

### Load-balancer context (`f5_context`)

The optional `f5_context` input is operator-supplied load-balancer
context.
The server **never** uses these fields to call other systems —
`f5_context` only classifies packet evidence (e.g. "this connection's
destination matches the configured VIP"). Field bounds:

- `virtual_server_ip`: parsed via `net/netip` and rejected on bad
  input. **Required** for the clientside classification — a bare
  port is not a VIP.
- `virtual_server_port`: must be in `[0, 65535]`. Optional
  narrowing field on top of `virtual_server_ip`.
- `virtual_server_name`, `pool_name`, `snat_pool_name`: free-form
  strings, capped at 256 bytes; NUL bytes rejected. Accepted
  values are echoed back unchanged.
- `notes`: free-form string, capped at 4096 bytes; NUL bytes
  rejected. Accepted value echoed back unchanged.

`validation_failed` from `f5_context` carries one of the field
tokens above, with `reason` ∈ {`invalid_format`, `out_of_range`,
`too_long`, `contains_nul`}.

SNAT-hint discriminators on the wire:

- `clientside_classification_skipped_no_context` — `f5_context` was
  absent or every field was empty.
- `clientside_classification_skipped_no_vip_ip` — `f5_context` had
  some field set but `virtual_server_ip` was not supplied.
- `clientside_to_vip_observed` — at least one connection's
  destination matched the configured VIP.
- `non_vip_destinations_observed` — at least one connection's
  destination did not match the configured VIP.

The profile **never** infers load-balancer or device configuration
from packets alone. Every claim that requires config (which VIP is
which, which pool a connection goes to, whether SNAT is enabled, what
TLS profile is bound) requires explicit `f5_context` from the caller.
The profile's limitations list spells this out exhaustively.

## TLS decryption status

`pcap_analyze` (and `pcap_explain_connection`) always stamp the
response with a `tls_decryption` section so a host can branch on the
typed status without parsing analyzer prose. The shape:

```json
{
  "tls_decryption": {
    "status": "<stable token>",
    "keylog_path": "/work/keylog/keys.log",
    "detail": "<bounded human fallback>",
    "limitations": ["..."]
  }
}
```

### Status tokens

| Status | When |
| --- | --- |
| `not_requested` | Caller did not pass `tls_keylog_path`. No `keylog_path` / `limitations` are stamped. Also returned on hard-error responses (validation / path / busy) so the field is always present on the wire. |
| `unavailable` | Keylog support is not configured on the server (`workspace.keylog_dir` empty), or the supplied path resolved outside that directory. The keylog is not handed to the analyzers. |
| `keylog_missing` | The supplied path resolves under `workspace.keylog_dir` but no file exists there. |
| `keylog_invalid` | The supplied file exists under `workspace.keylog_dir` but contains no recognized SSLKEYLOGFILE secret lines (blank/comment-only, malformed, unsupported label, or non-hex material). The keylog is not handed to the analyzers. |
| `attempted` | The keylog was validated, then applied to tshark (`-o tls.keylog_file:`) and Zeek (`SSLKEYLOGFILE` env), and the analyzers ran without subprocess errors. **This does not prove any session was decrypted.** TLS handshake summaries appear in Zeek output regardless of whether a keylog matched, so the analyze pipeline cannot promote on that signal alone. The limitations list documents this honestly. |
| `failed` | The keylog was applied but a keylog-consuming analyzer (tshark or Zeek) returned a subprocess error. Errors from analyzers that did not consume the keylog (capinfos, ASCII extraction) do not flip the status. The per-analyzer kind is in `errors[]`. |
| `succeeded` | **Reserved on the wire; not emitted today.** A future implementation that has a reliable decrypted-evidence signal (e.g. http records that came from inside TLS streams) will promote `attempted` → `succeeded`. The token lives in the constant set so a future emission lands without a wire-shape change. Hosts may pre-allocate orchestration for it but should not branch as if it can be returned today. |

### Path validation

- `tls_keylog_path` is symlink-resolved before the prefix check
  (symlink escape is rejected — a link under `keylog_dir` pointing
  outside returns `unavailable`).
- The keylog file must be a regular file under
  `workspace.keylog_dir`.
- The server reads the keylog only to validate SSLKEYLOGFILE line
  shape (recognized label plus hex key material). It returns counts
  and status only; it never returns, logs, stores, copies, or persists
  key material.
- Validated keylogs are handed to tshark via `-o` and to Zeek via
  `SSLKEYLOGFILE` set on the subprocess env (not the parent process).

### What this surface does NOT do

- Decrypted HTTP bodies, payload bytes, headers, cookies, and
  authorization values are **never** returned in tool output, even
  when decryption succeeds. Zeek's `http.log` summaries (with the
  unconditional URI redaction documented in the privacy invariants)
  remain the only HTTP evidence the response carries.
- The server never copies, ships, returns, or remotely reads keylog
  files. Operators place the file under `workspace.keylog_dir`
  themselves.
- TLS payload decryption is generally not possible from a pcap
  alone. The `limitations` list exhaustively documents why
  (forward-secret key exchange, missing server keys, partial
  captures); hosts should always surface that list to the LLM.

## Output artifacts

Tools that write derived files to `workspace.output_dir` return one
or more `OutputArtifact` entries:

```json
{
  "path": "/work/output/abc123def456-20260429T154301Z/analysis.json",
  "size_bytes": 12345,
  "sha256": "<hex-of-file-bytes>",
  "content_type": "application/json",
  "schema_version": "1.1.0",
  "generated_at": "2026-04-29T15:43:01Z",
  "kind": "analysis_json"
}
```

Stable `kind` tokens:

- `analysis_json` — the `pcap_analyze` response re-serialized to
  disk. The `artifacts` list is **cleared** in this serialization
  (a self-referential record can't predict its own size + sha256
  before the file is written). Hosts that want the
  `OutputArtifact` references read them from the in-memory MCP
  response, not from the persisted JSON.
- `summary_markdown` — human-readable capture summary.
- `filtered_pcap` — derived pcap from `pcap_filter`.

Hosts switch on `kind`, never on file extension or path. The path is
informational only; the same artifact can be re-read by SHA-256
verification against `sha256` (the file-content hash, not the input
pcap hash — the latter lives in `artifact.sha256`).

## Tool result shapes

Every tool returns a tool-specific result object. Two cross-cutting
fields are stable across tools:

- `error` (optional, top-level) — a typed `toolError`. Present iff
  `IsError` is set on the MCP `CallToolResult`. The whole call has
  failed; partial evidence is not in this object.
- `errors` (optional, per-section) — list of typed `toolError`
  entries. Present when the call succeeded overall but a sub-analyzer
  was unavailable, failed, or timed out. Used by `analyze_pcap` to
  return partial results without losing the failure signal.

A tool result with `error` set is a hard failure. A tool result with
`errors[]` populated is a partial success — the present sections are
truthful evidence and the missing/failed sections are documented in
`errors[]`.

## `toolError` shape

```json
{
  "kind": "<stable-error-kind>",
  "message": "<human fallback string>",
  "retryable": false,
  "remediation": "<optional human hint>",
  "field": "<optional offending input field>",
  "reason": "<optional stable per-field reason token>"
}
```

- `kind` is the stable token. Switch on this. **Never** parse
  `message`.
- `retryable` is a hint for orchestration. Today it is set on
  `analyzer_timeout` and `analysis_busy`. Other kinds default to
  `false`.
- `remediation` is human fallback text suggesting what the operator
  should change. Optional.
- `field` identifies the offending input field. It is populated by
  every kind whose semantics are tied to a specific input: today
  that is `validation_failed`, `invalid_filter` (`display_filter`),
  `hash_mismatch` (`expected_sha256`), `size_mismatch`
  (`expected_size_bytes`), and `no_packets_matched` (`display_filter`).
- `reason` is the stable per-field token explaining **why** a
  validation rejected the input. It is populated only by
  `validation_failed` (one of the `ValidationReason*` tokens listed
  below). Other kinds leave `reason` empty even when `field` is set,
  because the per-kind name itself already carries the "why" — a
  `hash_mismatch` is a hash mismatch; there is no sub-reason.

## Error kinds

The full set is defined in [`errors.go`](../internal/pcap/errors.go)
as `ErrorKind*` constants. Kinds without an active emission site today
are reserved here so future releases can land them without a wire
change.

| Kind | Emitted today | Description |
| --- | --- | --- |
| `invalid_request` | yes | Catch-all for malformed input that does not match a more specific kind. Prefer a typed kind. |
| `missing_field` | yes | A required input field was empty or absent. |
| `validation_failed` | yes | A per-field input value is the wrong shape. Carries `field` + `reason`. |
| `invalid_filter` | yes | A `display_filter` value was rejected by validation or by tshark. |
| `path_outside_allowlist` | yes | Resolved (real) pcap path is outside every configured `allowed_artifact_dirs` entry, including via symlink. |
| `artifact_not_regular_file` | yes | The path resolves to a directory, device, fifo, or other non-regular file. |
| `artifact_not_found` | yes | The resolved path does not exist. |
| `analyzer_unavailable` | yes | An external analyzer (`capinfos`, `tshark`, `zeek`) is not on PATH. |
| `analyzer_failed` | yes | An external analyzer ran but exited non-zero. |
| `analyzer_timeout` | yes | An external analyzer hit `analysis.command_timeout_seconds`. Retryable. |
| `pcap_too_large` | yes | Capture exceeds `analysis.max_pcap_bytes`. Rejected before any external analyzer runs. |
| `tmp_budget_exceeded` | yes | A Zeek (or other temp-bearing) run wrote more than `analysis.tmp_disk_budget_bytes` to the workspace tmp dir. |
| `analysis_busy` | yes | The configured concurrent-analyzer cap is saturated. Retryable. |
| `output_limit_reached` | yes | The rendered `analysis.json` + `summary.md` would exceed `analysis.output_disk_budget_bytes`. The artifacts are not written; the in-memory analyze response is still returned. |
| `no_packets_matched` | yes | A `pcap_filter` display filter matched zero packets. The empty derived pcap is removed before the error returns. Distinct from `empty_capture`. |
| `hash_mismatch` | yes | Caller-provided `expected_sha256` disagrees with the on-disk artifact. Carries `field: expected_sha256`. |
| `size_mismatch` | yes | Caller-provided `expected_size_bytes` disagrees with the on-disk artifact. Carries `field: expected_size_bytes`. The size check fires before the hash read, so callers that supply size only still get a fast typed error. |
| `frame_number_out_of_range` | yes | Emitted by `pcap_explain_connection` when the `frame_number` selector points past the last frame in the capture. Carries `field: frame_number`; the message names the valid range when capinfos was available. |
| `frame_not_on_stream` | yes | Emitted by `pcap_explain_connection` when the `frame_number` selector resolves to a real frame that is not on a tcp/udp stream the explainer can scope to (e.g., ARP, ICMP-only, FILEINFO records). Carries `field: frame_number`; the message names the frame's protocol so the operator understands. Distinct from `frame_number_out_of_range`. |
| `empty_capture` | reserved (future) | Capture is structurally valid but contains zero packets. Will be emitted from `pcap_analyze` once the capinfos pass surfaces zero-packet captures distinctly. |

## Validation reason tokens

`validation_failed` errors set `reason` to one of:

| Reason | Meaning |
| --- | --- |
| `empty` | The field was present but empty when a value was required. |
| `invalid_format` | The value did not parse against the expected format. |
| `out_of_range` | A numeric value was outside the allowed range. |
| `contains_nul` | A string value contained a NUL byte. |
| `too_long` | A string value exceeded its maximum length. |

## Finding codes

Tool outputs include `findings[]` of `{code, severity, message}`.
Findings are informational/warning signals about the analysis
itself. They are never used to claim packet-content facts the
analyzers did not produce.

| Code | Severity | Meaning |
| --- | --- | --- |
| `analysis_generated` | info | `analyze_pcap` ran end to end. |
| `summary_generated` | info | `summarize_pcap` produced a tshark protocol-hierarchy summary. |
| `tshark_analysis_available` | info | `analyze_pcap` got tshark evidence. |
| `zeek_analysis_available` | info | `analyze_pcap` got Zeek evidence. |
| `ascii_strings_extracted` | info | Bounded printable-ASCII strings were returned. Carries the count. |
| `ascii_strings_redacted` | warning | One or more ASCII strings matched a secret pattern and were redacted. |
| `ascii_strings_truncated` | warning | ASCII extraction hit a configured limit. |
| `zeek_notices_present` | warning | Zeek emitted notice records in the bounded output. |
| `zeek_weird_events_present` | warning | Zeek emitted weird-event records in the bounded output. |
| `http_error_statuses_present` | warning | Observed HTTP responses with status ≥ 400 in the bounded output. |
| `dns_rejections_present` | info | Observed DNS queries with non-`NOERROR` response codes. |
| `tcp_resets_present` | warning | Observed connections with reset-like Zeek connection states or history markers. |
| `filtered_pcap_written` | info | `pcap_filter` wrote a derived pcap; message includes the packet count when capinfos was available. |
| `connection_evidence_scoped` | info | `pcap_explain_connection` scoped the analyze pipeline via `zeek_uid`, `five_tuple`, or `frame_number`; carries the constructed display filter. |
| `analysis_profile_applied` | info | A registered `analysis_profile` ran successfully. |
| `analysis_profile_unknown` | warning | The requested `analysis_profile` is not registered; full generic evidence was still returned. |
| `f5_profile_resets_observed` | warning | The `f5_ltm_tls_debug` profile saw reset-bearing connections; message includes side counts. |
| `f5_profile_tls_observed` | info | The `f5_ltm_tls_debug` profile summarized TLS handshakes; message includes handshake count + distinct SNI count. |
| `f5_profile_http_observed` | info | The `f5_ltm_tls_debug` profile bucketed HTTP responses by status class. |
| `pcap_truncated` | warning | The source pcap was cut short mid-record but the analyzers still produced usable partial evidence. The analyze pipeline preserves whatever capinfos / tshark / Zeek managed to read; `pcap_filter` preserves the partial derived pcap (every packet tshark read before hitting the truncation). The finding message names the analyzer that detected the truncation and carries a bounded fragment of its stderr. Distinct from `analyzer_failed`, which is reserved for unrecoverable analyzer failures (binary missing, OOM, segfault, unrelated crash) where no partial evidence is salvageable. |

When an analyzer-level partial failure occurs in `analyze_pcap`, its
`toolError.kind` is mirrored as a finding `code` for orchestration
convenience. Hosts can switch on either surface.

## Privacy invariants

Every tool result must hold these invariants. They are enforced by
implementation choices and asserted by tests.

1. **No raw packet payload bytes returned by parsers.** Tool outputs
   include protocol-hierarchy tables, conversation tables, packet-
   summary rows (frame numbers, addresses, ports, protocol column,
   tshark Info column), Zeek logs, and derived summaries. The packet-
   parsing path never returns full TCP/UDP payload bytes, HTTP
   bodies, raw header text, decrypted content, or key material.

2. **Bounded printable-ASCII evidence is sensitive by design.**
   `analyze_pcap` opt-in defaults include
   [`include_ascii: true`](./TOOL_REFERENCE.md), which extracts
   bounded printable-ASCII runs from the capture file. These strings
   are derived from the bytes on disk, so they can include header
   fragments, request lines, and unencrypted payload text. Operators
   should treat ASCII output as sensitive packet evidence:
   - Default-on best-effort redaction masks `Authorization:`,
     `Cookie:`, `Set-Cookie:`, and common `password=` / `token=` /
     `api_key=` / `secret=` / `session_id=` substrings. Other secret
     shapes (custom auth headers, JWTs not behind those keywords,
     base64 blobs) will pass through.
   - `redact_secrets: false` disables the redaction pass entirely. It
     is an explicit operator opt-out for ASCII output and is intended
     for forensic workflows where the operator already trusts the
     downstream consumer with raw evidence.
   - `include_ascii: false` skips the ASCII section entirely and is
     the right setting when the LLM-visible surface must not contain
     payload-derived text.
   - Output is always bounded by `min_string_length`,
     `max_ascii_strings`, and `max_ascii_bytes` and never exceeds the
     `analysis.*` server caps.

3. **HTTP URIs in Zeek summaries are always redacted.** The Zeek
   `http.log` summary path runs URIs through the same secret-pattern
   pass unconditionally, regardless of `redact_secrets`. There is no
   opt-out for Zeek HTTP URI redaction in this release.

4. **Artifact references, not bytes.** Capture identity is carried as
   `{path, size_bytes, sha256}`. Capture bytes never enter tool
   output.

5. **Bounded outputs and clamping behavior.** Per-call result counts
   and total returned bytes are capped by `analysis.*` config and by
   per-call switches. Per-call values strictly above the configured
   maximum are silently **clamped to the configured maximum** rather
   than rejected; per-call values at or below the maximum are
   honored. `min_string_length` is similarly clamped to its hard
   `[1, 1024]` range. Negative numeric inputs and structurally
   invalid values (NUL bytes, oversize strings) are rejected with a
   typed `validation_failed` error.

6. **Persisted-artifact disk budget.** When `pcap_analyze` writes
   `analysis.json` + `summary.md`, the rendered byte total is checked
   against `analysis.output_disk_budget_bytes` before any file is
   created. Over-budget calls emit the typed `output_limit_reached`
   error in `errors[]` and skip the write entirely; the in-memory
   MCP response still carries the full evidence so the host can
   choose to retry with tighter per-call caps or raise the budget.

## Stability guarantees

- Tool names: never renamed. Removed tools become aliases for one
  release before deletion. New tools are additive.
- `kind` tokens: never renamed; only added.
- `reason` tokens: never renamed; only added.
- Finding `code` tokens: never renamed; only added.
- Status tokens such as `tls_decryption.status`: never renamed; only
  added.
- Output field names: additive. Removing a field is a breaking change
  and requires a roadmap entry.
- `schema_version` is stamped on every `pcap_analyze` /
  `pcap_explain_connection` response and on every persisted
  `OutputArtifact`. Current value is **`1.1.0`**, defined as
  `SchemaVersion` in
  [`output.go`](../internal/pcap/output.go). Bump rules: patch =
  fixes, minor = additive (new optional fields, new finding codes,
  new error kinds, new status tokens), major = breaking. The
  `schema_version` value itself, the field name, and the location
  at the top of the response are stable; hosts should switch on it
  before parsing the rest.

## Where to look in code

- Tool registration: [`internal/pcap/server.go`](../internal/pcap/server.go)
- Error taxonomy: [`internal/pcap/errors.go`](../internal/pcap/errors.go)
- Analyzer pipeline: [`internal/pcap/analyzer.go`](../internal/pcap/analyzer.go)
- Derived summaries: [`internal/pcap/signals.go`](../internal/pcap/signals.go)
- Drift ratchet: [`internal/pcap/tool_reference_doc_test.go`](../internal/pcap/tool_reference_doc_test.go)
