# Tool Reference

This document is the model-facing contract for the
`cute-pcap-mcp` MCP server. It covers every tool the server registers
in [`server.go`](../internal/pcap/server.go). The
`TestToolReferenceCoversEveryRegisteredTool` ratchet
([source](../internal/pcap/tool_reference_doc_test.go)) fails if a
registered tool is missing a section here, and if a section here names
a tool the server does not register.

The tool surface is intentionally small. It only takes pcap/pcapng
artifacts from operator-configured allowlisted directories and returns
bounded structured evidence. There is no "run a shell command" tool,
no upload tool, and no capture tool.

For wire-shape and error taxonomy details see
[`PCAP_SERVER_CONTRACT.md`](./PCAP_SERVER_CONTRACT.md). For the
delivery plan see [`ROADMAP.md`](./ROADMAP.md).

## Tools today

- `pcap_validate` — validate an allowlisted pcap and return artifact
  metadata. (Stable name; `inspect_pcap` is a one-release alias.)
- `pcap_analyzer_status` — report local availability and versions of
  `capinfos`, `tshark`, and `zeek`.
- `get_server_info` — read-only build/runtime metadata for this MCP
  server (build version, commit, build time, Go version, MCP handshake
  version, PCAP analysis schema version). No analyzer call; no file
  read. Available in every server profile.
- `pcap_analyze` — full analysis pipeline with capinfos, tshark, Zeek,
  bounded ASCII extraction, derived summaries, persisted JSON +
  Markdown artifacts, and findings. (Stable name; `analyze_pcap` is a
  one-release alias.)
- `pcap_diagnose_symptoms` — closed-vocabulary, vendor-neutral
  wire-level symptoms for downstream root-cause skills. Returns
  structural counters and parser findings only; no raw payload bytes
  or vendor interpretation.
- `pcap_filter` — write a filtered pcap under `workspace.output_dir`
  from a tshark display filter; returns an `OutputArtifact` reference
  with kind `filtered_pcap`.
- `pcap_explain_connection` — run the analyze pipeline scoped to one
  connection identified by `zeek_uid`, `five_tuple`, or
  `frame_number`. Same response shape as `pcap_analyze` plus a
  resolved-selector echo.
- `inspect_pcap` — legacy alias for `pcap_validate` (compat-only).
- `analyze_pcap` — legacy alias for `pcap_analyze` (compat-only).
- `summarize_pcap` — legacy tshark-only protocol hierarchy preview.

### Deprecation policy

Stable names (`pcap_*`) are the supported orchestration surface.
Legacy names (`inspect_pcap`, `analyze_pcap`, `summarize_pcap`) are
kept registered for one release. Hosts should migrate to the stable
names; the legacy names log under their own tool-name slug so the
migration is observable.

### `pcap_validate`

Validate an allowlisted pcap/pcapng artifact and return its metadata.
This tool runs no analyzers and does not read packet payload bytes; it
only stats the file, computes its SHA-256, and confirms the path
resolves under a configured allowed artifact directory.

Input:

- `path`: absolute or relative path to a pcap/pcapng file under an
  allowed artifact directory. Symlinks are resolved before allowlist
  checks.
- `expected_sha256` (optional): caller-provided sha256 from an
  external artifact reference. Mismatched values return the typed
  `hash_mismatch` error. Comparison is case-insensitive.
- `expected_size_bytes` (optional): caller-provided file size from an
  external artifact reference. Mismatched values return the typed
  `size_mismatch` error. The size check fires before the hash read,
  so callers that only know the size still get a fast typed error.

Success output:

- `artifact`: object with the resolved `path`, `size_bytes`, and
  `sha256` of the file.

Tool errors:

- `missing_field` — `path` was empty.
- `validation_failed` — the caller-provided `expected_sha256` is not
  exactly 64 hex digits, or `expected_size_bytes` is negative.
  Carries `field: expected_sha256` + `reason: invalid_format`, or
  `field: expected_size_bytes` + `reason: out_of_range`. Format
  validation runs **before** the artifact is opened, so a malformed
  expectation is reported as `validation_failed` (the actual mistake)
  rather than `hash_mismatch` / `size_mismatch` (a downstream
  side-effect).
- `path_outside_allowlist` — the resolved (real) path is not under any
  configured `allowed_artifact_dirs` entry or `workspace.pcap_dir`.
- `artifact_not_regular_file` — the path resolves to a directory,
  device, fifo, or other non-regular file.
- `artifact_not_found` — the resolved path does not exist on disk.
- `pcap_too_large` — the file is strictly larger than
  `analysis.max_pcap_bytes`. Rejected before reading the bytes for the
  SHA-256 hash.
- `hash_mismatch` — a well-formed `expected_sha256` does not equal
  the actual hash. Carries `field: expected_sha256`. The mismatch
  message echoes only the actual computed hash; the caller-provided
  value is never reflected back.
- `size_mismatch` — a non-negative `expected_size_bytes` does not
  equal the actual size. Carries `field: expected_size_bytes`.

### `pcap_analyze`

Run the full analysis pipeline: capinfos metadata (parsed into a
`capture_summary` section), tshark protocol hierarchy, conversation
tables, packet rows, Zeek logs and derived DNS / HTTP / TLS / notice /
weird summaries, derived `tcp_health`, and bounded printable-ASCII
extraction with secret redaction. When `workspace.output_dir` is
configured, also writes `analysis.json` and `summary.md` under
`${output_dir}/<sha256_prefix>-<utc_timestamp>[-<n>]/` and returns
`OutputArtifact` references in the response. The optional `-<n>`
suffix is added by the writer's `Mkdir` collision-retry loop when two
analyses of the same pcap fire in the same UTC second.

Output shape (top level): `schema_version`, `artifact`,
`capture_summary`, `protocols`, `conversations`, `packets`, `dns`,
`http`, `tls`, `tcp_health`, `notices`, `weird_events`, `zeek_logs`,
`ascii`, `tls_decryption`, `profile`, `findings`, `artifacts`,
`errors`, `metadata`.

Input:

- `path`: absolute or relative path to a pcap/pcapng file under an
  allowed artifact directory.
- `include_capinfos`, `include_tshark`, `include_zeek`,
  `include_ascii` (optional, default `true`): per-section opt-out.
- `redact_secrets` (optional, default `true`): redact common
  credential/token patterns from the ASCII string output. Zeek HTTP
  URI redaction is unconditional (see
  [`PCAP_SERVER_CONTRACT.md`](./PCAP_SERVER_CONTRACT.md) privacy
  invariants).
- `display_filter` (optional): tshark display filter applied to packet
  rows. Rejected if it contains NUL bytes or exceeds 4096 bytes.
- `min_string_length` (optional, default `4`): minimum printable ASCII
  run length to return.
- `max_packet_rows`, `max_ascii_strings`, `max_ascii_bytes`,
  `max_zeek_records_per_log` (optional): per-call caps. Per-call values
  above the configured maximum are clamped to that maximum.
- `write_artifacts` (optional, default `true`): write `analysis.json`
  and `summary.md` under `workspace.output_dir`. Has no effect when
  `output_dir` is empty.
- `expected_sha256` / `expected_size_bytes` (optional): same external
  artifact-reference fields documented under `pcap_validate`.
- `analysis_profile` (optional): named profile that layers extra
  analysis on top of the generic evidence. Today the only registered
  name is `f5_ltm_tls_debug`. Unknown names are not a hard error;
  the analyze pipeline still returns full generic evidence, and an
  `analysis_profile_unknown` finding marks the unrecognized name so
  the host can branch on it.
- `tls_keylog_path` (optional): absolute or relative path to an
  SSLKEYLOGFILE under `workspace.keylog_dir`. When set and valid,
  enables TLS decryption inside tshark (`-o tls.keylog_file:`) and
  Zeek (`SSLKEYLOGFILE` env). The response always carries a typed
  `tls_decryption` section reporting one of `not_requested` /
  `unavailable` / `keylog_missing` / `keylog_invalid` /
  `attempted` / `succeeded` / `failed`. Decrypted payload bytes are
  **never** returned in tool output regardless of state — only the
  typed status. See the
  "TLS decryption" section in
  [`PCAP_SERVER_CONTRACT.md`](./PCAP_SERVER_CONTRACT.md) for the
  full state machine and limitations.
- `f5_context` (optional): caller-supplied load-balancer context for the
  `f5_ltm_tls_debug` profile. The server **never** uses these values
  to call other systems — they classify packet evidence only. Field
  bounds:
  - `virtual_server_ip`: parsed via `net/netip`; rejected on bad
    format.
  - `virtual_server_port`: must be in `[0, 65535]`.
  - `virtual_server_name`, `pool_name`, `snat_pool_name`: free-form
    strings, capped at 256 bytes; NUL bytes rejected. Accepted
    values are echoed back unchanged.
  - `notes`: free-form string, capped at 4096 bytes; NUL bytes
    rejected. Accepted value echoed back unchanged.

Tool errors:

- `missing_field`, `validation_failed`, `invalid_filter` — input
  validation. `invalid_filter` carries a `field` of `display_filter`.
  `validation_failed` from `f5_context` carries one of the following
  field tokens: `f5_context.virtual_server_ip`,
  `f5_context.virtual_server_port`, `f5_context.virtual_server_name`,
  `f5_context.pool_name`, `f5_context.snat_pool_name`,
  `f5_context.notes`. The `reason` field carries
  `invalid_format` (bad IP), `out_of_range` (port outside
  `[0, 65535]`), `too_long` (free-form field over its cap), or
  `contains_nul` (NUL byte in a free-form field).
- `path_outside_allowlist`, `artifact_not_regular_file`,
  `artifact_not_found`, `pcap_too_large`, `hash_mismatch`,
  `size_mismatch` — same semantics as `pcap_validate`.
- `analysis_busy` — concurrent-analyzer cap saturated. Retryable.
- `tmp_budget_exceeded` — Zeek wrote more than
  `analysis.tmp_disk_budget_bytes` to `workspace.tmp_dir`. Returned in
  `errors[]` because other sub-analyzers may have produced evidence.
- `output_limit_reached` — the rendered `analysis.json` +
  `summary.md` would exceed `analysis.output_disk_budget_bytes`. The
  artifacts are not written; the in-memory analyze response is still
  returned, and the error lands in `errors[]`.
- `analyzer_unavailable`, `analyzer_failed`, `analyzer_timeout` —
  emitted per-analyzer in `errors[]`, not as a top-level error.
  **Recognized truncated-pcap diagnostics do NOT classify as
  `analyzer_failed`.** A capinfos / tshark / Zeek run that hits
  the truncation phrase still produces partial evidence (capture
  metadata, packet rows, log files); the response keeps that
  evidence and adds a `pcap_truncated` warning to `findings`
  instead of a failed-analyzer error.

#### `analysis_profile=f5_ltm_tls_debug`

Selecting this profile populates a `profile` section in the response
alongside (not replacing) the generic evidence:

```json
{
  "profile": {
    "name": "f5_ltm_tls_debug",
    "limitations": ["..."],
    "f5_ltm_tls_debug": {
      "context": { "virtual_server_ip": "203.0.113.10", "virtual_server_port": 443 },
      "resets":  { "total": 2, "originator_resets": 1, "responder_resets": 1, "connections": [...] },
      "tls":     { "handshake_count": 2, "distinct_sni": [...], "versions": {...}, "ciphers": {...}, "handshakes": [...] },
      "http":    { "request_count": 3, "status_class_counts": { "2xx": 1, "4xx": 1, "5xx": 1 }, "requests": [...] },
      "snat_hints": [{ "description": "clientside_to_vip_observed", "evidence": "1 connection(s) destined for the configured VIP" }]
    }
  }
}
```

Clientside classification requires `f5_context.virtual_server_ip`.
A bare `virtual_server_port` is not a VIP (port 443 is everyone's
HTTPS), so the profile refuses to label connections as
`clientside_to_vip_observed` without the IP. The wire `snat_hints`
discriminator reflects which refusal applies:

- `clientside_classification_skipped_no_context` — `f5_context` was
  absent or had every field empty; the profile reports the unknown.
- `clientside_classification_skipped_no_vip_ip` — `f5_context` was
  present (some name/port/notes field set) but
  `virtual_server_ip` was not, so a clientside claim cannot be
  made. `virtual_server_port` is honored only as an optional
  narrowing field on top of `virtual_server_ip`.

When `virtual_server_ip` is supplied, connections whose destination
matches it (and the port, if also set) emit
`clientside_to_vip_observed`; everything else emits
`non_vip_destinations_observed`.

Packet evidence alone cannot prove load-balancer config; the profile
reports the unknown rather than guessing.

Profile findings (added to the top-level `findings[]`):

- `analysis_profile_applied` — info, the requested profile ran.
- `analysis_profile_unknown` — warning, the requested profile name is
  not registered.
- `f5_profile_resets_observed` — warning, summarizes reset counts
  with side classification.
- `f5_profile_tls_observed` — info, summarizes TLS handshake counts +
  distinct SNI count.
- `f5_profile_http_observed` — info, summarizes HTTP request counts
  bucketed by status class.

### `pcap_diagnose_symptoms`

Diagnose an allowlisted pcap/pcapng into a closed vocabulary of
vendor-neutral wire symptoms. This tool describes only what was
observable on the wire. It does not name BIG-IP, firewall, proxy,
cloud load balancer, or other vendor concepts, and it does not
recommend configuration changes. Per-vendor catalogs and
cross-domain skills consume these tokens and add interpretation in
their own layer.

Output carries `schema_version: "1.0.0"` and uses this top-level
shape: `path`, `size_bytes`, `sha256`, `symptoms[]`, `findings[]`.
`path`, `size_bytes`, and `sha256` are populated only after path and
artifact validation succeeds. Every row is structural: flow tuple,
packet counters, timing offsets, and per-symptom counters. Raw packet
payload bytes, decrypted bytes, analyzer dumps, keys, and secrets are
never returned.

Input:

- `path`: absolute or relative path to a pcap/pcapng file under an
  allowed artifact directory. Required by the tool, validated inside
  the handler so missing path fails closed as a typed finding.
- `expected_sha256` / `expected_size_bytes` (optional): same external
  artifact-reference fields documented under `pcap_validate`.
- `scope` (optional): `src_ip`, `dst_ip`, `src_port`, `dst_port`,
  and `protocol` (`tcp`, `udp`, or `icmp`) for flow narrowing. v1
  symptoms are TCP-only, so non-TCP scope values simply produce no
  v1 symptoms.
- `symptom_filter` (optional): closed-vocabulary subset to evaluate.
  Unknown tokens fail closed before parse work.

Success output:

- `schema_version`: diagnose contract version (`1.0.0`).
- `path`, `size_bytes`, `sha256`: validated input artifact identity.
- `symptoms[]`: closed-vocabulary symptoms. v1 codes are
  `tls_handshake_attempted_on_plain_port`,
  `tcp_rst_after_synack_no_app_data`,
  `monitor_probe_returns_rst`, and
  `asymmetric_return_path_observed`.
- `findings[]`: parser-side state and fail-closed validation results.

v1 symptom contracts:

- `tls_handshake_attempted_on_plain_port`: warning/high. TLS Client
  Hello observed, no TLS Server Hello, and the server response is
  `rst`, `http_plaintext`, `other_plaintext`, or `none`. Evidence
  includes `client_hello_observed`, `server_response_kind`, and
  `tls_version_offered`.
- `tcp_rst_after_synack_no_app_data`: warning/high. TCP three-way
  handshake completed, then responder RST before application bytes in
  either direction. Evidence includes `handshake_completed`,
  `app_bytes_client_to_server`, `app_bytes_server_to_client`, and
  `time_to_rst_ms`.
- `monitor_probe_returns_rst`: info/medium. Short periodic
  probe-shaped flows from the same source to the same destination
  consistently receive RST. Evidence includes `probe_count`,
  `probe_cadence_seconds_p50`, and `rst_ratio`.
- `asymmetric_return_path_observed`: warning/medium. Interface-tagged
  capture shows SYN and matching SYN ACK on different capture
  interfaces, or SYN without the matching return leg. Evidence
  includes `syn_seen`, `syn_ack_seen`, `interfaces_observed`, and
  `flow_complete_via_other_interface`.

Findings vocabulary:

- `pcap_diagnose_flow_unparseable` — warning, parser could not
  classify flow evidence for v1 extractors.
- `pcap_diagnose_capture_truncated` — info, capture truncation was
  observed by packet metadata or analyzer diagnostics.
- `pcap_diagnose_window_too_short` — info, capture duration is below
  the cadence window for monitor-probe symptoms; cadence symptoms are
  skipped rather than fabricated.
- `pcap_diagnose_parse_timeout` — warning, diagnose parsing exceeded
  the server-side parse-time bound.
- `pcap_diagnose_capture_lacks_interface_metadata` — info, asymmetric
  return-path extraction is suppressed because interface metadata is
  absent or only a single unnamed interface is visible.
- `pcap_diagnose_unrecognized_pattern_observed` — info, reserved for
  internal extractor matches that are not promoted to symptom tokens.
  This is deliberately a finding, not a symptom, so hosts can keep the
  symptom vocabulary closed.
- `pcap_diagnose_input_invalid` — error, malformed input such as
  missing `path`, malformed `expected_sha256`, negative
  `expected_size_bytes`, invalid `scope`, or unknown
  `symptom_filter`.
- `pcap_diagnose_path_invalid` — error, path-safety or artifact-file
  checks rejected `path` before parse work.
- `pcap_diagnose_artifact_mismatch` — error,
  `expected_sha256` / `expected_size_bytes` disagreed with the file on
  disk, so parsing was refused.

MCP result semantics differ intentionally from sibling tools:
`pcap_validate`, `pcap_analyze`, `pcap_filter`, and
`pcap_explain_connection` use `IsError=true` for their hard
validation failures. `pcap_diagnose_symptoms` instead fails closed as
a normal MCP result (`IsError=false`) for malformed input, unsafe
paths, and artifact hash/size mismatches. In those responses,
`schema_version` is populated, `symptoms` is empty, and `findings[]`
names the typed reason. Hosts should branch on
`findings[].code`/`severity` for diagnose failure states instead of
expecting MCP-level errors.

### `pcap_filter`

Apply a tshark display filter to an allowlisted source pcap and write
the matching packets to a derived pcap under `workspace.output_dir`.
The output path is server-generated (operators cannot pick a
destination); same-second re-runs of the same source pcap get an
incrementing `-<n>` suffix on the dir name. The derived artifact is
hashed after write and returned with the standard `OutputArtifact`
shape.

Input:

- `path`: absolute or relative path to the source pcap/pcapng file.
- `display_filter`: tshark display filter applied with `-Y`. Must be
  non-empty, no NUL bytes, ≤ 4096 bytes.
- `expected_sha256` / `expected_size_bytes` (optional): same external
  artifact-reference fields documented under `pcap_validate`.

Success output:

- `schema_version`: contract wire version.
- `source`: input pcap reference (`path`, `size_bytes`, `sha256`).
- `artifact`: `OutputArtifact` for the derived pcap, with `kind`
  `filtered_pcap` and `content_type` `application/vnd.tcpdump.pcap`.
  The file is written in the legacy libpcap format (tshark `-F pcap`)
  so the bytes match the advertised content type.
- `packet_count`: best-effort exact count from `capinfos -c`. Present
  (non-zero) when capinfos is available; **omitted from the JSON
  wire shape** when capinfos is missing or unparseable. The
  derived pcap is still guaranteed non-empty on the success path —
  the zero-vs-non-zero check uses tshark, not capinfos. The
  `filtered_pcap_written` finding's message reflects this:
  it lists the count when known, and explicitly says "exact packet
  count unavailable" when capinfos was missing.
- `display_filter`: the filter that was applied.
- `findings`: includes `filtered_pcap_written`. When the source
  pcap was cut short mid-record but tshark still wrote a readable
  derived pcap, also includes a `pcap_truncated` warning finding
  alongside the success path. The artifact is preserved in this
  case — every packet tshark read before the truncation point
  lands in `filtered.pcap`.

Tool errors:

- `missing_field` — `path` or `display_filter` was empty.
- `validation_failed` — `display_filter` had a NUL byte or was over
  4096 bytes (carries `field` + `reason`).
- `invalid_filter` — tshark rejected the filter syntax. Carries
  `field: display_filter`.
- `path_outside_allowlist`, `artifact_not_regular_file`,
  `artifact_not_found`, `pcap_too_large`, `hash_mismatch`,
  `size_mismatch` — same semantics as `pcap_validate`.
- `analysis_busy` — concurrent-analyzer cap saturated. Retryable.
- `output_limit_reached` — the derived pcap would exceed
  `analysis.output_disk_budget_bytes`. The over-budget file is
  removed before the error returns.
- `no_packets_matched` — the display filter matched zero packets.
  The empty derived pcap is removed before the error returns. Carries
  `field: display_filter`. **Truncated-source caveat:** when the
  source pcap was cut short mid-record, the verdict only covers the
  readable prefix — matches after the truncation point are
  unobservable. In that case the response includes a
  `pcap_truncated` finding in `findings[]` even on the error path,
  and the error message reads "produced zero packets in the readable
  prefix; matches after the truncation point are unknown" so
  orchestration cannot over-trust the no-match verdict. The empty
  derived pcap is still removed.
- `analyzer_unavailable` / `analyzer_failed` / `analyzer_timeout` —
  tshark was missing, exited non-zero on a non-recoverable error,
  or hit the call timeout. **Recognized truncated-pcap diagnostics
  do NOT classify as `analyzer_failed`** — on the success path they
  preserve the partial derived artifact and surface a
  `pcap_truncated` warning finding; on the no-match path described
  above they survive as a warning alongside the typed
  `no_packets_matched` error.
- `analyzer_failed` from `workspace.output_dir` not being configured;
  `pcap_filter` requires an output workspace.

### `pcap_explain_connection`

Run the analyze pipeline scoped to a single connection. The selector
identifies the connection three ways; exactly one must be set:

- `zeek_uid` — the Zeek connection UID. Triggers a Zeek pass over
  the source pcap to map UID → 5-tuple, then reuses the analyze
  pipeline with that 5-tuple. Most expensive selector.
- `five_tuple` — explicit `{source_ip, source_port, dest_ip,
  dest_port, protocol}`. Direct filter construction; cheapest.
- `frame_number` — a tshark frame number on a TCP or UDP stream.
  Triggers a single tshark call to map frame → `tcp.stream` /
  `udp.stream` id, then filters on the stream.

Output is the same shape as `pcap_analyze` plus a resolved
`selector` echo and a `connection_evidence_scoped` finding.

Input:

- `path`: absolute or relative path to the source pcap.
- `zeek_uid` (optional): Zeek connection UID.
- `five_tuple` (optional): `{source_ip, source_port, dest_ip,
  dest_port, protocol}`. `protocol` must be `tcp` or `udp`.
- `frame_number` (optional, > 0): tshark frame number.
- `max_packet_rows` (optional): per-call cap on returned packet
  rows; clamped to `analysis.max_packet_rows`.
- `redact_secrets` (optional, default `true`): same semantics as
  `pcap_analyze`.
- `include_ascii` (optional, default `false`): include bounded ASCII
  string output for the scoped packets. Defaults to false because
  connection-explain workflows are usually about flow shape, not
  payload bytes.
- `write_artifacts` (optional, default `true` when `output_dir` is
  configured): persist `analysis.json` + `summary.md`.
- `expected_sha256` / `expected_size_bytes` (optional): same external
  artifact-reference fields documented under `pcap_validate`.
- `analysis_profile` / `f5_context` (optional): same profile fields
  documented under `pcap_analyze`. The profile runs against the
  connection-scoped evidence.
- `tls_keylog_path` (optional): same SSLKEYLOGFILE field documented
  under `pcap_analyze`. The keylog is plumbed into the same
  analyze pipeline that runs scoped to the resolved selector, so
  the response carries the typed `tls_decryption.status` for the
  scoped analysis.

Success output:

- All fields of `pcap_analyze`'s response, scoped to the resolved
  connection.
- `selector`: `{resolution, zeek_uid?, five_tuple?, frame_number?,
  stream_id?, display_filter}`. `resolution` is one of `five_tuple`,
  `zeek_uid`, `frame_number`.
- `findings` includes `connection_evidence_scoped`.

Tool errors:

- `missing_field` — `path` was empty.
- `validation_failed` — wrong number of selectors set, missing
  five_tuple fields, invalid protocol, out-of-range port, etc.
  Carries `field` + `reason`.
- `path_outside_allowlist`, `artifact_not_regular_file`,
  `artifact_not_found`, `pcap_too_large`, `hash_mismatch`,
  `size_mismatch` — same semantics as `pcap_validate`.
- `analysis_busy` — concurrent-analyzer cap saturated. Retryable.
- `frame_number_out_of_range` — `frame_number` selector points past
  the last frame in the capture. Carries `field: frame_number`; the
  message names the valid range when capinfos was available.
- `frame_not_on_stream` — `frame_number` selector resolved to a real
  frame that is not on a tcp/udp stream (e.g., ARP, ICMP-only,
  FILEINFO records). Carries `field: frame_number`; the message names
  the frame's protocol.
- `analyzer_failed` — `zeek_uid` was not found in `conn.log`, or
  another analyzer-level failure occurred while resolving the
  selector.
- All errors from `pcap_analyze` are passed through (per-section
  failures land in `errors[]`).

### `inspect_pcap`

Compatibility alias for `pcap_validate`. Same input, output, and
error set. New clients should call `pcap_validate` directly.

### `pcap_analyzer_status`

Report local availability and version strings for the analyzers this
server may invoke. Useful for orchestration: an LLM can branch on
`available` before requesting an analysis that needs a specific
analyzer.

Input:

- no arguments

Success output:

- `analyzers`: list of `{name, available, path, version, error}`
  entries for `capinfos`, `tshark`, and `zeek`.

Tool errors:

- none — analyzer absence is reported per-entry, not as a tool error.

### `get_server_info`

Return the PCAP MCP server's build and runtime metadata. Read-only;
the handler is pure in-process (no analyzer call, no file read, no
subprocess) so it answers fast and is safe to call before any
allowlist or workspace config has resolved. The same `internal/buildinfo`
package symbols backing the CLI `--version` flag are reused so the
two surfaces cannot drift. Available in every server profile.

`pcap_analyzer_status` remains the authoritative answer for analyzer
availability and version strings (`tshark`, `capinfos`, `zeek`); this
tool intentionally does NOT probe the analyzer binaries.

Input:

- no arguments

Success output:

- `name`: product / server identity. Always `"cute-pcap-mcp"`.
- `build_version`: link-time release version from `internal/buildinfo`
  (the value the linker injects via `-ldflags`). Falls back to the
  `"unknown"` sentinel for dev builds.
- `commit`: VCS revision from `internal/buildinfo`. Same fallback.
- `build_time`: link-time build timestamp from `internal/buildinfo`.
  Same fallback.
- `go_version`: Go toolchain version from `runtime.Version()` via
  `internal/buildinfo`.
- `mcp_server_version`: the MCP handshake `serverInfo.version` this
  server advertises during initialize. Distinct from `build_version`:
  this is the wire-protocol identity version, not the release
  artifact's injected version.
- `schema_version`: the current PCAP analysis output schema version
  (the same value `pcap_analyze` and `pcap_explain_connection` stamp
  on every response). Lets a host pair the server build version with
  the analysis-contract version.
- `config_source`: closed enum describing where the server resolved
  its config from. Today this is always `"file"` (the binary requires
  `-c`/`--config`); `"env"` and `"default"` are reserved for future
  fallbacks. Never a path.
- `analyzer_status_available`: `true` when `pcap_analyzer_status` is
  registered on this server. Static in-process check, not a runtime
  probe of the analyzer binaries.

Tool errors:

- none — the handler is pure metadata and cannot fail under normal
  operation.

### `summarize_pcap`

Run `tshark -q -z io,phs` against an allowlisted pcap and return the
protocol-hierarchy table as plain text. Intended as a low-cost preview
before calling `analyze_pcap`.

Input:

- `path`: absolute or relative path to a pcap/pcapng file under an
  allowed artifact directory.
- `expected_sha256` / `expected_size_bytes` (optional): same external
  artifact-reference fields documented under `pcap_validate`.

Success output:

- `artifact`: artifact metadata (same shape as `inspect_pcap`).
- `analyzer`: always `"tshark"` for this tool.
- `protocol_report`: tshark's protocol-hierarchy text, bounded by
  `analysis.max_stdout_bytes`.
- `findings`: stable finding codes including `summary_generated`.

Tool errors:

- `missing_field`, `path_outside_allowlist`,
  `artifact_not_regular_file`, `artifact_not_found`, `pcap_too_large`,
  `hash_mismatch`, `size_mismatch` — same semantics as `pcap_validate`.
- `analysis_busy` — the configured concurrent-analyzer cap is
  saturated. Retryable.
- `analyzer_unavailable` — `tshark` is not on PATH.
- `analyzer_failed` — tshark ran but exited non-zero.
- `analyzer_timeout` — tshark hit `analysis.command_timeout_seconds`.

### `analyze_pcap`

Compatibility alias for `pcap_analyze`. Same input, output, and
error set. New clients should call `pcap_analyze` directly.

## What's NOT shipped (today)

The tools below are planned but not registered by this release.

_(no remaining roadmap items at this layer; profile and decryption
inputs are documented in their own sections above)_

Capture acquisition, remote file copy, and device-specific workflows are
intentionally not in this repo. They belong to humans, scripts, or
external MCP servers. See [`ROADMAP.md`](./ROADMAP.md) for project
boundaries and future work.
