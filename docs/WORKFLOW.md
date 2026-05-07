# Local Workflow

This document is the operator's guide for placing pcap/pcapng files
into the `cute-pcap-mcp` workspace and running analysis through an
MCP host (Claude Code, Codex, etc.). The model-facing wire contract
lives in [`PCAP_SERVER_CONTRACT.md`](./PCAP_SERVER_CONTRACT.md); the
per-tool input/output/error sets live in
[`TOOL_REFERENCE.md`](./TOOL_REFERENCE.md). This file covers the
end-to-end flow: how files get into the workspace, how the MCP host
calls tools, and what to do when things go wrong.

## Boundary recap

`cute-pcap-mcp` analyzes local pcap files. It does **not**:

- capture traffic (no `tcpdump`, port mirrors, appliance packet
  capture, etc.)
- copy files from remote systems (no SSH, SCP, SFTP, HTTP transfer)
- talk to network device APIs (no vendor REST, SSH, or control-plane
  API calls)
- call other MCP servers

Files arrive in the workspace by some other mechanism — a human
copying a pcap, a CI job writing one, a companion MCP server emitting
one, a `tcpdump` cron, etc. Once the file is on the local
filesystem under the configured workspace, this server analyzes it
and returns bounded structured evidence.

## Workspace layout

The canonical workspace is a single directory the operator owns,
typically `~/mcp-work` on a host install or `/work` inside the
container with `~/mcp-work` bind-mounted onto it. The directory has
three subdirectories:

```text
~/mcp-work/
  pcaps/      # pcap/pcapng input files
  output/    # derived JSON / Markdown / filtered pcap artifacts
  tmp/        # per-call analyzer temp work (Zeek workdirs)
```

First-time setup:

```sh
mkdir -p ~/mcp-work/{pcaps,output,tmp}
```

The server enforces the workspace as a containment boundary. With
`workspace.root` set in config, every workspace subdir must resolve
strictly under root. See
[`PCAP_SERVER_CONTRACT.md`](./PCAP_SERVER_CONTRACT.md) for the
"workspace.root is a containment boundary" invariant.

## Running with Docker (recommended)

Build the image once, install the wrapper, and configure the wrapper as
the MCP command in Claude, Codex, or another host:

```sh
make docker-build
mkdir -p ~/bin ~/mcp-work/{pcaps,output,tmp,keylogs}
cp config.docker.example.yaml ~/mcp-work/config.docker.yaml
install -m 0755 scripts/cute-pcap-mcp-docker ~/bin/cute-pcap-mcp-docker
CUTE_PCAP_MCP_IMAGE=cute-pcap-mcp:latest ~/bin/cute-pcap-mcp-docker --version
```

The final command is only a smoke test because it passes `--version`.
Without `--version`, the server waits for MCP messages on stdin/stdout.
`config.docker.example.yaml` sets `workspace.root: /work`; the
`pcap_dir` / `output_dir` / `tmp_dir` defaults follow from there.

For a stricter mount where input pcaps stay read-only:

```sh
docker run --rm -i \
  -v "$HOME/mcp-work/config.docker.yaml:/config/config.yaml:ro" \
  -v "$PWD/captures:/work/pcaps:ro" \
  -v "$HOME/mcp-work-out:/work/output" \
  -v "$HOME/mcp-work-tmp:/work/tmp" \
  cute-pcap-mcp:latest -c /config/config.yaml --version
```

## Running without Docker

The host needs `tshark`, `capinfos`, and `zeek` on PATH for the full
analyze surface. `pcap_analyzer_status` reports which analyzers are
available and the `errors[]` of `pcap_analyze` will note when one is
missing. See
[`CONTAINER.md`](./CONTAINER.md#zeek-runtime) for the local-fallback
contract.

## Placing artifacts

External producers — humans, scripts, CI jobs, other MCP servers —
write pcap files under `~/mcp-work/pcaps/` (or wherever `pcap_dir`
points inside the container). Filenames are caller-chosen.

If the producer can compute the file's SHA-256 and size, it should
pass them to the MCP host as part of an **ArtifactReference** object:

```json
{
  "artifact_id": "incident-2026-04-29-001",
  "pcap_path": "/work/pcaps/incident-2026-04-29-001.pcap",
  "sha256": "<hex>",
  "size_bytes": 4096,
  "source": {
    "kind": "tcpdump-host",
    "context": { "host": "lab-jumphost-01" }
  }
}
```

The host maps the relevant fields to the PCAP MCP tool inputs:

- `pcap_path` → `path`
- `sha256` → `expected_sha256`
- `size_bytes` → `expected_size_bytes`
- `artifact_id` and `source` are opaque to the server; the host may
  log or surface them however it likes

If the producer cannot compute the hash or size, omit those fields
and the server will report its own values back. **Producers MUST NOT
embed the file's bytes** in the reference; pcap bytes never enter MCP
input or LLM prompts.

## Calling the tools (orchestration walkthrough)

A typical analyze flow from the MCP host. **Carry
`expected_sha256` and `expected_size_bytes` from the
ArtifactReference into every tool call**, not just the validate
step — a file can change after validation and before analysis, and
re-passing the expectations means the typed `hash_mismatch` /
`size_mismatch` errors fire on the actual call that needed the
guarantee.

1. **Verify the file** — call `pcap_validate` with `path`,
   `expected_sha256`, and `expected_size_bytes` from the
   ArtifactReference. Returns the artifact's actual metadata, or one
   of `path_outside_allowlist` / `artifact_not_found` /
   `pcap_too_large` / `hash_mismatch` / `size_mismatch`.

2. **Check analyzer availability** (optional) — call
   `pcap_analyzer_status` if you want to branch on whether Zeek is
   available before requesting an analysis that needs Zeek-derived
   sections.

3. **Run the analysis** — call `pcap_analyze` with `path`,
   `expected_sha256`, and `expected_size_bytes`. Defaults write
   `analysis.json` and `summary.md` under
   `${output_dir}/<sha256_prefix>-<utc_timestamp>/` and return
   `OutputArtifact` references in the response. Set
   `write_artifacts: false` to skip the file emission when the host
   only wants the in-memory response.

4. **Scope to a connection** (optional) — call
   `pcap_explain_connection` with a `five_tuple` / `frame_number` /
   `zeek_uid` selector to re-run the analyze pipeline scoped to one
   connection. Pass `expected_sha256` and `expected_size_bytes`
   alongside the selector.

5. **Derive a smaller pcap** (optional) — call `pcap_filter` with a
   tshark display filter to write a derived pcap under
   `${output_dir}` for downstream tooling. The artifact is in the
   legacy libpcap format (matches `application/vnd.tcpdump.pcap`).
   Pass `expected_sha256` and `expected_size_bytes` so the source
   pcap is re-verified before the filter runs.

The host receives `OutputArtifact` references for any persisted
files. It may pass those references onward (paths, sizes, sha256s)
the same way the original ArtifactReference flowed in.

## Load-balancer TLS debug profile

`pcap_analyze` and `pcap_explain_connection` accept an optional
`analysis_profile: "f5_ltm_tls_debug"` switch that layers extra
load-balancer path analysis on top of the generic evidence. The profile is
additive — generic sections (`capture_summary`, `protocols`, `dns`,
`http`, `tls`, `tcp_health`, etc.) are still populated.

When the operator can supply load-balancer context, pass it as
`f5_context` so the profile can classify connections as clientside /
serverside:

```json
{
  "path": "/work/pcaps/incident-2026-04-29-001.pcap",
  "expected_sha256": "<hex>",
  "analysis_profile": "f5_ltm_tls_debug",
  "f5_context": {
    "virtual_server_name": "vs_app_https_443",
    "virtual_server_ip": "203.0.113.10",
    "virtual_server_port": 443,
    "pool_name": "pool_app_443",
    "snat_pool_name": "snat_app",
    "notes": "Failure reported during 14:00–15:00 UTC by ops"
  }
}
```

- `virtual_server_ip` drives the clientside classifier:
  connections whose destination matches it get a
  `clientside_to_vip_observed` SNAT hint, everything else gets a
  `non_vip_destinations_observed` hint. `virtual_server_port` is
  optional and only narrows the match — a bare port without an IP
  cannot be used to claim "this is the VIP."
- `pool_name` / `snat_pool_name` / `virtual_server_name` / `notes`
  are echoed back unchanged (capped at 256 bytes for names, 4096
  for notes; NUL bytes rejected). The server makes no API calls
  based on these values — they're for human / LLM context only.

Without `f5_context`, or with a context that does not include
`virtual_server_ip`, the profile refuses to guess sides and emits
one of two typed hints:

- `clientside_classification_skipped_no_context` — no `f5_context`
  was supplied, or every field was empty.
- `clientside_classification_skipped_no_vip_ip` — `f5_context` was
  present but `virtual_server_ip` was missing, so a clientside
  claim cannot be made (port 443 is everyone's HTTPS — a port
  alone is not a VIP).

This is deliberate: the profile never infers load-balancer config from
packets alone, so it reports the unknown rather than guessing.

The profile result lives at `response.profile`:

```json
{
  "profile": {
    "name": "f5_ltm_tls_debug",
    "limitations": [
      "Packet evidence alone cannot prove virtual server, pool, SNAT pool, ...",
      "Reset-side classification uses Zeek conn_state ...",
      "..."
    ],
    "f5_ltm_tls_debug": {
      "context": { ... },
      "resets":  { "total": 2, "originator_resets": 1, "responder_resets": 1 },
      "tls":     { "handshake_count": 2, "distinct_sni": [...], "versions": {...} },
      "http":    { "request_count": 3, "status_class_counts": { "2xx": 1, "5xx": 1 } },
      "snat_hints": [...]
    }
  }
}
```

The host should always surface `profile.limitations` to the LLM —
the list is the explicit boundary on what packet evidence alone can
prove.

## TLS decryption (SSLKEYLOGFILE)

`pcap_analyze` and `pcap_explain_connection` accept an optional
`tls_keylog_path` input that points at an SSLKEYLOGFILE captured by
the client (typically by setting the `SSLKEYLOGFILE` environment
variable on Chrome / Firefox / curl during the original capture).
When the keylog is valid and lives under `workspace.keylog_dir`, the
server hands it to tshark via `-o tls.keylog_file:` and to Zeek via
the `SSLKEYLOGFILE` subprocess env. The response always carries a
typed `tls_decryption.status` so the host can branch on the outcome
without parsing analyzer prose.

### Setup

The keylog directory is **separate** from `pcap_dir` for safety —
keylog files grant retroactive decryption of every connection they
cover, so they should not live next to the captures they unlock.
Configure it explicitly:

```yaml
workspace:
  root: /work
  keylog_dir: /work/keylog
analysis:
  # ... usual fields ...
```

If `workspace.keylog_dir` is unset, the server reports every keylog
input as `tls_decryption.status: unavailable`.

### Capturing a keylog

Common producers (run on the **client** side of the connection — a
captured server-side pcap alone cannot be decrypted under modern
forward-secret cipher suites):

```sh
# Curl (TLS 1.2/1.3 PFS-aware):
SSLKEYLOGFILE=/work/keylog/curl.log curl -v https://example.test

# Chromium / Chrome / Edge:
SSLKEYLOGFILE=/work/keylog/browser.log google-chrome ...

# Firefox:
SSLKEYLOGFILE=/work/keylog/firefox.log firefox ...
```

Place the resulting file under the configured `keylog_dir`. The
server symlink-resolves the supplied `tls_keylog_path` before the
allowlist check, so a symlink under `keylog_dir` pointing outside
is rejected (`status: unavailable`).

### Calling pcap_analyze with a keylog

```json
{
  "path": "/work/pcaps/incident.pcap",
  "expected_sha256": "<hex>",
  "tls_keylog_path": "/work/keylog/browser.log"
}
```

Possible response statuses (always present under
`response.tls_decryption.status`):

- `not_requested` — caller passed no `tls_keylog_path`. Also
  returned on hard-error analyze responses (validation / path /
  busy) so the field is always present on the wire.
- `unavailable` — server has no `keylog_dir` configured, or the
  path resolves outside it (including via symlink escape).
- `keylog_missing` — path resolves under `keylog_dir` but no file
  exists there.
- `keylog_invalid` — path resolves under `keylog_dir`, but the file
  contains no recognized SSLKEYLOGFILE secret lines. Blank files,
  comment-only files, unsupported labels, non-hex material, and
  malformed rows are not handed to analyzers.
- `attempted` — keylog shape was validated, then applied to tshark
  and Zeek; the analyzers ran without subprocess errors. **This does
  not prove any session was decrypted.** TLS handshakes appear in
  Zeek output regardless of whether a keylog matched, so the pipeline
  does not promote on that signal alone. The limitations list
  documents this honestly.
- `failed` — keylog applied but a keylog-consuming analyzer
  (tshark or Zeek) returned a subprocess error. Errors from
  analyzers that did not consume the keylog (capinfos, ASCII) do
  not flip the status. Per-analyzer kind lands in `errors[]`.
- `succeeded` — **reserved on the wire, not emitted today.** A
  future implementation that has a reliable decrypted-evidence
  signal will promote `attempted` → `succeeded`.

### Why decryption frequently isn't possible

The response's `tls_decryption.limitations` list documents these
exhaustively. The headline reasons:

- TLS 1.3 and ECDHE / DHE in TLS 1.2 use forward-secret key
  exchange. A captured server private key alone cannot decrypt past
  traffic — only an SSLKEYLOGFILE captured during the session
  works.
- A captured SSLKEYLOGFILE only decrypts the connections whose
  handshake keys it contains. Connections that started before the
  keylog began, or used a different TLS session, remain opaque.
- This server reports decryption status only. Decrypted HTTP
  bodies, payload bytes, and headers are **never** returned in
  tool output even when decryption succeeds; the existing redacted
  Zeek `http.log` summaries are the only HTTP evidence.

### Privacy

Keylog files are highly sensitive. Treat them as you would private
keys: restrict filesystem permissions, rotate or delete them
promptly after use, and never check them into source control. The
server never copies, ships, or remotely reads keylog files — the
operator places them in `keylog_dir` and the server hands the path
to its analyzer subprocesses.

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `path_outside_allowlist` | The path resolves outside `allowed_artifact_dirs` and `workspace.pcap_dir`, possibly via symlink. | Place the file under one of the configured input roots, or extend the allowlist. |
| `artifact_not_found` | Path does not exist on disk. | Confirm the producer wrote the file before the tool call; on a Docker run, confirm the bind mount is correct. |
| `artifact_not_regular_file` | Path is a directory, fifo, or device. | Pass the file path, not the parent dir. |
| `pcap_too_large` | File size exceeds `analysis.max_pcap_bytes`. | Raise the budget for trusted hosts, or split / decimate the capture before submitting. |
| `hash_mismatch` | Producer-provided sha256 disagrees with on-disk content. | Confirm the producer wrote the file completely. Omit `expected_sha256` if the producer didn't compute it. |
| `size_mismatch` | Producer-provided size disagrees with on-disk size. | Same as `hash_mismatch` — typically a partial-write or an older reference. |
| `analyzer_unavailable` (in `errors[]`) | A required external analyzer is missing on PATH. | Use the Docker image, or install the missing analyzer on the host. |
| `analyzer_timeout` (in `errors[]`) | An external analyzer exceeded `analysis.command_timeout_seconds`. | Raise the timeout, narrow the `display_filter`, or lower `max_packet_rows`. |
| `analyzer_failed` (in `errors[]`) | The analyzer ran but exited non-zero. The message carries a bounded fragment of stderr. | Inspect the error message. For Zeek: try a smaller pcap to confirm the binary works. |
| `tmp_budget_exceeded` (in `errors[]`) | Zeek wrote more than `analysis.tmp_disk_budget_bytes` to `workspace.tmp_dir`. | Raise the budget, or set `include_zeek: false` to skip Zeek. |
| `output_limit_reached` (in `errors[]`) | The rendered `analysis.json` + `summary.md` would exceed `analysis.output_disk_budget_bytes`, **or** a `pcap_filter` derived pcap exceeded the same budget. | Raise the budget, or lower per-call evidence caps (`max_packet_rows`, `max_zeek_records_per_log`, `max_ascii_strings`, `max_ascii_bytes`). |
| `no_packets_matched` | A `pcap_filter` display filter matched zero packets. | Loosen the filter, or use `pcap_validate` first to confirm the source pcap has packets in the expected protocol. |
| `invalid_filter` | A tshark display filter was rejected by the parser. | Verify the filter syntax (e.g. `tcp.port == 443`, not `tcp_port == 443`). |
| `analysis_busy` | The concurrent-analyzer cap is saturated. | Retryable. Wait for an in-flight call to complete, or raise `analysis.max_concurrent_analyses`. |
| `tls_decryption.status: unavailable` | `workspace.keylog_dir` is not configured, or `tls_keylog_path` resolves outside it. | Set `workspace.keylog_dir` and place the keylog under it; symlinks are followed before the allowlist check, so rebase the link if it points outside. |
| `tls_decryption.status: keylog_missing` | The path resolves under `keylog_dir` but no file is present. | Check the producer wrote the file completely; verify the operator-passed path. |
| `tls_decryption.status: keylog_invalid` | The file exists but has no recognized SSLKEYLOGFILE secret lines. | Reproduce with `SSLKEYLOGFILE` enabled before the client starts; verify the file contains non-comment `CLIENT_RANDOM` or TLS 1.3 traffic-secret rows. |
| `tls_decryption.status: failed` | tshark or Zeek errored while the keylog was applied. | Inspect `errors[]` for the per-analyzer kind. Try the analyze pass without the keylog to confirm the analyzers themselves work. |

## Privacy reminders

- Raw pcap bytes never enter MCP input or LLM prompts. Only
  references (path, size, sha256) flow through.
- ASCII string output from `pcap_analyze` is bounded sensitive
  evidence: best-effort secret redaction is on by default
  (`redact_secrets: true`). Set `include_ascii: false` if the LLM-
  visible surface must not contain payload-derived text.
- Zeek HTTP URI redaction is unconditional regardless of
  `redact_secrets`.
- See the privacy invariants in
  [`PCAP_SERVER_CONTRACT.md`](./PCAP_SERVER_CONTRACT.md) for the
  exhaustive list.

## Storage and audit

- Output artifacts live under the configured `workspace.output_dir`
  with a deterministic per-run directory (`<sha256_prefix>-<utc_ts>`).
  Re-runs of the same input pcap get distinct `-<n>` suffixes when
  they fire in the same second, so evidence diffs across runs are
  preserved.
- Nothing is uploaded anywhere. There is no S3, cloud storage, or
  external artifact store; the workspace is the audit surface.
- Logs go to stderr in JSON-text format. Tool inputs and outputs are
  not logged at info level — operators get tool name, outcome, and
  typed error kind.
