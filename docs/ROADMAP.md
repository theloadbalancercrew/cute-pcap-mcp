# Roadmap

This roadmap turns the open GitLab issues into an implementation plan for
`cute-pcap-mcp`. It is written for coding agents and reviewers: each
milestone has goals, non-goals, issue scope, ordering, and done criteria.

The server stays packet-capture first. It composes with
`cute-bigip-mcp` and other producers through local artifact references,
while keeping these contract rules:

- domain server first, not a generic framework
- MCP is the repo-to-repo contract
- typed tools beat prompt steering
- stable error and finding tokens beat prose parsing
- unknown stays unknown
- bounded inputs reject unsafe values instead of silently widening scope
- private artifacts are references, not prompt content
- docs and tests must match the registered tool surface

## Product Boundary

`cute-pcap-mcp` owns local packet evidence normalization. It accepts
operator-provided PCAP/PCAPNG files from configured workspace paths,
runs bounded local analysis tools, and returns structured evidence plus
safe artifact references.

It does not capture traffic, copy files from devices, authenticate to
network equipment, or call other MCP servers. External producers create
pcap files and place them in the local workspace. The only contract this
repo owns is a local artifact reference: path, size, hash, and optional
producer/source context.

## Goals

- Work with Claude Code / Codex through typed MCP tools.
- Keep raw PCAP bytes out of LLM-visible prompts and logs.
- Default to local filesystem storage under `/work`.
- Analyze with `capinfos`, `tshark`, Zeek, and bounded internal parsing.
- Produce stable JSON and Markdown artifacts.
- Preserve partial results when one analyzer fails.
- Make load-balancer profile analysis explicit, optional, and
  limitation-aware.
- Keep Docker as the preferred portable runtime.

## Non-Goals

- No S3, cloud storage, or remote artifact store.
- No raw PCAP upload to the LLM.
- No arbitrary shell execution.
- No PCAP capture implementation in this repo.
- No direct MCP-to-MCP calls from this server.
- No remote file copy, SCP/SFTP, SSH, or device API clients.
- No web daemon, metrics endpoint, GUI, approval workflow, or control
  plane behavior.
- No generic multi-domain plugin framework.
- No TLS decryption claims unless key material is supplied and bounded.

## Contract Patterns

Use these patterns as implementation constraints:

- **Exact tool contract docs and tests.**
  Tool reference docs and server-contract docs must stay aligned with
  registered tools by tests.
- **Typed errors.**
  Use stable error kind and reason tokens for PCAP validation,
  analyzer failures, resource limits, filter failures, and artifact
  mismatches.
- **Truth-over-closure.**
  Unsupported or unavailable capability is a typed outcome, not a fake
  success. Empty capture, no packet match, analyzer unavailable, and
  analyzer failure must remain distinct.
- **Bounded inputs.**
  Reject over-limit values instead of silently clamping. PCAP analysis
  should do this for file size, result limits, filter length, and
  output budget.
- **Private artifacts.**
  Return paths/hashes/sizes for artifacts, never raw bytes.
- **Boundary docs.**
  Be explicit about what belongs in this MCP server versus the host or
  an external producer/control plane.
- **Observability through stderr JSON logs only.**
  Keep stdio MCP and structured stderr logs; avoid web/metrics scope
  creep.
- **Tests as truth tables.**
  `docs/PCAP_TESTS_AND_SMOKE.md` documents exactly what tests prove
  and what they do not prove.

## Anti-Patterns

Avoid these even if they seem convenient:

- Teaching the host or prompt to compensate for weak tools.
- Parsing free-form analyzer prose when a structured field can be added.
- Adding a generic "run command" or raw shell tool.
- Letting user input choose output paths.
- Writing derived artifacts next to raw PCAPs.
- Returning packet payload bytes, HTTP bodies, cookies, Authorization
  headers, tokens, key material, or raw decrypted content.
- Calling external producers or other MCP servers from inside
  `cute-pcap-mcp`.
- Creating a shared Go package between this server and companion
  control-plane repos.
- Adding control-plane features such as approvals, audit persistence,
  dashboards, notifications, or session routing.
- Landing aspirational docs without implementation or tests.

## Milestone 0: Alignment And Contract Discipline

**Theme:** Make the work executable and keep the repo honest.

**Issues:**

- #3 Umbrella: LLM-safe packet evidence MCP server
- #15 Track roadmap phases for PCAP MCP without hidden workflows
- #16 Formalize input validation and typed error taxonomy

**Implementation order:**

1. Add this roadmap and keep it linked from `README.md`.
2. Write `docs/TOOL_REFERENCE.md` for the PCAP tool surface.
3. Write `docs/PCAP_SERVER_CONTRACT.md` with wire shapes, typed errors,
   and finding tokens.
4. Add a test that registered tools are covered by the tool reference.
5. Add typed error kinds and validation reason tokens.

**Done criteria:**

- Tool names, input fields, output fields, error kinds, and finding
  codes are documented.
- Tests fail if a registered tool is undocumented.
- Tool errors use stable `kind` tokens; messages are human fallback only.

**Claude coding notes:**

- Start with docs and small tests.
- Do not rename existing tools without compatibility aliases.
- Prefer additive schema changes.

## Milestone 1: Workspace And Resource Safety

**Theme:** Establish `/work` as the local filesystem contract before
writing more analysis behavior.

**Issues:**

- #5 Enforce `/work` workspace layout and output artifact contract
- #13 Add PCAP size limits and resource hardening controls
- #11 Bring Docker runtime in line with `/work` design and required helper
  tools

**Implementation order:**

1. Extend config with workspace roots:
   `workspace_root`, `pcap_dir`, `output_dir`, `tmp_dir`.
2. Default docs/examples to `/work`, `/work/pcaps`, `/work/output`,
   `/work/tmp`.
3. Resolve symlinks and reject path escapes for every root.
4. Move Zeek temp work under configured `tmp_dir`.
5. Add `max_pcap_bytes`, output disk budget, and tmp disk budget.
6. Add analyzer concurrency limits.
7. Install Docker helper tools required by the target runtime:
   `jq` and `python3` in addition to existing `tshark`, `capinfos`,
   `tcpdump`, and Zeek.
8. Add Docker smoke checks for every required binary.

**Done criteria:**

- `docker run -v ~/mcp-work:/work ...` is the canonical run shape.
- PCAP input reads are restricted to `/work/pcaps` by default.
- Output artifacts are written only under `/work/output`.
- Analyzer temp files are created only under `/work/tmp`.
- Oversized PCAPs fail before external analyzers run.
- Concurrent analyzer calls are bounded.

**Claude coding notes:**

- Keep root validation in one small package or module.
- Never let callers supply final output paths.
- Reject over-budget values; do not silently widen limits.

## Milestone 2: PCAP MCP MVP Surface

**Theme:** Land the required PCAP tools with stable names and artifacts.

**Issues:**

- #1 Structured pcap summary schema and redaction tests
- #2 Add Zeek-backed analysis image/runtime
- #6 Add required PCAP MCP tool surface and compatibility aliases
- #7 Persist versioned JSON and Markdown analysis artifacts

**Implementation order:**

1. Add stable tool names:
   `pcap_validate`, `pcap_analyze`, `pcap_filter`,
   `pcap_explain_connection`.
2. Keep existing names as compatibility aliases for one release if useful:
   `inspect_pcap`, `analyze_pcap`, `summarize_pcap`.
3. Add `schema_version` to analysis output.
4. Persist `analysis.json` and `summary.md` under `/work/output`.
5. Implement `pcap_filter` with server-generated output artifact paths.
6. Implement `pcap_explain_connection` using Zeek UID, 5-tuple, or packet
   row selector.
7. Expand redaction tests so fake secrets never appear in JSON, Markdown,
   logs, or findings.

**Done criteria:**

- Required MCP tools are registered and documented.
- JSON and Markdown artifacts are emitted with path, size, hash, content
  type, and schema version.
- Analysis output has stable top-level sections:
  `capture_summary`, `protocols`, `conversations`, `dns`, `http`, `tls`,
  `tcp_health`, `findings`, and `artifacts`.
- No raw PCAP bytes appear in tool output, and no unredacted secrets
  appear by default. ASCII string extraction is treated as sensitive
  payload-derived evidence per the privacy invariants in
  `PCAP_SERVER_CONTRACT.md`: `redact_secrets` and `include_ascii` are
  the operator switches that govern its visibility, and best-effort
  redaction is documented as best-effort, not exhaustive.

**Claude coding notes:**

- Build the tool contract first, then adapt existing implementation.
- Use structured fields; do not ask the LLM to parse tshark tables.
- Keep partial analyzer failures in `errors[]` while returning available
  evidence.

## Milestone 3: External Artifact Contract And Local Usage

**Theme:** Make local artifact inputs explicit without turning any
example producer into product behavior.

**Issues:**

- #8 Define external PCAP artifact reference contract
- #12 Document local artifact workspace usage

**Implementation order:**

1. Define artifact reference schema:
   `artifact_id`, `pcap_path`, `sha256`, `size_bytes`, optional source
   metadata, and optional producer-specific context.
2. Add validation for caller-provided artifact hash and size.
3. Document that capture acquisition, remote copy, SSH/SCP/SFTP, and
   device API behavior belong outside this repo.
4. Add `docs/WORKFLOW.md` covering local workspace setup, external
   artifact placement, PCAP analysis, and output artifacts.
5. Add troubleshooting docs for missing analyzers, path denial, invalid
   PCAP, empty capture, no matches, and truncation.

**Done criteria:**

- A pcap artifact created by any external producer can be passed to PCAP
  MCP as a local reference without raw bytes.
- Hash and size are verified locally before analysis.
- Docs explain why the LLM only sees references and summaries.
- Docs do not present any example producer as required product behavior.

**Claude coding notes:**

- Do not add capture, SSH, SCP/SFTP, or device API code to this repo.
- Treat optional producer context as untrusted metadata unless the packet
  evidence supports it.

## Milestone 4: Load-Balancer TLS Debug Profile

**Theme:** Add optional load-balancer troubleshooting without losing
generic PCAP behavior.

**Issues:**

- #4 Load-balancer packet evidence enrichment
- #9 Add `f5_ltm_tls_debug` analysis profile

**Implementation order:**

1. Add optional `analysis_profile` input.
2. Implement profile registry with only `f5_ltm_tls_debug` at first.
3. Use generic evidence to summarize:
   TCP resets, likely reset side, retransmission indicators where
   available, TLS handshake/SNI/version/cipher, HTTP status classes,
   and possible SNAT/clientside/serverside hints.
4. Add profile limitations to every profile result.
5. Accept optional external context from the artifact contract when it is
   relevant to the selected profile.

**Done criteria:**

- `analysis_profile: "f5_ltm_tls_debug"` returns a profile-specific
  section.
- Findings distinguish observed packet evidence from possible inference.
- Output never claims load-balancer config facts from packets alone.
- Tests cover reset, TLS, HTTP, and possible SNAT hints.

**Claude coding notes:**

- Keep generic analysis first-class.
- If evidence is insufficient, say unknown.
- Do not invent virtual server, pool, SNAT, policy, or profile config.

## Milestone 5: TLS Decryption Status

**Theme:** Be explicit about TLS decryption possibilities and limits.

**Issues:**

- #10 Add TLS decryption support status and SSLKEYLOGFILE workflow

**Implementation order:**

1. Add `tls_decryption` status to analysis output.
2. Add optional key-log file path input behind allowlist validation.
3. Use tshark decryption arguments only when key material is present and
   allowed.
4. Report states:
   `not_requested`, `unavailable`, `keylog_missing`, `attempted`,
   `succeeded`, `failed`.
5. Document SSLKEYLOGFILE, PFS, server-key limitations, and why many
   captures cannot be decrypted.

**Done criteria:**

- Analysis always reports whether TLS decryption was requested/possible.
- TLS metadata analysis still works when decryption fails.
- Raw decrypted payload content is not returned by default.

**Claude coding notes:**

- Key log files are sensitive artifacts.
- Do not return decrypted HTTP bodies unless a future issue designs a
  bounded/redacted shape.

## Milestone 6: CI, Smoke, And Release Hardening

**Theme:** Make the behavior reproducible for humans and agents.

**Issues:**

- #14 Add CI pipeline with real PCAP integration and failure tests

**Implementation order:**

1. Add `.gitlab-ci.yml` for `go test`, `go vet`, `make build`,
   Docker build, and Docker smoke.
2. Run integration tests in an image with packet tools available.
3. Add safe synthetic PCAP fixtures or deterministic PCAP generation.
4. Add failure cases:
   invalid PCAP, empty PCAP, no packets matched, missing analyzer,
   path outside workspace, oversized file, hash mismatch, size mismatch,
   and redaction.
5. Add `docs/PCAP_TESTS_AND_SMOKE.md` mirroring the flagship truth-table
   style.

**Done criteria:**

- CI proves the supported local runtime works.
- Packet-tool integration tests do not skip in CI.
- Test docs list exactly what is proven and what is not.

**Claude coding notes:**

- Keep fixtures synthetic and non-sensitive.
- Do not rely on host-installed tshark/Zeek for CI.

## Suggested Coding Sequence

For a coding agent, use this order:

1. Milestone 0 docs/tests for contracts.
2. Milestone 1 workspace/resource safety.
3. Milestone 2 stable PCAP tool names and artifact files.
4. Milestone 3 artifact contract/docs.
5. Milestone 6 CI basics, so later work is protected.
6. Milestone 4 load-balancer profile.
7. Milestone 5 TLS decryption status.

This sequence intentionally brings hardening and contracts forward.
Profile and TLS work should not land until the local artifact and schema
boundaries are stable.

## Review Checklist

Every merge request should answer:

1. What PCAP-analysis capability or safety boundary does this add?
2. Why does it belong in `cute-pcap-mcp` instead of the MCP host or an
   external artifact producer?
3. What tool contract changed, and where is it documented?
4. What typed error/finding tokens were added?
5. What prevents raw PCAP bytes or secrets from reaching the LLM?
6. What tests prove the new behavior?

Kick back changes that:

- make docs aspirational instead of truthful
- add host/control-plane behavior
- infer packet or producer-specific semantics from prose
- hide unknowns, partial results, or analyzer failures
- add arbitrary command execution
- return raw payload bytes or secrets
- bypass workspace/output/tmp root enforcement
