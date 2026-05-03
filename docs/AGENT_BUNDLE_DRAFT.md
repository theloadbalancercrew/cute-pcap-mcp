# Agent Bundle Draft

This document is a working draft for a portable bundle standard that
works in Claude and Codex today and can later be promoted into a CuteOS
pack. It is intentionally not a pack spec. Until the first release, every
name, field, and check in this document is provisional.

The goal is to make domain automation shippable before CuteOS owns the
runtime. A bundle should be useful on its own as MCP servers, skills,
docs, and tests, while carrying enough structured metadata for CuteOS to
ingest later without rediscovering the domain boundary from prose.

## Status

- `schema_version`: `cute.agent_bundle.draft.v0`
- Stability: work in progress
- Breaking changes: allowed until a released `v1`
- Validation posture: hard-fail only on Claude/Codex usability and
  safety-critical contract issues
- CuteOS mapping: advisory hints, not binding commitments

Use this draft to shape real bundles, learn from those bundles, and then
promote only the parts that survive contact with real usage.

## Design Goals

1. **Portable first** — a valid bundle should be useful in Claude and
   Codex without CuteOS.
2. **Pack-ready later** — the same bundle should map cleanly into future
   CuteOS pack sections.
3. **Contracts over vibes** — tools, capabilities, safety boundaries,
   install steps, and evals should be checkable.
4. **Operational honesty** — unknowns, skipped checks, partial results,
   approval gates, and delayed execution states must be explicit.
5. **Low ceremony while draft** — the standard should guide authors
   without freezing product decisions too early.

## Non-Goals

- Requiring CuteOS to run the bundle.
- Requiring Temporal, OPA, or a CuteOS UI in portable bundles.
- Turning prompt text into the only source of safety policy.
- Defining a general plugin marketplace.
- Promising stable field names before a release candidate.

## Bundle Shape

A draft bundle is a directory or release artifact with a small manifest
and portable assets:

```text
bundle.wip.yaml
mcp/
skills/
docs/
evals/
contracts/
fixtures/
routines/
changes/
scripts/check-bundle
```

Not every directory is required. The minimal useful bundle has:

- one `bundle.wip.yaml`
- at least one MCP server or one skill
- install documentation for Claude and Codex
- enough checks to prove the advertised entrypoints exist

## Manifest Sketch

```yaml
schema_version: cute.agent_bundle.draft.v0
status: experimental

metadata:
  id: cute-pcap-mcp
  name: Cute PCAP MCP
  domain: packet_capture
  version: 0.1.0
  maintainers:
    - The Load Balancer Crew

compatibility:
  claude:
    mcp: true
    skills: true
  codex:
    mcp: true
    skills: true
  cuteos:
    target_pack_schema: v5
    promotion_status: candidate

entrypoints:
  mcp:
    - id: cute-pcap-mcp
      transport: stdio
      command: cute-pcap-mcp
      tool_contract: docs/TOOL_REFERENCE.md
  skills:
    - id: pcap-analysis
      path: skills/pcap-analysis
    - id: network-triage
      path: skills/network-triage

capabilities:
  - id: pcap.validate
    mcp_tool: pcap_validate
    risk_class: read_only
    mutability: none
    resources:
      - pcap_artifact
  - id: pcap.analyze
    mcp_tool: pcap_analyze
    risk_class: local_analysis
    mutability: writes_local_artifacts
    resources:
      - pcap_artifact
      - analysis_artifact

checks:
  required:
    - mcp_tools_have_contracts
    - skills_have_frontmatter
    - docs_include_claude_install
    - docs_include_codex_install
    - no_raw_secret_or_artifact_payload_outputs
  recommended:
    - evals_cover_skill_triggers
    - release_has_checksums
    - capabilities_have_cuteos_hints
```

During draft, unknown fields should be allowed with warnings. Future
CuteOS-specific experiments should live under `x_cuteos` or clearly
marked draft fields until the promotion schema settles.

## Compatibility Targets

### Claude

A Claude-compatible bundle should provide:

- MCP config snippets for the server command and arguments.
- One upload-ready skill archive per skill when skills are included.
- Skill archives with `SKILL.md` at the archive root.
- Human-readable install and uninstall instructions.
- Safety and refusal language inside the skill body or frontmatter.

### Codex

A Codex-compatible bundle should provide:

- MCP config snippets for the server command and arguments.
- Skills as directories that can be copied under the Codex skills
  directory.
- Optional Codex plugin metadata when a bundle wants a richer install
  experience.
- Local check scripts that can run without CuteOS.

### CuteOS Later

A CuteOS-ready bundle should include advisory mappings for:

- `metadata`
- `skills`
- `mcp`
- `capabilities`
- `docs`
- `tests`
- policy hints
- workflow and routine hints
- migration notes when compatibility breaks

The draft bundle does not need to provide CuteOS UI, Temporal workflow
templates, or OPA policy to be valid. Those can be added during pack
promotion.

## Capability Model

Capabilities are symbolic operations a host can reason about without
parsing skill prose. They may point to MCP tools, skill workflows, local
scripts, or future CuteOS workflows.

Suggested draft fields:

```yaml
id: pcap.filter
title: Filter a packet capture
description: Write a derived pcap from a display filter.
entrypoint:
  kind: mcp_tool
  id: pcap_filter
risk_class: local_artifact_write
mutability: writes_local_artifacts
resource_kinds:
  - pcap_artifact
  - filtered_pcap
verification:
  required: true
  method: output_artifact_hash
policy_hints:
  approval: not_required
  data_sensitivity: packet_metadata
```

Draft risk classes should be descriptive rather than final. Examples:

- `read_only`
- `local_analysis`
- `local_artifact_write`
- `external_read`
- `external_change`
- `destructive_change`

## Checks

Draft validation should report three levels:

| Level | Meaning |
| --- | --- |
| `FAIL` | The bundle cannot be safely installed or used as advertised. |
| `WARN` | The bundle works, but future CuteOS promotion is weak or unclear. |
| `INFO` | Helpful metadata or test coverage is missing. |

Initial hard failures:

- Manifest cannot be parsed.
- Declared skill path does not contain `SKILL.md`.
- Declared MCP tool lacks a contract entry.
- Claude install docs are advertised but absent.
- Codex install docs are advertised but absent.
- A mutating capability has no declared mutability or resource kind.
- A tool claims to be read-only but writes artifacts or changes external
  state.
- Known secret, credential, or raw artifact payload outputs are exposed
  without an explicit safety declaration.

Initial warnings:

- Capability has no future CuteOS mapping.
- Evals do not cover skill trigger behavior.
- Release artifact has no checksums.
- Policy hints are absent.
- Migration notes are absent for a breaking change.

## Cues: Portable Routines And Automations

CuteOS will need routines or automations: scheduled runs of a skill,
workflow, MCP tool, or capability. The draft name for these is **Cues**.

The name is intentionally small:

- A **Cue** is one scheduled or queued instruction to run.
- A **Rhythm** is a recurring Cue template, like cron with domain
  context.
- A **Run** is one execution attempt produced by a Cue.
- A **Change Cue** is an approved change waiting for its release window.

This gives us familiar operational language without forcing every host
to implement the same scheduler immediately.

### Cue Model

```yaml
id: nightly-pcap-summary
kind: cue
status: draft

schedule:
  type: cron
  expression: "0 6 * * *"
  timezone: America/New_York

target:
  kind: skill
  id: pcap-report-writer

context:
  mcp_servers:
    - cute-pcap-mcp
  allowed_capabilities:
    - pcap.validate
    - pcap.analyze

inputs:
  artifact_query:
    path_glob: /work/pcaps/*.pcapng
    max_age_hours: 24

outputs:
  mode: report
  destination: local_artifact

limits:
  max_runtime_seconds: 600
  max_runs_in_flight: 1

approval:
  required: false
```

Portable hosts can treat Cues as documentation, local scripts, or queue
records. CuteOS can later map Cues to durable schedules and workflow
executions.

### Cue Triggers

Draft trigger types:

- `manual` — created by a user or operator.
- `cron` — recurring wall-clock schedule.
- `interval` — every N minutes or hours.
- `event` — future hook for events such as new artifact, issue update,
  deploy completed, or monitor fired.
- `after_approval` — run only after an approval gate clears.
- `not_before` — run once at or after a specific time.

Cron expressions are useful, but the draft should not expose raw cron as
the only UX forever. A future CuteOS UI can render common schedules as
forms while preserving the underlying schedule.

## Scheduled Changes

Some operations should not push immediately after approval. A bundle
needs a portable model for an approved change that is queued for a
specific time or maintenance window.

The draft name is **Change Cue**.

A Change Cue separates these moments:

1. The operator proposes a change.
2. The system plans the change and records the expected target state.
3. A human or policy gate approves the exact plan.
4. The approved plan is queued for a release window.
5. At execution time, the system revalidates the plan and target state.
6. The change runs.
7. Verification runs.
8. Rollback or follow-up is triggered if verification fails.

### Change Cue State Machine

```text
draft
  -> proposed
  -> planned
  -> approved
  -> queued
  -> armed
  -> executing
  -> verifying
  -> completed

approved -> canceled
queued   -> canceled
queued   -> expired
armed    -> canceled
executing -> failed
verifying -> failed
failed -> rolled_back
```

The `armed` state means the release window has arrived and preflight
checks are passing, but the mutating operation has not yet started.

### Change Cue Sketch

```yaml
id: drain-pool-member-2026-05-07
kind: change_cue
status: queued

capability:
  id: bigip.pool_member.drain
  risk_class: external_change
  mutability: changes_managed_system

change:
  summary: Drain pool member app01 from pool_app_443.
  target:
    kind: load_balancer_pool_member
    id: bigip-a/pool_app_443/app01:443
  desired_state:
    session: user-disabled
    monitor: unchanged

approval:
  required: true
  approved_by: user@example.com
  approved_at: "2026-05-03T15:30:00-04:00"
  approved_plan_sha256: "<hash-of-plan>"

schedule:
  not_before: "2026-05-07T22:00:00-04:00"
  not_after: "2026-05-07T23:00:00-04:00"
  timezone: America/New_York

preflight:
  revalidate_plan_hash: true
  verify_target_unchanged: true
  verify_approval_not_expired: true

verification:
  required: true
  checks:
    - pool_member_state_matches
    - traffic_no_longer_selected

rollback:
  available: true
  strategy: restore_previous_state
```

The important invariant: approval applies to a specific plan. If the
plan changes after approval, the Change Cue must go back to `planned` or
`proposed`; it cannot silently execute a different operation.

## Queueing Rules

Queued work needs predictable semantics:

- Every queued Cue has an immutable requested operation payload.
- Every queued mutating Change Cue has an approved plan hash.
- Queue records include timezone-aware `not_before` and optional
  `not_after`.
- Time comparisons should use instants, while UIs may render local time.
- A queued item can be canceled before execution starts.
- A queued item can expire if the release window closes.
- Execution should re-check policy, approval freshness, target state,
  and tool availability.
- Idempotency keys should prevent duplicate execution after retries.

For normal Cues, small scheduler jitter may be acceptable. For Change
Cues, the scheduler must respect the maintenance window and should not
start early.

## CuteOS Promotion Mapping

| Draft Bundle Concept | Future CuteOS Pack Section |
| --- | --- |
| `metadata` | `metadata` |
| `skills/*/SKILL.md` | `skills` |
| `entrypoints.mcp` | `mcp` |
| `capabilities` | `capabilities` |
| `docs` | `docs` |
| `evals`, `contracts`, `fixtures` | `tests` |
| `policy_hints` | `policy` |
| `routines/*.cue.yaml` | `workflows` or schedule templates |
| `changes/*.change-cue.yaml` | `workflows` + change gates |
| `x_cuteos.ui_hints` | `ui` |
| migration notes | `migration` |

Promotion should be explicit. A bundle does not become a CuteOS pack
just because it carries hints. Promotion means CuteOS validates the
bundle, fills in missing pack-native sections, and records a migration
path from draft bundle fields to pack fields.

## Open Questions

- Should the portable manifest use YAML only, or allow JSON as a build
  output?
- Should Cues live inside the bundle, inside the host, or both?
- How much of a Change Cue can Claude or Codex safely execute without a
  CuteOS control plane?
- Should policy hints use a small portable vocabulary before mapping to
  OPA?
- Should release artifacts include a generated CuteOS promotion report?
- What is the minimum eval suite required before a bundle is listed as
  "promotion candidate"?

## Near-Term Work

For `cute-pcap-mcp`, the next practical step is to create a small
`bundle.wip.yaml` that points at the existing MCP server, skills, docs,
and evals. Then add `scripts/check-bundle` with draft checks that fail
only on install-breaking or safety-critical issues.

After that, add one or two sample Cues:

- recurring pcap analyzer status check
- daily packet-evidence report for newly added captures

Those examples will keep the standard honest without requiring CuteOS
to exist yet.
