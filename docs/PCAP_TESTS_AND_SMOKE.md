# Tests And Smoke

This document is the truth table for the tests and smoke checks shipped
with `cute-pcap-mcp`. Every test row says **what is proven** and **what
is NOT proven**. CI or release automation should run these same classes
of checks; this doc says why each one exists.

## Check Classes

| Stage | Image | What it proves | What it does not prove |
| --- | --- | --- | --- |
| `lint` | `golang:1.26-bookworm` | `go vet ./...` passes — no unreachable code, no Printf format mismatches, no shadowed vars caught by vet. | Style or naming conventions; we don't run a separate linter today. |
| `unit` | `golang:1.26-bookworm` | The full Go test suite passes on a host **without** packet analyzers. Tests that require tshark / Zeek / capinfos call `requireCommand` and skip cleanly. | That tshark/Zeek behaviors are correct on real captures. The `integration` stage covers that. |
| `build` | `golang:1.26-bookworm` | `make build` produces a `bin/cute-pcap-mcp` binary; the binary's `--version` exits 0. The artifact is archived for 7 days. | That the binary runs correctly inside the Docker image. The `docker` stage covers that. |
| `release-binary` matrix | `golang:1.26-bookworm` | Each matrix job runs `make release-binaries` for one OS/arch pair and archives only that platform tarball plus `dist/checksums.txt`. | That every cross-compiled binary runs on its target OS/arch. Cross-compilation proves compilation and checksums, not runtime execution on those platforms. |
| `skill-package` matrix | `golang:1.26-bookworm` + `zip` / `unzip` | Each matrix job packages one Claude/Codex skill ZIP and verifies `SKILL.md` is at the ZIP root. | That Claude's hosted skill UI accepts a given ZIP in every future UI version. |
| `skills-bundle` | `golang:1.26-bookworm` + `zip` / `unzip` | `make skills-bundle` packages every server-local skill ZIP, then creates one convenience ZIP containing those ZIPs plus their checksum file. | That users installed every skill they need. Cross-domain skills are packaged from `lbc-mcp-workspace`; Claude still imports skill ZIPs individually. |
| `docker` | Docker Engine | The runtime image builds reproducibly. Every analyzer the runtime promises (`cute-pcap-mcp`, `tshark`, `capinfos`, `tcpdump`, `zeek`, `jq`, `python3`) resolves on PATH inside the image. `cute-pcap-mcp --version` exits 0 from the entrypoint. | That Zeek-derived sections are populated end-to-end. The `integration` stage covers that. |
| `integration` | `zeek/zeek:lts` + apt-installed `tshark` / `jq` / `python3` + downloaded Go | The full test suite **with** every integration test running (no skips). Exercises the tshark / Zeek format contract against deterministic synthetic captures. | That the runtime image's specific tshark / Zeek versions agree with `zeek/zeek:lts`. The `docker` stage covers binary presence; integration covers behavior on the LTS Zeek build. |

## What the integration stage proves end-to-end

Each test row below runs in the `integration` stage on every push.
Locally, these tests skip when the named binaries are absent.

### Generic analyze pipeline

| Test | Synthetic input | Proves |
| --- | --- | --- |
| `TestAnalyzeArtifactIntegrationWithPacketTools` | One-packet HTTP/TLS pcap from `syntheticHTTPPcap` | `pcap_analyze` populates `capture_summary`, `protocols`, `conversations`, `packets`, `dns`/`http`/`tls` from Zeek logs (when present), `ascii` with redaction. The `schema_version` is stamped. |
| `TestAnalyzeArtifactBubblesInvalidFilterToTopLevel` | Same pcap + bogus display filter | Invalid display filters from tshark surface as the typed `invalid_filter` kind in `out.Errors[]` and as a finding. They are not hidden inside the tshark sub-report. |
| `TestRunZeekReportUsesWorkspaceTmpDir` | Same pcap | Zeek's per-call workdir lands under `cfg.Workspace.TmpDir` rather than `/tmp`, honoring the workspace contract. |

### `pcap_filter`

| Test | Synthetic input | Proves |
| --- | --- | --- |
| `TestRunFilterIntegration` | One-packet HTTP pcap + `tcp.port == 80` | `pcap_filter` writes a derived pcap under `${output_dir}/<sha256_prefix>-<utc_ts>/` with the expected `OutputArtifact` shape (path / size / sha256 / content_type / schema_version / kind). |
| `TestRunFilterIntegrationProducesLegacyPCAPFormat` | Same | The derived pcap really is libpcap (`-F pcap`), not pcapng. Magic-byte check fails loudly on `0x0a0d0d0a`. |
| `TestRunFilterEnforcesOutputDiskBudget` | Same + 24-byte budget | Over-budget filtered pcaps are removed before `output_limit_reached` returns. |
| `TestRunFilterEmitsNoPacketsMatchedOnEmptyResult` | Same + UDP filter (no match) | Zero-match filters return the typed `no_packets_matched` kind and remove the empty derived pcap. |
| `TestTSharkHasAnyPacketDistinguishesEmptyFromNonEmpty` | Header-only pcap vs one-packet pcap | The probe used by `pcap_filter` to decide `no_packets_matched` is reliable on both shapes. |

### `pcap_explain_connection`

| Test | Synthetic input | Proves |
| --- | --- | --- |
| `TestExplainConnectionFiveTupleIntegration` | One-packet HTTP pcap + matching 5-tuple | The connection-scoped analyze pipeline runs, the resolved selector echo carries the constructed `display_filter`, and the `connection_evidence_scoped` finding is present. |
| `TestExplainConnectionSelectorFailureSetsIsError` | Same pcap + frame_number=999 (absent) | A selector failure surfaces as `IsError=true` on the MCP tool result, no artifacts are persisted, and the response carries a typed error kind. |

### `pcap_detect_symptoms`

| Test | Synthetic input | Proves |
| --- | --- | --- |
| `TestRunDiagnosePacketRowsIntegration` | One-packet HTTP pcap from `syntheticHTTPPcap` | The tshark field pass used by `pcap_detect_symptoms` extracts only structural packet metadata: tuple, protocol, flags, payload length counters, HTTP presence, timing, and interface tags. |
| `TestDiagnoseIntegrationDoesNotExposeSyntheticHTTPPayload` | Same pcap with secret-looking URI text | The MCP response does not expose raw HTTP payload fragments while still returning a normal symptom-detection output. |

### Profile + decryption surfaces

| Test | Synthetic input | Proves |
| --- | --- | --- |
| `TestAnalyzeArtifactIntegrationProfileFindingsSurvive` | Same pcap + `analysis_profile=f5_ltm_tls_debug` + VIP context | The dispatcher's `analysis_profile_applied` finding is merged into `out.Findings` after `buildFindings`. The unknown-name path emits `analysis_profile_unknown`. |
| `TestExplainConnectionPassesKeylogToAnalyzePipeline` | Header-only pcap + valid `tls_keylog_path` under `keylog_dir` | `pcap_explain_connection` carries `tls_keylog_path` through the synthesized `analyzeInput`; the response's `tls_decryption.status` reflects validated keylog plumbing (not `not_requested` / `keylog_invalid`). |

### Privacy and redaction

| Test | Synthetic input | Proves |
| --- | --- | --- |
| `TestNoSecretLeaksAcrossEntireResponse` | Synthetic pcap stuffed with fake `Authorization`, `Cookie`, `password=`, `token=` | None of the unredacted secret values appear in the in-memory `pcap_analyze` response, the persisted `analysis.json`, the persisted `summary.md`, or any finding message. At least one `[REDACTED]` marker is present so the test cannot pass vacuously. |
| `TestRedactSecretsFalseStillScrubsZeekHTTPURI` | Same pcap with `redact_secrets=false` | Zeek's HTTP URI redaction runs **unconditionally** — even with the operator opt-out, the `token=` URL-parameter substring stays masked in the URI section. |

## What the unit stage proves

Unit tests run without any external analyzer. They cover input
validation, the typed error taxonomy, output shape construction,
the redaction pattern table, and every always-running pure-Go
helper. The full set lives in `internal/pcap/*_test.go` and
`internal/config/*_test.go`. Highlights:

- `TestClassifyEmitsStableKinds` — pins every wire `kind` token.
- `TestRedactASCIISecretsCoversDocumentedPatterns` — pins every
  redaction pattern the contract claims (`Authorization`,
  `Cookie`, `password=`, `token=`, `api_key=`, `secret=`,
  `session_id=`, etc.).
- `TestNormalizeRejectsHiddenSubdirNestedUnderPCAPDir` — pins the
  workspace containment ratchet (`/work/pcaps/.out` is rejected,
  not silently allowed).
- `TestServerRegistersStableAndLegacyToolNames` — pins the full
  set of registered tool names; new tool registrations must
  update this test.
- `TestListPCAPArtifacts*` — pins the bounded allowlisted inventory
  surface: empty/populated roots, deterministic pagination, scan-budget
  truncation with last-scanned cursors, hash-budget omissions,
  fail-soft symlink skips, and typed caller-input validation.
- `TestToolReferenceCoversEveryRegisteredTool` /
  `TestToolReferenceRoadmapOmitsRegisteredTools` — drift ratchets
  keeping `docs/TOOL_REFERENCE.md` aligned with the registered
  tool surface.
- `TestDiagnoseV1SymptomContracts` /
  `TestDiagnoseFixtureRegistryCoversClosedVocabulary` — pin the four
  v1 closed-vocabulary wire symptoms and their positive/negative
  synthetic packet-row fixtures.
- `TestDiagnoseFailClosedValidationResponses` — pins that malformed
  symptom-detection input, path rejection, and artifact mismatch return
  normal outputs with empty `symptoms[]` and typed findings.
- `TestDiagnoseNarrativesStayVendorNeutral` /
  `TestDiagnoseOutputDoesNotExposeRawPayloadBytes` — pin the
  vendor-neutral and no-raw-payload boundaries for the detection
  surface.
- `TestF5ProfileWithoutContextRefusesToGuessSides` /
  `TestF5ProfilePortOnlyContextRefusesClientsideClaim` — pin the
  truth-over-closure boundary on the load-balancer profile.
- `TestFinalizeTLSDecryptionDoesNotPromoteOnHandshakeOnly` —
  verifies TLS keylog attempts are not promoted to `succeeded` from
  handshake visibility alone.
- `TestResolveTLSKeylogStateMachine` /
  `TestValidateTLSKeylogFileRecognizesModernLabels` — pin TLS keylog
  allowlist/path states plus secret-safe SSLKEYLOGFILE shape
  validation, including `keylog_invalid` for unusable files.
- `TestInspectArtifactRejectsHashMismatch` /
  `TestInspectArtifactRejectsSizeMismatch` /
  `TestHashMismatchMessageDoesNotEchoCallerValue` — pin the external
  artifact reference contract.

## Fixtures

`cute-pcap-mcp` does **not** ship a `testdata/pcaps/` or
`testdata/symptoms/` directory of binary fixture files. Every test
that needs a pcap synthesizes one in-memory
via `syntheticHTTPPcap`, `syntheticSecretsPcap`, or
`libpcapHeaderOnly`; `pcap_detect_symptoms` additionally uses
closed-vocabulary packet-row fixtures in `diagnoseSyntheticFixtures`.
This is deliberate:

- Fixtures generated by code are deterministic and have no risk of
  carrying real customer traffic or secrets.
- The synthesis helpers double as living documentation of the wire
  shapes the tests exercise.
- New tests can compose new fixtures (different protocols, edge-case
  packet sizes) without managing a binary-checked-in directory.

The synthesis helpers live in `internal/pcap/analyzer_test.go`
(`syntheticHTTPPcap`, `ipv4Checksum`),
`internal/pcap/redaction_integration_test.go`
(`syntheticSecretsPcap`), and `internal/pcap/filter_test.go`
(`libpcapHeaderOnly`). The wire-symptom fixtures live in
`internal/pcap/diagnose_test.go` as structural packet rows so the
ratchet can cover positive and negative symptoms without checking in
binary pcaps.

## Local invocation

```sh
# Mirror the unit / lint stages exactly:
make ci

# Mirror the cross-platform binary artifact stage:
make release-binaries

# Build only one release package:
RELEASE_PLATFORMS=darwin/arm64 make release-binaries

# Build only one skill package:
SKILLS=pcap-analysis make skills-package

# Build the server-local skills convenience ZIP:
make skills-bundle

# Mirror the docker stage:
make docker-build docker-smoke

# Run integration tests locally on a host with tshark + zeek
# installed (skipped when binaries are absent):
make integration-test
```

## What this doc does NOT prove

- Performance / throughput regressions. We don't ship a benchmark
  suite; the analyzer pipeline is bounded by `analysis.*` config and
  trades any unbounded-output bug for a typed error.
- Behavior on captures we haven't synthesized in tests (e.g. SCTP,
  GTP, vendor-proprietary encapsulations). The generic analyze
  pipeline forwards whatever tshark / Zeek emit; tests do not gate
  on those formats.
- Compatibility with companion MCP servers or any other external
  producer beyond the `ArtifactReference` shape documented in
  [`PCAP_SERVER_CONTRACT.md`](./PCAP_SERVER_CONTRACT.md).
- The runtime under every possible host architecture. The Dockerfile
  builds for the local Docker daemon's native architecture unless a
  separate multi-arch build is configured.
