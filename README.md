# cute-pcap-mcp

`cute-pcap-mcp` is an MCP server for redacted packet-capture analysis
using `tshark` and Zeek, designed to compose with `cute-bigip-mcp` and
other capture producers. It accepts local pcap/pcapng artifacts from
allowlisted directories, runs bounded analysis with packet tooling such
as `capinfos`, `tshark`, and Zeek, and returns structured evidence that
an LLM can reason over.

The main tool, `pcap_analyze`, returns:

- artifact metadata and SHA-256
- `capinfos` capture metadata
- `tshark` protocol hierarchy, conversations, and packet rows
- parsed Zeek logs such as `conn.log`, `dns.log`, `http.log`, `ssl.log`,
  `files.log`, `weird.log`, and whatever else Zeek emits
- derived summaries for connections, DNS, HTTP, TLS, Zeek notices, and
  weird events
- bounded printable ASCII strings found in the capture file, with common
  credential/token patterns redacted by default

It is designed to consume local artifacts created by humans, scripts, or
other MCP servers without knowing how those captures were acquired:

```text
External producer writes a pcap under an allowlisted local directory.
cute-pcap-mcp analyzes that local path and returns bounded evidence.
The MCP client / LLM passes references, never raw pcap bytes.
```

## Quick Start

This path assumes you have never run an MCP server before. It installs a
release binary, creates a workspace, writes a config file, then shows the
Claude and Codex settings to paste.

### 1. Download The Right File

Open the [Releases page](https://github.com/theloadbalancercrew/cute-pcap-mcp/releases)
and download the newest package for your OS and CPU:

| Machine | Download |
| --- | --- |
| Modern Mac / Apple Silicon | `cute-pcap-mcp-darwin-arm64.tar.gz` |
| Intel Mac | `cute-pcap-mcp-darwin-amd64.tar.gz` |
| Linux x86_64 | `cute-pcap-mcp-linux-amd64.tar.gz` |
| Linux ARM64 | `cute-pcap-mcp-linux-arm64.tar.gz` |
| Windows x86_64 | `cute-pcap-mcp-windows-amd64.tar.gz` |
| Windows ARM64 | `cute-pcap-mcp-windows-arm64.tar.gz` |

Also download `cute-pcap-mcp-skills-<version>.zip` if you want the
Claude/Codex helper skills. That bundle contains individual skill ZIPs.

Native installs need packet tools on the same machine. On macOS:

```sh
brew install wireshark zeek
```

On Windows, native analysis needs `tshark` / `capinfos` from Wireshark
and Zeek on `PATH`. If that is annoying, use Docker instead; the Docker
image bundles the packet tools. Full Docker setup lives in
[`docs/QUICKSTART.md`](docs/QUICKSTART.md).

### 2. Install The Binary And Config

The examples below use `~/mcp-work` as a shared MCP workspace. The
important convention is `~/mcp-work/pcaps`: other MCP servers and local
capture scripts can write `.pcap` / `.pcapng` files there, and
`cute-pcap-mcp` can read them without extra path juggling.

macOS / Linux shell:

```sh
# Change this if you downloaded a different release or platform.
VERSION="v1.0.0"
ARCHIVE="cute-pcap-mcp-darwin-arm64.tar.gz"

WORK="$HOME/mcp-work"
BASE_URL="https://github.com/theloadbalancercrew/cute-pcap-mcp/releases/download/$VERSION"

mkdir -p "$WORK"/{bin,downloads,pcaps,output,tmp,keylogs}
curl -L "$BASE_URL/$ARCHIVE" -o "$WORK/downloads/$ARCHIVE"
tar -xzf "$WORK/downloads/$ARCHIVE" -C "$WORK/downloads"

DIR_NAME="${ARCHIVE%.tar.gz}"
install -m 0755 "$WORK/downloads/$DIR_NAME/cute-pcap-mcp" "$WORK/bin/cute-pcap-mcp"

cat > "$WORK/config.yaml" <<YAML
allowed_artifact_dirs: []

workspace:
  root: $WORK
  pcap_dir: ""
  output_dir: ""
  tmp_dir: ""
  keylog_dir: $WORK/keylogs

analysis:
  command_timeout_seconds: 20
  max_stdout_bytes: 200000
  max_packet_rows: 200
  max_ascii_strings: 200
  max_ascii_bytes: 200000
  max_zeek_records_per_log: 100
  max_pcap_bytes: 1073741824
  max_concurrent_analyses: 2
  tmp_disk_budget_bytes: 536870912
  output_disk_budget_bytes: 268435456
YAML

"$WORK/bin/cute-pcap-mcp" -c "$WORK/config.yaml" --version
```

Windows PowerShell:

```powershell
# Change this if you downloaded a different release or platform.
$Version = "v1.0.0"
$Archive = "cute-pcap-mcp-windows-amd64.tar.gz"

$Work = Join-Path $HOME "mcp-work"
$BaseUrl = "https://github.com/theloadbalancercrew/cute-pcap-mcp/releases/download/$Version"

New-Item -ItemType Directory -Force `
  "$Work\bin", `
  "$Work\downloads", `
  "$Work\pcaps", `
  "$Work\output", `
  "$Work\tmp", `
  "$Work\keylogs" | Out-Null

Invoke-WebRequest -Uri "$BaseUrl/$Archive" -OutFile "$Work\downloads\$Archive"
tar -xzf "$Work\downloads\$Archive" -C "$Work\downloads"

$DirName = $Archive -replace '\.tar\.gz$', ''
Copy-Item "$Work\downloads\$DirName\cute-pcap-mcp.exe" "$Work\bin\cute-pcap-mcp.exe" -Force

$YamlWork = ($Work -replace '\\', '/')
@"
allowed_artifact_dirs: []

workspace:
  root: $YamlWork
  pcap_dir: ""
  output_dir: ""
  tmp_dir: ""
  keylog_dir: $YamlWork/keylogs

analysis:
  command_timeout_seconds: 20
  max_stdout_bytes: 200000
  max_packet_rows: 200
  max_ascii_strings: 200
  max_ascii_bytes: 200000
  max_zeek_records_per_log: 100
  max_pcap_bytes: 1073741824
  max_concurrent_analyses: 2
  tmp_disk_budget_bytes: 536870912
  output_disk_budget_bytes: 268435456
"@ | Set-Content -Encoding UTF8 "$Work\config.yaml"

& "$Work\bin\cute-pcap-mcp.exe" -c "$Work\config.yaml" --version
```

The server speaks MCP over stdin/stdout. Running it without `--version`
is not a normal interactive command; it waits for Claude or Codex to
send MCP messages.

Put packet captures in `~/mcp-work/pcaps`. Generated reports and
JSON artifacts go under `~/mcp-work/output`; temp files stay under
`~/mcp-work/tmp`; TLS key logs can go under `~/mcp-work/keylogs`.

### 3. Add The Server To Claude

Claude Desktop config file locations:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

macOS / Linux example:

```json
{
  "mcpServers": {
    "cute-pcap-mcp": {
      "command": "/Users/you/mcp-work/bin/cute-pcap-mcp",
      "args": [
        "-c",
        "/Users/you/mcp-work/config.yaml"
      ]
    }
  }
}
```

Windows example:

```json
{
  "mcpServers": {
    "cute-pcap-mcp": {
      "command": "C:\\Users\\you\\mcp-work\\bin\\cute-pcap-mcp.exe",
      "args": [
        "-c",
        "C:\\Users\\you\\mcp-work\\config.yaml"
      ]
    }
  }
}
```

Replace `you` with your username. Restart Claude after saving this
config. MCP servers are launched when Claude starts, so changing the
binary or config usually requires a restart.

### 4. Install Claude Skills

Download `cute-pcap-mcp-skills-<version>.zip` from the
[Releases page](https://github.com/theloadbalancercrew/cute-pcap-mcp/releases)
and unzip it. The extracted files are individual skill ZIPs such as
`pcap-analysis.zip`, `network-triage.zip`, and `capture-planning.zip`.

In Claude:

1. Open **Customize**.
2. Open **Skills**.
3. Click **+**.
4. Click **Upload**.
5. Drag and drop the individual skill ZIPs, or select all of them from
   the unzipped bundle.

Restart Claude after installing or updating skills.

### 5. Add The Server To Codex

Codex reads MCP servers from `~/.codex/config.toml` on macOS/Linux and
`%USERPROFILE%\.codex\config.toml` on Windows.

macOS / Linux:

```toml
[mcp_servers.cute-pcap-mcp]
command = "/Users/you/mcp-work/bin/cute-pcap-mcp"
args = ["-c", "/Users/you/mcp-work/config.yaml"]
```

Windows:

```toml
[mcp_servers.cute-pcap-mcp]
command = "C:\\Users\\you\\mcp-work\\bin\\cute-pcap-mcp.exe"
args = ["-c", "C:\\Users\\you\\mcp-work\\config.yaml"]
```

Restart Codex after changing `config.toml`.

To install the skills for Codex from the all-skills bundle, unzip the
bundle and then extract each inner skill ZIP under `~/.codex/skills`.

macOS / Linux:

```sh
VERSION="v1.0.0"
WORK="$HOME/mcp-work"
BASE_URL="https://github.com/theloadbalancercrew/cute-pcap-mcp/releases/download/$VERSION"
SKILLS_BUNDLE="cute-pcap-mcp-skills-$VERSION.zip"

rm -rf "$WORK/downloads/skills"
mkdir -p "$HOME/.codex/skills" "$WORK/downloads/skills"
curl -L "$BASE_URL/$SKILLS_BUNDLE" -o "$WORK/downloads/$SKILLS_BUNDLE"
unzip -q "$WORK/downloads/$SKILLS_BUNDLE" -d "$WORK/downloads/skills"

for zip in "$WORK/downloads/skills"/*.zip; do
  name="$(basename "$zip" .zip)"
  rm -rf "$HOME/.codex/skills/$name"
  mkdir -p "$HOME/.codex/skills/$name"
  unzip -q "$zip" -d "$HOME/.codex/skills/$name"
done
```

Windows PowerShell:

```powershell
$Version = "v1.0.0"
$Work = Join-Path $HOME "mcp-work"
$BaseUrl = "https://github.com/theloadbalancercrew/cute-pcap-mcp/releases/download/$Version"
$SkillsBundle = "cute-pcap-mcp-skills-$Version.zip"
$SkillRoot = Join-Path $HOME ".codex\skills"
$Downloads = Join-Path $Work "downloads"
$SkillDownloads = Join-Path $Work "downloads\skills"

Remove-Item $SkillDownloads -Recurse -Force -ErrorAction SilentlyContinue
New-Item -Path $SkillRoot, $Downloads, $SkillDownloads -ItemType Directory -Force | Out-Null
Invoke-WebRequest -Uri "$BaseUrl/$SkillsBundle" -OutFile "$Work\downloads\$SkillsBundle"
Expand-Archive "$Work\downloads\$SkillsBundle" `
  -DestinationPath $SkillDownloads `
  -Force

Get-ChildItem $SkillDownloads -Filter "*.zip" | ForEach-Object {
  $Name = [IO.Path]::GetFileNameWithoutExtension($_.Name)
  $Dest = Join-Path $SkillRoot $Name
  Remove-Item $Dest -Recurse -Force -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force $Dest | Out-Null
  Expand-Archive $_.FullName -DestinationPath $Dest -Force
}
```

Restart Codex after installing or updating skills.

### 6. First Test Prompt

Copy a small `.pcap` or `.pcapng` file into `~/mcp-work/pcaps`, then ask
Claude or Codex. Use the real path for your OS:

```text
Use cute-pcap-mcp to run pcap_analyzer_status.
Then validate this capture:
- macOS: /Users/you/mcp-work/pcaps/sample.pcap
- Linux: /home/you/mcp-work/pcaps/sample.pcap
- Windows: C:\Users\you\mcp-work\pcaps\sample.pcap
Then analyze it with max_packet_rows=50 and write_artifacts=true.
Summarize only packet evidence returned by the tool; do not guess.
```

More detailed Docker, Claude Code, Codex, and native setup examples live
in [`docs/QUICKSTART.md`](docs/QUICKSTART.md).

See `docs/ARCHITECTURE.md` for the product boundary and
`docs/QUICKSTART.md` for Docker/native setup with Claude and Codex.
See `docs/CONTAINER.md` for the Docker runtime. See `docs/WORKFLOW.md`
for the operator walkthrough — workspace setup, ArtifactReference
exchange shape, orchestration flow, and a troubleshooting table. See
`docs/ROADMAP.md` for product boundaries and future work. The
model-facing contract lives in `docs/TOOL_REFERENCE.md` (per-tool
input/output/error sets) and `docs/PCAP_SERVER_CONTRACT.md` (wire
shapes, error taxonomy, finding codes, and privacy invariants). The
CI truth table lives in `docs/PCAP_TESTS_AND_SMOKE.md`. Adjacent
agent workflow skills live in `skills/`; see `docs/SKILLS.md`.

## Tools

Stable names (use these in new orchestration):

- `pcap_validate`: validate an allowlisted pcap/pcapng and return
  artifact metadata.
- `pcap_analyze`: full analysis pipeline with capinfos, tshark, Zeek,
  bounded ASCII extraction, derived summaries, and persisted JSON +
  Markdown artifacts.
- `pcap_filter`: write a filtered pcap under `workspace.output_dir`
  from a tshark display filter; returns an `OutputArtifact` reference.
- `pcap_explain_connection`: scope the analyze pipeline to one
  connection identified by `zeek_uid`, `five_tuple`, or
  `frame_number`.
- `pcap_analyzer_status`: report local availability and versions for
  `capinfos`, `tshark`, and Zeek.

Legacy aliases (kept registered for one release; migrate to the
stable names above):

- `inspect_pcap` → alias of `pcap_validate`.
- `analyze_pcap` → alias of `pcap_analyze`.
- `summarize_pcap` → tshark-only protocol hierarchy preview.

`pcap_analyze` supports per-call output limits and switches such as
`max_packet_rows`, `max_ascii_strings`, `max_ascii_bytes`,
`max_zeek_records_per_log`, `min_string_length`, `display_filter`,
`include_capinfos`, `include_tshark`, `include_zeek`, `include_ascii`,
`redact_secrets`, and `write_artifacts`.
