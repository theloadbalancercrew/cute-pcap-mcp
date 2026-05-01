# Quickstart

This guide gets `cute-pcap-mcp` running as a local MCP server for
Claude, Codex, or any other MCP client that can launch a stdio command.

Docker is the preferred runtime on most machines because the image
bundles the packet tools the server needs: `capinfos`, `tshark`,
`tcpdump`, and Zeek. Native macOS works well too if those tools are
installed locally.

## What You Need

- An MCP client: Claude Desktop, Claude Code, Codex, or another client
  that supports stdio MCP servers.
- A workspace directory for packet captures and generated artifacts.
- One runtime:
  - Docker Desktop / Docker Engine, recommended on macOS, Linux, and
    Windows.
  - A native binary plus local packet tools, covered below for macOS.

The server speaks MCP over stdio. Your MCP client starts the process;
you normally do not run it as a long-lived network service.

## Workspace

Create one workspace that all configs can share.

macOS / Linux:

```sh
mkdir -p "$HOME/mcp-work"/{pcaps,output,tmp,keylogs}
```

Windows PowerShell:

```powershell
New-Item -ItemType Directory -Force `
  "$HOME\mcp-work\pcaps", `
  "$HOME\mcp-work\output", `
  "$HOME\mcp-work\tmp", `
  "$HOME\mcp-work\keylogs"
```

Put `.pcap` / `.pcapng` files under `pcaps`. Generated JSON and
Markdown analysis artifacts go under `output`. Zeek and other temporary
analyzer work uses `tmp`. Optional TLS SSLKEYLOGFILE inputs go under
`keylogs`.

Treat keylog files as secrets. They can decrypt any captured TLS
sessions whose keys they contain.

## Docker Runtime

Use Docker when you want the same analyzer behavior on every OS.

### Get The Image

For a first local setup, build the Docker image from the repo:

```sh
git clone https://github.com/theloadbalancercrew/cute-pcap-mcp.git
cd cute-pcap-mcp
make docker-build
```

Local builds produce `cute-pcap-mcp:latest`.

If a published GitHub Container Registry image is available to your
account, you can use it instead:

```sh
docker pull ghcr.io/theloadbalancercrew/cute-pcap-mcp:latest
```

### Docker Server Config

Copy the example config:

```sh
cp config.docker.example.yaml "$HOME/mcp-work/config.docker.yaml"
```

Or save this as `$HOME/mcp-work/config.docker.yaml`:

```yaml
allowed_artifact_dirs: []

workspace:
  root: /work
  pcap_dir: ""
  output_dir: ""
  tmp_dir: ""
  keylog_dir: /work/keylogs

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
```

With `workspace.root: /work`, the server reads captures from
`/work/pcaps`, writes derived artifacts to `/work/output`, and uses
`/work/tmp` for per-call analyzer temp files.

When you run through Docker, prompts and tool calls should use the
container paths (`/work/pcaps/...`, `/work/keylogs/...`), not the host
paths. The host files are visible at those container paths because of
the bind mount.

### Install The Docker Wrapper

The Docker image speaks MCP over stdin/stdout. If you run the server
without a test flag in a normal terminal, it will appear to hang while
it waits for MCP messages. Claude, Claude Code, and Codex are the
processes that should launch it.

Use the wrapper so client configs only need one command:

```sh
mkdir -p "$HOME/bin" "$HOME/mcp-work"/{pcaps,output,tmp,keylogs}
install -m 0755 scripts/cute-pcap-mcp-docker "$HOME/bin/cute-pcap-mcp-docker"
```

The wrapper is available from a repo checkout and is also included in
release archives under `scripts/cute-pcap-mcp-docker`.

The wrapper defaults to:

- image: `cute-pcap-mcp:latest`
- host workspace: `$HOME/mcp-work`
- host config: `$HOME/mcp-work/config.docker.yaml`
- container workspace: `/work`

Override those defaults with environment variables if needed:

```sh
CUTE_PCAP_MCP_IMAGE=cute-pcap-mcp:latest \
CUTE_PCAP_MCP_WORK=/Users/you/mcp-work \
CUTE_PCAP_MCP_CONFIG=/Users/you/mcp-work/config.docker.yaml \
  "$HOME/bin/cute-pcap-mcp-docker" --version
```

### Test The Docker Command

This is only a smoke test because it passes `--version`. Without
`--version`, the same command waits for an MCP host.

macOS / Linux:

```sh
"$HOME/bin/cute-pcap-mcp-docker" --version
```

If you built locally, set `CUTE_PCAP_MCP_IMAGE=cute-pcap-mcp:latest`.

Windows PowerShell:

```powershell
$IMAGE = "cute-pcap-mcp:latest"

docker run --rm -i `
  -v "$HOME\mcp-work:/work" `
  -v "$HOME\mcp-work\config.docker.yaml:/config/config.yaml:ro" `
  $IMAGE -c /config/config.yaml --version
```

## Claude With Docker

Use absolute host paths in MCP client configs. Environment variables
like `$HOME` are not expanded by every client.

The wrapper is the recommended form. It is equivalent to putting the
expanded `docker run --rm -i ...` command in `command` / `args`, but it
keeps client config small and keeps Docker mount details in one place.

### Claude Desktop

Config file locations:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux, if your build supports it: `~/.config/Claude/claude_desktop_config.json`

Example using the wrapper with the default local image:

```json
{
  "mcpServers": {
    "cute-pcap-mcp": {
      "command": "/Users/you/bin/cute-pcap-mcp-docker"
    }
  }
}
```

If you need non-default paths or a local image, set environment values:

```json
{
  "mcpServers": {
    "cute-pcap-mcp": {
      "command": "/Users/you/bin/cute-pcap-mcp-docker",
      "env": {
        "CUTE_PCAP_MCP_IMAGE": "cute-pcap-mcp:latest",
        "CUTE_PCAP_MCP_WORK": "/Users/you/mcp-work",
        "CUTE_PCAP_MCP_CONFIG": "/Users/you/mcp-work/config.docker.yaml"
      }
    }
  }
}
```

On Windows, use the raw Docker form and escape backslashes in JSON:

```json
{
  "mcpServers": {
    "cute-pcap-mcp": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "-v",
        "C:\\Users\\you\\mcp-work:/work",
        "-v",
        "C:\\Users\\you\\mcp-work\\config.docker.yaml:/config/config.yaml:ro",
        "cute-pcap-mcp:latest",
        "-c",
        "/config/config.yaml"
      ]
    }
  }
}
```

Restart Claude after changing its MCP config.

### Claude Code

Claude Code can use project-scoped MCP config. Save this as `.mcp.json`
in the repo or workspace where you run Claude Code:

```json
{
  "mcpServers": {
    "cute-pcap-mcp": {
      "command": "/Users/you/bin/cute-pcap-mcp-docker"
    }
  }
}
```

Alternatively, add it from the CLI:

```sh
claude mcp add cute-pcap-mcp -- /Users/you/bin/cute-pcap-mcp-docker
```

## Codex With Docker

Codex reads MCP servers from `~/.codex/config.toml` on macOS/Linux
and `%USERPROFILE%\.codex\config.toml` on Windows.

Add:

```toml
[mcp_servers.cute-pcap-mcp]
command = "/Users/you/bin/cute-pcap-mcp-docker"
```

For a local Docker image, replace the image with
`cute-pcap-mcp:latest` by setting `CUTE_PCAP_MCP_IMAGE` in the
environment used to launch Codex.

Or add it from the CLI:

```sh
codex mcp add cute-pcap-mcp -- /Users/you/bin/cute-pcap-mcp-docker
```

## Native macOS Runtime

Native macOS is handy for local lab work and packet-capture iteration.
You still need the analyzer tools on PATH.

### Install Tools

Install Homebrew if needed:

```sh
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Install packet tools:

```sh
brew install wireshark zeek
```

Optional, for creating TLS SSLKEYLOGFILE captures with curl:

```sh
brew install curl
```

Verify the analyzers:

```sh
command -v capinfos tshark zeek
capinfos --version
tshark --version
zeek --version
```

### Install The Binary

From a release archive, choose the archive for your Mac:

- Apple Silicon: `cute-pcap-mcp-darwin-arm64.tar.gz`
- Intel Mac: `cute-pcap-mcp-darwin-amd64.tar.gz`

You only need the archive for your CPU architecture. For most modern
Macs, that is the Apple Silicon `darwin-arm64` package.

```sh
tar -xzf cute-pcap-mcp-darwin-arm64.tar.gz
install -m 0755 cute-pcap-mcp-darwin-arm64/cute-pcap-mcp /usr/local/bin/cute-pcap-mcp
```

Or build from source:

```sh
git clone https://github.com/theloadbalancercrew/cute-pcap-mcp.git
cd cute-pcap-mcp
make build
./bin/cute-pcap-mcp --version
```

### Native Server Config

Save this as `$HOME/mcp-work/config.native.yaml` and change the paths
if your workspace lives somewhere else:

```yaml
allowed_artifact_dirs: []

workspace:
  root: /Users/you/mcp-work
  pcap_dir: ""
  output_dir: ""
  tmp_dir: ""
  keylog_dir: /Users/you/mcp-work/keylogs

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
```

Test the binary:

```sh
cute-pcap-mcp -c "$HOME/mcp-work/config.native.yaml" --version
```

If you built from source and did not install into `/usr/local/bin`, use
the repo binary path:

```sh
/Users/you/src/cute-pcap-mcp/bin/cute-pcap-mcp -c "$HOME/mcp-work/config.native.yaml" --version
```

## Claude With Native macOS

Claude Desktop config:

```json
{
  "mcpServers": {
    "cute-pcap-mcp": {
      "command": "/usr/local/bin/cute-pcap-mcp",
      "args": [
        "-c",
        "/Users/you/mcp-work/config.native.yaml"
      ]
    }
  }
}
```

Claude Code project `.mcp.json`:

```json
{
  "mcpServers": {
    "cute-pcap-mcp": {
      "command": "/usr/local/bin/cute-pcap-mcp",
      "args": [
        "-c",
        "/Users/you/mcp-work/config.native.yaml"
      ]
    }
  }
}
```

Restart Claude after updating the config.

## Codex With Native macOS

Add this to `~/.codex/config.toml`:

```toml
[mcp_servers.cute-pcap-mcp]
command = "/usr/local/bin/cute-pcap-mcp"
args = ["-c", "/Users/you/mcp-work/config.native.yaml"]
```

If you run from a source checkout:

```toml
[mcp_servers.cute-pcap-mcp]
command = "/Users/you/src/cute-pcap-mcp/bin/cute-pcap-mcp"
args = ["-c", "/Users/you/mcp-work/config.native.yaml"]
cwd = "/Users/you/src/cute-pcap-mcp"
```

Or add it from the CLI:

```sh
codex mcp add cute-pcap-mcp -- /usr/local/bin/cute-pcap-mcp \
  -c /Users/you/mcp-work/config.native.yaml
```

Restart Codex after updating `~/.codex/config.toml`.

## First Test

Copy a capture into the workspace:

```sh
cp sample.pcap "$HOME/mcp-work/pcaps/sample.pcap"
```

In Claude or Codex, ask:

```text
Use cute-pcap-mcp to run pcap_analyzer_status.
Then validate the capture path for my runtime:
- Docker: /work/pcaps/sample.pcap
- Native macOS: /Users/you/mcp-work/pcaps/sample.pcap
Then analyze it with max_packet_rows=50 and write_artifacts=true.
Summarize only packet evidence returned by the tool; do not guess.
```

For Docker on Windows, still use the container path in the prompt:

```text
Validate /work/pcaps/sample.pcap, then analyze it.
```

The server normalizes and allowlist-checks paths before analysis.

## TLS Decryption Test

TLS decryption requires an SSL key log captured from the client that
created the TLS sessions. The server will not crack TLS from packet
bytes alone.

With Homebrew curl on macOS:

```sh
KEYLOG="$HOME/mcp-work/keylogs/curl.keys"
: > "$KEYLOG"
chmod 600 "$KEYLOG"

SSLKEYLOGFILE="$KEYLOG" /opt/homebrew/opt/curl/bin/curl \
  --http1.1 \
  https://example.com/ \
  -o /dev/null
```

Capture the matching traffic while that curl command runs, then ask the
client:

```text
Use cute-pcap-mcp to analyze the capture path for my runtime:
- Docker: /work/pcaps/tls-test.pcap
- Native macOS: /Users/you/mcp-work/pcaps/tls-test.pcap
Use the tls_keylog_path for my runtime:
- Docker: /work/keylogs/curl.keys
- Native macOS: /Users/you/mcp-work/keylogs/curl.keys
Use display_filter="tls || http" and max_packet_rows=100.
Tell me whether any HTTP request or response packet rows prove decrypted TLS evidence.
```

Current behavior is conservative: `tls_decryption.status: attempted`
means the keylog was passed to tshark and Zeek without subprocess
errors. It does not by itself prove any session was decrypted. Look for
decrypted `HTTP` / `HTTP2` packet rows or Zeek HTTP records in the
bounded evidence.

## Troubleshooting

`MCP server disconnected`

- Run the exact `command` plus `args` from your client config in a
  terminal with `--version`. If that fails, fix the command path,
  Docker image name, or config path first.

`path_outside_allowlist`

- The pcap is not under `workspace.pcap_dir` or another configured
  allowlisted directory. Put captures under `mcp-work/pcaps`.

`analyzer_unavailable`

- Native runtime: install `tshark`, `capinfos`, and Zeek and make sure
  they are on PATH.
- Docker runtime: rebuild or pull the current image.

No DNS / HTTP / TLS summaries

- Zeek may be missing, failed, or the capture may not contain those
  protocols. Run `pcap_analyzer_status` first and check `errors[]` in
  the analysis response.

Docker mount errors on Windows

- Use absolute Windows paths in the JSON/TOML config, and keep the
  `:/work` container suffix. In JSON, escape backslashes.

After replacing the binary

- Restart the MCP client. Running Claude/Codex sessions do not reload a
  server binary that has already been started.
