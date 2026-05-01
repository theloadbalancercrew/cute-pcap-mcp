# Container Runtime

Docker is the preferred runtime for most operators because packet
analysis tooling is noisy to install consistently across macOS, Linux,
and Windows.

The image includes:

- `cute-pcap-mcp`
- `capinfos`
- `tshark`
- `tcpdump`
- `zeek`
- `jq`
- `python3`

A Docker `RUN` step in the build verifies each binary is on PATH; the
image fails to build if any are missing.

The runtime image is based on the official Zeek LTS container image and
installs Wireshark CLI tooling on top of it. Override the Zeek base image
when needed:

```sh
docker build --build-arg ZEEK_IMAGE=zeek/zeek:latest -t cute-pcap-mcp:latest .
```

The local development tag is `cute-pcap-mcp:latest`. Release automation
can also publish `ghcr.io/theloadbalancercrew/cute-pcap-mcp:<tag>` when
GitHub Container Registry publishing is enabled for the repo.

## Workspace layout

The container image creates an empty `/work` layout owned by the
non-root runtime user:

```text
/work/pcaps     # input pcap/pcapng files (read-only mount recommended)
/work/output    # derived JSON / Markdown analysis artifacts
/work/tmp       # per-call analyzer temp work (e.g. Zeek workdirs)
```

The canonical run shape is a single bind-mount of an operator-owned
workspace directory at `/work`:

```sh
mkdir -p ~/bin ~/mcp-work/{pcaps,output,tmp,keylogs}
cp config.docker.example.yaml ~/mcp-work/config.docker.yaml
install -m 0755 scripts/cute-pcap-mcp-docker ~/bin/cute-pcap-mcp-docker
CUTE_PCAP_MCP_IMAGE=cute-pcap-mcp:latest ~/bin/cute-pcap-mcp-docker --version
```

The `--version` call is a smoke test. Without a test flag, the process
waits for MCP messages on stdin/stdout and should be launched by Claude,
Codex, or another MCP host. `config.docker.example.yaml` sets
`workspace.root: /work` and relies on the per-subdir defaults.

If you need to keep the input mount strictly read-only, mount
`pcaps` separately:

```sh
docker run --rm -i \
  -v "$HOME/mcp-work/config.docker.yaml:/config/config.yaml:ro" \
  -v "$PWD/captures:/work/pcaps:ro" \
  -v "$HOME/mcp-work-out:/work/output" \
  -v "$HOME/mcp-work-tmp:/work/tmp" \
  cute-pcap-mcp:latest -c /config/config.yaml --version
```

## Zeek runtime

`cute-pcap-mcp` ships **one** image variant. Zeek is included by
default — the runtime is built FROM the Zeek upstream LTS image and
adds the Wireshark CLI tools and the Go binary on top. There is no
"core" image without Zeek, and no separate "with-Zeek" variant.

Why: the analyze pipeline emits structured DNS / HTTP / TLS evidence
from `conn.log`, `dns.log`, `http.log`, `ssl.log`, etc. Without Zeek
those sections of the response are nil, which would surprise hosts
that switched on the `pcap_analyze` schema. Bundling Zeek keeps the
image self-contained and makes the model-facing contract honest about
what comes back.

### Version policy

The base image tag is controlled by the `ZEEK_IMAGE` build arg, set
to `zeek/zeek:lts` by default (see [`Dockerfile`](../Dockerfile)).
The `lts` tag tracks Zeek's long-term-support stream — currently
the 8.x line — and floats forward as Zeek's LTS branches advance.
Operators who need to pin a specific Zeek version (for reproducibility
in regulated environments, for instance) can override at build time:

```sh
docker build --build-arg ZEEK_IMAGE=zeek/zeek:8.1.1 -t cute-pcap-mcp:latest .
```

The Dockerfile's `RUN`-time smoke check (see the [Smoke check](#)
section above) verifies that `zeek` resolves on PATH after the apt
install step, so a build that produces an image without Zeek fails
loudly at build time rather than silently at first MCP call.

### Local fallback

When the image is not used (operator runs the host binary directly),
Zeek must be installed on the host PATH for `pcap_analyze` to populate
`dns` / `http` / `tls` / `notices` / `weird_events` / `tcp_health`
sections. If Zeek is missing the analyze response still returns
capinfos, tshark, and ASCII evidence; the missing analyzer surfaces
as a typed `analyzer_unavailable` entry in `errors[]` and the
affected sections are absent rather than empty.

`pcap_analyzer_status` reports the local availability of each
analyzer; orchestration can branch on that before requesting an
analysis that needs Zeek-derived sections.

## Stdio only

The server speaks MCP over stdio. Do not expose it as an unauthenticated
network service.
