# PCAP Skills

This repository includes portable `SKILL.md` files for packet-capture
workflows around `cute-pcap-mcp`. The MCP server provides the facts; the
skills provide the operating rhythm an agent should follow. The user
usually does not read the skill directly; the skill helps the agent
print the right how-to, ask the right follow-up, and call the right MCP
tool at the right time.

## Included Skills

- `pcap-analysis`: default workflow for analyzing pcap/pcapng evidence.
- `network-triage`: turns a vague network problem into evidence,
  captures, or MCP analysis.
- `capture-planning`: tcpdump and traffic-generation recipes.
- `tls-decryption`: SSLKEYLOGFILE workflow and decryption limits.
- `load-balancer-path-debug`: clientside/serverside path analysis for
  VIPs, pool members, SNAT, resets, and proxy paths.
- `pcap-report-writer`: narrow report writer that only triggers when
  report/write-up language appears with packet-capture evidence.

Each skill is a small package. Besides `SKILL.md`, skills may include:

- `agents/openai.yaml`: UI-facing display metadata.
- `assets/`: lightweight icons or other packaged assets.
- `references/`: optional detail the agent reads only when needed.
- `scripts/`: deterministic helpers for repeatable command generation
  or secret-safe summaries.

The repository also includes `evals/pcap-skill-triggers.yaml`, a small
set of prompt/expected-skill cases to help tune frontmatter as real usage
comes in.

## Installing For Codex

Copy the skill directories into your Codex skills directory:

```sh
mkdir -p "$HOME/.codex/skills"
cp -R skills/* "$HOME/.codex/skills/"
```

Restart Codex after installing or updating skills.

## Installing For Claude

Claude's skill upload flow expects a ZIP for one skill at a time, with
`SKILL.md` at the ZIP root. Do not upload the entire repo or a single
ZIP containing all skill directories unless your Claude UI explicitly
supports bulk imports.

Build upload-ready ZIPs locally:

```sh
make skills-package
ls dist/skills/
```

Upload the ZIPs you want from `dist/skills/` in Claude's Skills
customization screen. Each archive is named after the skill, for
example `pcap-analysis.zip` or `network-triage.zip`.

To build one convenience archive that contains all of the individual
skill ZIPs plus their checksum file:

```sh
make skills-bundle
ls dist/cute-pcap-mcp-skills-*.zip
```

Upload the inner skill ZIPs from that bundle in Claude's Skills
customization screen.

Release assets publish each skill ZIP individually and also publish the
all-skills bundle. Download only the individual skill archive you want,
or download the bundle when you want all of them at once.

For Claude Code projects that do not use skills directly, the same
workflow text can still be referenced from project instructions, but
skills are preferred because the frontmatter descriptions let the model
load the right workflow only when the user's prompt calls for it.

## Trigger Philosophy

The descriptions are intentionally task-oriented:

- `network-triage` can trigger from natural language like "the app is
  timing out."
- `pcap-analysis` triggers when a capture or packet evidence is already
  present.
- `pcap-report-writer` is intentionally narrow. It requires both report
  language and pcap/trace/tcpdump/Wireshark/packet language so it does
  not steal unrelated writing tasks.

As real usage accumulates, tune the frontmatter descriptions first.
That is usually enough to improve when a skill is loaded without
changing the body.

The skills are intended to make the agent print useful next steps, not
to replace the conversation. For example, when a user says "my app is
slow" and has no capture yet, `network-triage` should lead the agent to
ask for the missing endpoint details, print an appropriate tcpdump
command, tell the user where to copy the file in `mcp-work/pcaps`, and
give the follow-up prompt for analysis.
