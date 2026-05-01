package pcap

// Mechanical alignment ratchet: every tool the PCAP MCP server actually
// registers must appear in docs/TOOL_REFERENCE.md. New tools land in
// this doc with their implementation; if a future change adds a
// registered tool but forgets the docs update, this test fails so the
// contract reference can never silently describe a stale surface.
//
// The check is intentionally narrow: it asserts each registered tool
// name appears as a `### \`<tool_name>\`` section header in the doc.
// Per-tool body content is the author's responsibility — this test
// cannot verify any of that.
//
// The reverse direction (every doc section corresponds to a registered
// tool) is also checked so that the doc cannot describe unshipped
// tools as current behavior. The "What's NOT shipped (today)" section
// is excluded from the reverse check via an explicit fence.

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"cute-pcap-mcp/internal/config"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const roadmapFence = "## What's NOT shipped (today)"

func TestToolReferenceCoversEveryRegisteredTool(t *testing.T) {
	registered := registeredToolNames(t)
	documented := documentedToolNames(t)

	missingFromDoc := setDiff(registered, documented)
	if len(missingFromDoc) > 0 {
		t.Errorf("docs/TOOL_REFERENCE.md is missing tool sections for: %v\nAdd a `### `<tool_name>`` section per tool that the server registers.", missingFromDoc)
	}

	extraInDoc := setDiff(documented, registered)
	if len(extraInDoc) > 0 {
		t.Errorf("docs/TOOL_REFERENCE.md describes tools the server does NOT register: %v\nMove these to the %q section if they are roadmap, or remove the section if they are not planned.", extraInDoc, roadmapFence)
	}
}

// TestToolReferenceRoadmapOmitsRegisteredTools is the same drift
// surface companion repos guard against: a registered tool name must
// not also appear in the roadmap fence as if it were unshipped.
// Backtick-quoted snake_case tokens below the fence are matched.
func TestToolReferenceRoadmapOmitsRegisteredTools(t *testing.T) {
	registered := registeredToolNames(t)
	roadmapMentions := roadmapToolNameMentions(t)

	registeredSet := map[string]bool{}
	for _, n := range registered {
		registeredSet[n] = true
	}
	var leaked []string
	for _, name := range roadmapMentions {
		if registeredSet[name] {
			leaked = append(leaked, name)
		}
	}
	if len(leaked) > 0 {
		sort.Strings(leaked)
		t.Errorf(
			"docs/TOOL_REFERENCE.md roadmap section names tools that ARE registered today: %v\nThe %q fence is for unshipped tools only.",
			leaked, roadmapFence)
	}
}

func registeredToolNames(t *testing.T) []string {
	t.Helper()

	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{t.TempDir()},
	})
	if err != nil {
		t.Fatalf("config.Normalize: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	serverTransport, clientTransport := mcp.NewInMemoryTransports()

	server := NewServer(cfg, ServerOptions{Logger: slog.New(slog.NewTextHandler(discardWriter{}, nil))})
	go func() {
		_ = server.Run(ctx, serverTransport)
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	var names []string
	for tool, err := range session.Tools(ctx, nil) {
		if err != nil {
			t.Fatalf("session.Tools: %v", err)
		}
		names = append(names, tool.Name)
	}
	sort.Strings(names)
	return names
}

func documentedToolNames(t *testing.T) []string {
	t.Helper()
	src := readToolReference(t)
	if i := strings.Index(src, roadmapFence); i != -1 {
		src = src[:i]
	}
	pattern := regexp.MustCompile("(?m)^###\\s+`([a-z_]+)`")
	matches := pattern.FindAllStringSubmatch(src, -1)
	seen := map[string]bool{}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		name := m[1]
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func roadmapToolNameMentions(t *testing.T) []string {
	t.Helper()
	src := readToolReference(t)
	idx := strings.Index(src, roadmapFence)
	if idx == -1 {
		return nil
	}
	below := src[idx:]
	pattern := regexp.MustCompile("`([a-z_]+)`")
	matches := pattern.FindAllStringSubmatch(below, -1)
	seen := map[string]bool{}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		name := m[1]
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

func readToolReference(t *testing.T) string {
	t.Helper()
	root := findRepoRoot(t)
	path := filepath.Join(root, "docs", "TOOL_REFERENCE.md")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read TOOL_REFERENCE.md: %v", err)
	}
	return string(raw)
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := cwd
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "docs", "TOOL_REFERENCE.md")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not find docs/TOOL_REFERENCE.md walking up from %q", cwd)
	return ""
}

func setDiff(a, b []string) []string {
	bset := map[string]bool{}
	for _, x := range b {
		bset[x] = true
	}
	var out []string
	for _, x := range a {
		if !bset[x] {
			out = append(out, x)
		}
	}
	return out
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
