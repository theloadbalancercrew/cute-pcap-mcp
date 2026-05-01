package pcap

import (
	"sort"
	"testing"
)

// TestServerRegistersStableAndLegacyToolNames pins the alias contract:
// both the stable pcap_* names and their legacy aliases remain
// registered. The drift ratchet
// (TestToolReferenceCoversEveryRegisteredTool) catches docs drift; this
// test catches a future refactor that drops a name without touching
// docs.
func TestServerRegistersStableAndLegacyToolNames(t *testing.T) {
	got := registeredToolNames(t)
	want := []string{
		"analyze_pcap",
		"inspect_pcap",
		"pcap_analyze",
		"pcap_analyzer_status",
		"pcap_explain_connection",
		"pcap_filter",
		"pcap_validate",
		"summarize_pcap",
	}
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("got %d tools, want %d: got=%v want=%v", len(got), len(want), got, want)
	}
	for i, name := range got {
		if name != want[i] {
			t.Fatalf("tool[%d] = %q, want %q (full got=%v)", i, name, want[i], got)
		}
	}
}
