package pcap

import (
	"strings"
	"testing"
	"time"
)

func TestBuildReportChartsUsesBoundedTimingAndZeekSignals(t *testing.T) {
	out := analyzeOutput{
		CaptureSummary: &CaptureSummary{PacketCount: 100, DurationSeconds: 1.2},
		Packets: []TSharkPacketSummary{
			{TimeRelative: "0.000000", Protocol: "TCP"},
			{TimeRelative: "0.200000", Protocol: "DNS"},
			{TimeRelative: "0.900000", Protocol: "TCP"},
			{TimeRelative: "not-a-number", Protocol: "HTTP"},
		},
	}
	summary := &AnalysisSummary{
		Signals: map[string]int{
			"dns_queries":    2,
			"http_requests":  1,
			"notices":        0,
			"tls_handshakes": 1,
		},
		Connections: []ConnectionSummary{
			{
				UID:         "C1",
				Protocol:    "tcp",
				Service:     "http",
				Source:      "192.0.2.10",
				SourcePort:  "49152",
				Destination: "198.51.100.20",
				DestPort:    "80",
				Duration:    "1.25",
			},
			{UID: "C2", Protocol: "udp", Duration: "not-a-duration"},
		},
	}

	charts := buildReportCharts(out, summary)
	if charts == nil {
		t.Fatal("charts = nil")
	}
	if charts.PacketTiming == nil {
		t.Fatal("PacketTiming = nil")
	}
	if charts.PacketTiming.PacketRowsReturned != 4 {
		t.Fatalf("PacketRowsReturned = %d, want 4", charts.PacketTiming.PacketRowsReturned)
	}
	if charts.PacketTiming.PacketRowsPlotted != 3 {
		t.Fatalf("PacketRowsPlotted = %d, want 3", charts.PacketTiming.PacketRowsPlotted)
	}
	if charts.PacketTiming.CaptureDurationSeconds != 1.2 {
		t.Fatalf("CaptureDurationSeconds = %v, want 1.2", charts.PacketTiming.CaptureDurationSeconds)
	}
	if got, want := totalTimingPackets(charts.PacketTiming.Buckets), 3; got != want {
		t.Fatalf("bucket packet total = %d, want %d", got, want)
	}

	if got, want := charts.ProtocolDistribution[0], (ChartCount{Label: "TCP", Count: 2}); got != want {
		t.Fatalf("top protocol = %#v, want %#v", got, want)
	}
	if len(charts.SignalCounts) != 3 {
		t.Fatalf("SignalCounts len = %d, want 3: %#v", len(charts.SignalCounts), charts.SignalCounts)
	}
	if len(charts.ConnectionDurations) != 1 {
		t.Fatalf("ConnectionDurations len = %d, want 1", len(charts.ConnectionDurations))
	}
	if charts.ConnectionDurations[0].DurationSeconds != 1.25 {
		t.Fatalf("DurationSeconds = %v, want 1.25", charts.ConnectionDurations[0].DurationSeconds)
	}
	if !strings.Contains(charts.ConnectionDurations[0].Label, "192.0.2.10:49152 -> 198.51.100.20:80") {
		t.Fatalf("connection label = %q", charts.ConnectionDurations[0].Label)
	}
}

func TestRenderMarkdownSummaryIncludesReportCharts(t *testing.T) {
	charts := buildReportCharts(analyzeOutput{
		CaptureSummary: &CaptureSummary{PacketCount: 3, DurationSeconds: 1},
		Packets: []TSharkPacketSummary{
			{TimeRelative: "0.000000", Protocol: "TCP"},
			{TimeRelative: "0.500000", Protocol: "HTTP"},
			{TimeRelative: "1.000000", Protocol: "HTTP"},
		},
	}, &AnalysisSummary{
		Signals: map[string]int{"http_requests": 2},
	})
	out := analyzeOutput{
		SchemaVersion: SchemaVersion,
		Artifact: ArtifactInfo{
			Path:      "/work/pcaps/example.pcap",
			SizeBytes: 512,
			SHA256:    "deadbeef",
		},
		ReportCharts: charts,
	}

	body := renderMarkdownSummary(out, time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC))
	for _, want := range []string{
		"## Reporting charts",
		"### Packet timing",
		"### Protocol distribution",
		"### Signal counts",
		"| Protocol | Count | Share | Chart |",
		"`########################`",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("summary.md missing %q:\n%s", want, body)
		}
	}
}

func totalTimingPackets(buckets []PacketTimingBucket) int {
	total := 0
	for _, bucket := range buckets {
		total += bucket.PacketCount
	}
	return total
}
