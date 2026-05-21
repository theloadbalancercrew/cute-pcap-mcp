package pcap

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxReportTimingBuckets       = 12
	maxReportConnectionDurations = 10
	maxReportChartLabelBytes     = 96
)

func buildReportCharts(out analyzeOutput, summary *AnalysisSummary) *ReportChartsSection {
	charts := &ReportChartsSection{
		Metadata: map[string]string{
			"scope": "Charts are derived from bounded analyzer evidence returned by this tool call; packet timing may be capped or display-filtered.",
		},
	}

	if timing := buildPacketTimingChart(out.CaptureSummary, out.Packets); timing != nil {
		charts.PacketTiming = timing
	}
	if protocols := buildProtocolDistribution(out.Packets); len(protocols) > 0 {
		charts.ProtocolDistribution = protocols
	}
	if summary != nil {
		if signals := buildSignalCounts(summary.Signals); len(signals) > 0 {
			charts.SignalCounts = signals
		}
		if durations := buildConnectionDurations(summary.Connections); len(durations) > 0 {
			charts.ConnectionDurations = durations
		}
	}

	if charts.PacketTiming == nil &&
		len(charts.ProtocolDistribution) == 0 &&
		len(charts.SignalCounts) == 0 &&
		len(charts.ConnectionDurations) == 0 {
		return nil
	}
	return charts
}

func appendReportChartsMarkdown(b *strings.Builder, charts *ReportChartsSection) {
	if charts == nil {
		return
	}
	wroteHeading := false
	ensureHeading := func() {
		if wroteHeading {
			return
		}
		b.WriteString("## Reporting charts\n\n")
		wroteHeading = true
	}

	if charts.PacketTiming != nil && len(charts.PacketTiming.Buckets) > 0 {
		ensureHeading()
		appendPacketTimingMarkdown(b, charts.PacketTiming)
	}
	if len(charts.ProtocolDistribution) > 0 {
		ensureHeading()
		appendCountChartMarkdown(b, "### Protocol distribution\n\n", "Protocol", charts.ProtocolDistribution)
	}
	if len(charts.SignalCounts) > 0 {
		ensureHeading()
		appendCountChartMarkdown(b, "### Signal counts\n\n", "Signal", charts.SignalCounts)
	}
	if len(charts.ConnectionDurations) > 0 {
		ensureHeading()
		appendConnectionDurationsMarkdown(b, charts.ConnectionDurations)
	}
}

func appendPacketTimingMarkdown(b *strings.Builder, chart *PacketTimingChart) {
	fmt.Fprintf(b, "### Packet timing\n\n")
	fmt.Fprintf(b, "- Packet rows plotted: %d of %d returned rows\n", chart.PacketRowsPlotted, chart.PacketRowsReturned)
	if chart.CaptureDurationSeconds > 0 {
		fmt.Fprintf(b, "- Timing span: %s\n", formatChartSeconds(chart.CaptureDurationSeconds))
	}
	if chart.BucketWidthSeconds > 0 {
		fmt.Fprintf(b, "- Bucket width: %s\n", formatChartSeconds(chart.BucketWidthSeconds))
	}
	b.WriteString("\n")
	b.WriteString("| Offset window | Packets | Top protocol | Chart |\n")
	b.WriteString("| --- | ---: | --- | --- |\n")
	maxCount := maxPacketTimingBucketCount(chart.Buckets)
	for _, bucket := range chart.Buckets {
		fmt.Fprintf(
			b,
			"| %s | %d | %s | `%s` |\n",
			packetTimingWindowLabel(bucket),
			bucket.PacketCount,
			topProtocolLabel(bucket.ProtocolCounts),
			chartBar(bucket.PacketCount, maxCount, 24),
		)
	}
	b.WriteString("\n")
}

func appendCountChartMarkdown(b *strings.Builder, title, labelHeader string, rows []ChartCount) {
	b.WriteString(title)
	b.WriteString("| " + labelHeader + " | Count | Share | Chart |\n")
	b.WriteString("| --- | ---: | ---: | --- |\n")
	total := 0
	maxCount := 0
	for _, row := range rows {
		total += row.Count
		if row.Count > maxCount {
			maxCount = row.Count
		}
	}
	for _, row := range rows {
		share := 0.0
		if total > 0 {
			share = float64(row.Count) / float64(total) * 100
		}
		fmt.Fprintf(b, "| %s | %d | %.1f%% | `%s` |\n", row.Label, row.Count, share, chartBar(row.Count, maxCount, 24))
	}
	b.WriteString("\n")
}

func appendConnectionDurationsMarkdown(b *strings.Builder, rows []ConnectionDurationChartRow) {
	b.WriteString("### Connection durations\n\n")
	b.WriteString("| Connection | Duration | Service | Chart |\n")
	b.WriteString("| --- | ---: | --- | --- |\n")
	maxDuration := 0.0
	for _, row := range rows {
		if row.DurationSeconds > maxDuration {
			maxDuration = row.DurationSeconds
		}
	}
	for _, row := range rows {
		fmt.Fprintf(
			b,
			"| %s | %s | %s | `%s` |\n",
			row.Label,
			formatChartSeconds(row.DurationSeconds),
			firstNonEmpty(row.Service, row.Protocol, "-"),
			durationBar(row.DurationSeconds, maxDuration, 24),
		)
	}
	b.WriteString("\n")
}

func buildPacketTimingChart(summary *CaptureSummary, packets []TSharkPacketSummary) *PacketTimingChart {
	if len(packets) == 0 {
		return nil
	}

	times := make([]float64, 0, len(packets))
	protocols := make([]string, 0, len(packets))
	maxTime := 0.0
	for _, packet := range packets {
		t, err := strconv.ParseFloat(strings.TrimSpace(packet.TimeRelative), 64)
		if err != nil || math.IsNaN(t) || math.IsInf(t, 0) || t < 0 {
			continue
		}
		times = append(times, t)
		protocols = append(protocols, chartLabelOr(packet.Protocol, "UNKNOWN"))
		if t > maxTime {
			maxTime = t
		}
	}
	if len(times) == 0 {
		return nil
	}

	duration := maxTime
	if summary != nil && summary.DurationSeconds > duration {
		duration = summary.DurationSeconds
	}

	bucketCount := 1
	if duration > 0 {
		bucketCount = len(times)
		if bucketCount > maxReportTimingBuckets {
			bucketCount = maxReportTimingBuckets
		}
	}
	bucketWidth := 0.0
	if duration > 0 {
		bucketWidth = duration / float64(bucketCount)
	}

	chart := &PacketTimingChart{
		PacketRowsReturned:     len(packets),
		PacketRowsPlotted:      len(times),
		CaptureDurationSeconds: duration,
		BucketWidthSeconds:     bucketWidth,
		Buckets:                make([]PacketTimingBucket, bucketCount),
	}
	for i := range chart.Buckets {
		start := 0.0
		end := 0.0
		if bucketWidth > 0 {
			start = float64(i) * bucketWidth
			end = start + bucketWidth
			if i == bucketCount-1 {
				end = duration
			}
		}
		chart.Buckets[i] = PacketTimingBucket{
			StartOffsetSeconds: start,
			EndOffsetSeconds:   end,
			ProtocolCounts:     map[string]int{},
		}
	}

	for i, t := range times {
		bucketIdx := 0
		if duration > 0 && bucketWidth > 0 {
			bucketIdx = int(math.Floor(t / bucketWidth))
			if bucketIdx >= bucketCount {
				bucketIdx = bucketCount - 1
			}
			if bucketIdx < 0 {
				bucketIdx = 0
			}
		}
		chart.Buckets[bucketIdx].PacketCount++
		chart.Buckets[bucketIdx].ProtocolCounts[protocols[i]]++
	}

	for i := range chart.Buckets {
		if len(chart.Buckets[i].ProtocolCounts) == 0 {
			chart.Buckets[i].ProtocolCounts = nil
		}
	}
	return chart
}

func buildProtocolDistribution(packets []TSharkPacketSummary) []ChartCount {
	counts := map[string]int{}
	for _, packet := range packets {
		label := chartLabelOr(packet.Protocol, "UNKNOWN")
		counts[label]++
	}
	return sortedChartCounts(counts)
}

func buildSignalCounts(signals map[string]int) []ChartCount {
	counts := map[string]int{}
	for label, count := range signals {
		if count <= 0 {
			continue
		}
		counts[chartLabelOr(label, "unknown")] = count
	}
	return sortedChartCounts(counts)
}

func buildConnectionDurations(connections []ConnectionSummary) []ConnectionDurationChartRow {
	rows := make([]ConnectionDurationChartRow, 0, len(connections))
	for _, conn := range connections {
		duration := parseChartFloat(conn.Duration)
		if duration <= 0 {
			continue
		}
		rows = append(rows, ConnectionDurationChartRow{
			Label:           connectionDurationLabel(conn),
			UID:             chartLabel(conn.UID),
			Protocol:        chartLabel(conn.Protocol),
			Service:         chartLabel(conn.Service),
			Source:          chartLabel(conn.Source),
			SourcePort:      chartLabel(conn.SourcePort),
			Destination:     chartLabel(conn.Destination),
			DestPort:        chartLabel(conn.DestPort),
			DurationSeconds: duration,
		})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].DurationSeconds == rows[j].DurationSeconds {
			return rows[i].Label < rows[j].Label
		}
		return rows[i].DurationSeconds > rows[j].DurationSeconds
	})
	if len(rows) > maxReportConnectionDurations {
		return rows[:maxReportConnectionDurations]
	}
	return rows
}

func sortedChartCounts(counts map[string]int) []ChartCount {
	out := make([]ChartCount, 0, len(counts))
	for label, count := range counts {
		if count <= 0 {
			continue
		}
		out = append(out, ChartCount{Label: label, Count: count})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Label < out[j].Label
		}
		return out[i].Count > out[j].Count
	})
	return out
}

func connectionDurationLabel(conn ConnectionSummary) string {
	src := hostPortLabel(conn.Source, conn.SourcePort)
	dst := hostPortLabel(conn.Destination, conn.DestPort)
	switch {
	case src != "" && dst != "":
		return chartLabel(fmt.Sprintf("%s -> %s", src, dst))
	case conn.UID != "":
		return chartLabel(conn.UID)
	default:
		return chartLabel(firstNonEmpty(conn.Service, conn.Protocol, "connection"))
	}
}

func hostPortLabel(host, port string) string {
	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)
	if host == "" {
		return ""
	}
	if port == "" {
		return host
	}
	return host + ":" + port
}

func chartLabel(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t', '|', '`':
			return ' '
		default:
			return r
		}
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	if value == "" {
		return ""
	}
	if len(value) <= maxReportChartLabelBytes {
		return value
	}
	var b strings.Builder
	for _, r := range value {
		nextLen := b.Len() + utf8.RuneLen(r)
		if nextLen > maxReportChartLabelBytes {
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

func chartLabelOr(value, fallback string) string {
	label := chartLabel(value)
	if label == "" {
		return fallback
	}
	return label
}

func parseChartFloat(value string) float64 {
	value = strings.TrimSpace(value)
	if value == "" || value == "-" {
		return 0
	}
	v, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return v
}

func packetTimingWindowLabel(bucket PacketTimingBucket) string {
	if bucket.StartOffsetSeconds == bucket.EndOffsetSeconds {
		return formatChartSeconds(bucket.StartOffsetSeconds)
	}
	return formatChartSeconds(bucket.StartOffsetSeconds) + "-" + formatChartSeconds(bucket.EndOffsetSeconds)
}

func topProtocolLabel(counts map[string]int) string {
	if len(counts) == 0 {
		return "-"
	}
	rows := sortedChartCounts(counts)
	if len(rows) == 0 {
		return "-"
	}
	return rows[0].Label
}

func maxPacketTimingBucketCount(buckets []PacketTimingBucket) int {
	maxCount := 0
	for _, bucket := range buckets {
		if bucket.PacketCount > maxCount {
			maxCount = bucket.PacketCount
		}
	}
	return maxCount
}

func chartBar(count, maxCount, width int) string {
	if count <= 0 || maxCount <= 0 || width <= 0 {
		return ""
	}
	n := int(math.Ceil(float64(count) / float64(maxCount) * float64(width)))
	if n < 1 {
		n = 1
	}
	return strings.Repeat("#", n)
}

func durationBar(value, maxValue float64, width int) string {
	if value <= 0 || maxValue <= 0 || width <= 0 {
		return ""
	}
	n := int(math.Ceil(value / maxValue * float64(width)))
	if n < 1 {
		n = 1
	}
	return strings.Repeat("#", n)
}

func formatChartSeconds(value float64) string {
	return strconv.FormatFloat(value, 'f', 6, 64) + "s"
}
