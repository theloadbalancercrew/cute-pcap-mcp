package pcap

import (
	"regexp"
	"strconv"
	"strings"
)

// parseCapinfos extracts a structured CaptureSummary from capinfos's
// human-readable text. The parser is best-effort: missing fields stay
// at their zero value and the raw text is preserved verbatim. tshark
// can change capinfos's output formatting between major versions, so
// we never fail the call on a parse miss — the contract guarantees
// `Raw` always survives.
func parseCapinfos(raw string) *CaptureSummary {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	summary := &CaptureSummary{Raw: raw}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:colon]))
		value := strings.TrimSpace(line[colon+1:])
		switch key {
		case "number of packets":
			summary.PacketCount = parseLeadingInt64(value)
		case "capture duration":
			summary.DurationSeconds = parseLeadingFloat(value)
		case "first packet time":
			summary.StartTime = value
		case "last packet time":
			summary.EndTime = value
		case "data byte rate":
			summary.DataByteRate = value
		case "average packet rate":
			summary.PacketRate = value
		case "file type":
			summary.FileType = value
		case "file encapsulation":
			summary.Encapsulation = value
		case "packet size limit":
			summary.SnapshotLength = int(parseLeadingInt64(value))
		case "average packet size":
			summary.AveragePacketSize = parseLeadingFloat(value)
		}
	}
	return summary
}

func captureSummaryFromCapinfos(raw string, artifact ArtifactInfo) *CaptureSummary {
	summary := parseCapinfos(raw)
	if summary == nil {
		return nil
	}
	summary.FileSizeBytes = artifact.SizeBytes
	return summary
}

var leadingNumber = regexp.MustCompile(`^[-+]?[0-9]+(?:\.[0-9]+)?`)

func parseLeadingInt64(s string) int64 {
	match := leadingNumber.FindString(s)
	if match == "" {
		return 0
	}
	if v, err := strconv.ParseInt(match, 10, 64); err == nil {
		return v
	}
	if v, err := strconv.ParseFloat(match, 64); err == nil {
		return int64(v)
	}
	return 0
}

func parseLeadingFloat(s string) float64 {
	match := leadingNumber.FindString(s)
	if match == "" {
		return 0
	}
	v, _ := strconv.ParseFloat(match, 64)
	return v
}
