package pcap

import "testing"

func TestCaptureSummaryUsesArtifactSizeBytes(t *testing.T) {
	raw := `File name:           sample.pcap
File size:           118 kB
Number of packets:   42
Capture duration:    1.5 seconds
`
	artifact := ArtifactInfo{Path: "/work/pcaps/sample.pcap", SizeBytes: 118341}

	summary := captureSummaryFromCapinfos(raw, artifact)
	if summary == nil {
		t.Fatal("summary = nil")
	}
	if summary.FileSizeBytes != artifact.SizeBytes {
		t.Fatalf("FileSizeBytes = %d, want artifact size %d", summary.FileSizeBytes, artifact.SizeBytes)
	}
	if summary.PacketCount != 42 {
		t.Fatalf("PacketCount = %d, want 42", summary.PacketCount)
	}
	if summary.DurationSeconds != 1.5 {
		t.Fatalf("DurationSeconds = %v, want 1.5", summary.DurationSeconds)
	}
}
