package pcap

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"cute-pcap-mcp/internal/config"
)

func TestValidateExplainInputRejectsBadSelectors(t *testing.T) {
	cases := []struct {
		name     string
		input    explainInput
		wantKind string
	}{
		{
			name:     "missing_path",
			input:    explainInput{},
			wantKind: ErrorKindMissingField,
		},
		{
			name:     "no_selector",
			input:    explainInput{Path: "x"},
			wantKind: ErrorKindValidationFailed,
		},
		{
			name: "two_selectors",
			input: explainInput{
				Path:        "x",
				ZeekUID:     "C1",
				FrameNumber: 5,
			},
			wantKind: ErrorKindValidationFailed,
		},
		{
			name: "five_tuple_missing_protocol",
			input: explainInput{
				Path: "x",
				FiveTuple: &FiveTuple{
					SourceIP:   "10.0.0.1",
					DestIP:     "10.0.0.2",
					SourcePort: 1024,
					DestPort:   80,
				},
			},
			wantKind: ErrorKindValidationFailed,
		},
		{
			name: "five_tuple_invalid_protocol",
			input: explainInput{
				Path: "x",
				FiveTuple: &FiveTuple{
					SourceIP:   "10.0.0.1",
					DestIP:     "10.0.0.2",
					SourcePort: 1024,
					DestPort:   80,
					Protocol:   "icmp",
				},
			},
			wantKind: ErrorKindValidationFailed,
		},
		{
			name: "five_tuple_port_out_of_range",
			input: explainInput{
				Path: "x",
				FiveTuple: &FiveTuple{
					SourceIP:   "10.0.0.1",
					DestIP:     "10.0.0.2",
					SourcePort: 99999,
					DestPort:   80,
					Protocol:   "tcp",
				},
			},
			wantKind: ErrorKindValidationFailed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateExplainInput(tc.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if got := classify(err).Kind; got != tc.wantKind {
				t.Fatalf("Kind = %q, want %q", got, tc.wantKind)
			}
		})
	}
}

func TestValidateExplainInputRejectsBadIPs(t *testing.T) {
	cases := []struct {
		name     string
		ft       FiveTuple
		wantKind string
	}{
		{
			name:     "garbage_source_ip",
			ft:       FiveTuple{SourceIP: "not.an.ip", DestIP: "10.0.0.2", SourcePort: 1, DestPort: 80, Protocol: "tcp"},
			wantKind: ErrorKindValidationFailed,
		},
		{
			name:     "filter_injection_attempt",
			ft:       FiveTuple{SourceIP: "10.0.0.1 or 1=1", DestIP: "10.0.0.2", SourcePort: 1, DestPort: 80, Protocol: "tcp"},
			wantKind: ErrorKindValidationFailed,
		},
		{
			name:     "mixed_address_families",
			ft:       FiveTuple{SourceIP: "10.0.0.1", DestIP: "2001:db8::1", SourcePort: 1, DestPort: 80, Protocol: "tcp"},
			wantKind: ErrorKindValidationFailed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateExplainInput(explainInput{Path: "x", FiveTuple: &tc.ft})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if got := classify(err).Kind; got != tc.wantKind {
				t.Fatalf("Kind = %q, want %q", got, tc.wantKind)
			}
		})
	}
}

func TestValidateExplainInputNormalizesIPs(t *testing.T) {
	// Caller passes v6 in a non-canonical form; validate should
	// rewrite the input to the canonical text rep so the filter we
	// build is stable.
	in := explainInput{
		Path: "x",
		FiveTuple: &FiveTuple{
			SourceIP:   "2001:0db8:0000:0000:0000:0000:0000:0001",
			DestIP:     "2001:DB8::2",
			SourcePort: 1024,
			DestPort:   443,
			Protocol:   "tcp",
		},
	}
	if err := validateExplainInput(in); err != nil {
		t.Fatal(err)
	}
	if in.FiveTuple.SourceIP != "2001:db8::1" {
		t.Fatalf("SourceIP not normalized: %q", in.FiveTuple.SourceIP)
	}
	if in.FiveTuple.DestIP != "2001:db8::2" {
		t.Fatalf("DestIP not normalized: %q", in.FiveTuple.DestIP)
	}
}

func TestBuildFiveTupleFilter(t *testing.T) {
	cases := []struct {
		name string
		ft   FiveTuple
		want string
	}{
		{
			name: "tcp_v4",
			ft: FiveTuple{
				SourceIP:   "10.0.0.1",
				DestIP:     "10.0.0.2",
				SourcePort: 5555,
				DestPort:   80,
				Protocol:   "tcp",
			},
			want: "(ip.addr eq 10.0.0.1 and ip.addr eq 10.0.0.2 and tcp.port eq 5555 and tcp.port eq 80)",
		},
		{
			name: "udp_v4",
			ft: FiveTuple{
				SourceIP:   "10.0.0.1",
				DestIP:     "10.0.0.2",
				SourcePort: 53,
				DestPort:   53000,
				Protocol:   "udp",
			},
			want: "(ip.addr eq 10.0.0.1 and ip.addr eq 10.0.0.2 and udp.port eq 53 and udp.port eq 53000)",
		},
		{
			name: "ipv6_uses_ipv6_addr",
			ft: FiveTuple{
				SourceIP:   "2001:db8::1",
				DestIP:     "2001:db8::2",
				SourcePort: 1024,
				DestPort:   443,
				Protocol:   "tcp",
			},
			want: "(ipv6.addr eq 2001:db8::1 and ipv6.addr eq 2001:db8::2 and tcp.port eq 1024 and tcp.port eq 443)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildFiveTupleFilter(tc.ft)
			if got != tc.want {
				t.Fatalf("\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

// TestExplainConnectionFiveTupleIntegration exercises the analyze
// pipeline scoped to the synthetic HTTP pcap's known 5-tuple. Skipped
// without tshark.
func TestExplainConnectionFiveTupleIntegration(t *testing.T) {
	requireCommand(t, "tshark")

	root := t.TempDir()
	pcapDir := filepath.Join(root, "pcaps")
	outputDir := filepath.Join(root, "output")
	if err := os.MkdirAll(pcapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pcap := filepath.Join(pcapDir, "http.pcap")
	if err := os.WriteFile(pcap, syntheticHTTPPcap(), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{pcapDir},
		Workspace:           config.WorkspaceConfig{OutputDir: outputDir},
		Analysis: config.AnalysisConfig{
			CommandTimeoutSeconds: 10,
			MaxStdoutBytes:        200000,
			MaxPacketRows:         20,
			MaxZeekRecordsPerLog:  20,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	source, err := inspectArtifact(pcap, cfg, artifactExpectations{})
	if err != nil {
		t.Fatal(err)
	}

	out := explainConnection(context.Background(), source, cfg, explainInput{
		Path: pcap,
		FiveTuple: &FiveTuple{
			SourceIP:   "192.0.2.10",
			DestIP:     "198.51.100.20",
			SourcePort: 55555,
			DestPort:   80,
			Protocol:   "tcp",
		},
	})

	if out.SchemaVersion != SchemaVersion {
		t.Fatalf("SchemaVersion = %q", out.SchemaVersion)
	}
	if out.Selector.Resolution != resolutionFiveTuple {
		t.Fatalf("Selector.Resolution = %q, want %q", out.Selector.Resolution, resolutionFiveTuple)
	}
	if !strings.Contains(out.Selector.DisplayFilter, "tcp.port eq 80") {
		t.Fatalf("DisplayFilter missing tcp.port: %q", out.Selector.DisplayFilter)
	}
	if len(out.Packets) == 0 {
		t.Fatalf("no packets returned for the scoped 5-tuple; errors: %#v", out.Errors)
	}
	// connection_evidence_scoped finding must be present.
	var scoped bool
	for _, f := range out.Findings {
		if f.Code == FindingConnectionEvidenceScoped {
			scoped = true
			break
		}
	}
	if !scoped {
		t.Fatalf("connection_evidence_scoped finding missing; got %#v", out.Findings)
	}
}

// TestResolveFrameNumberOutOfRange covers the bug from #10 case (1):
// the operator picks a frame_number past the last frame in the
// capture. The pre-fix code returned analyzer_failed("frame N not
// found in capture"); the fix returns the typed
// frame_number_out_of_range so a host can switch on the kind.
func TestResolveFrameNumberOutOfRange(t *testing.T) {
	requireCommand(t, "tshark")

	root := t.TempDir()
	pcap := filepath.Join(root, "http.pcap")
	if err := os.WriteFile(pcap, syntheticHTTPPcap(), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{root},
		Analysis:            config.AnalysisConfig{CommandTimeoutSeconds: 10, MaxStdoutBytes: 200000},
	})
	if err != nil {
		t.Fatal(err)
	}
	source, err := inspectArtifact(pcap, cfg, artifactExpectations{})
	if err != nil {
		t.Fatal(err)
	}

	_, _, _, err = resolveFrameNumber(context.Background(), source, cfg, 999)
	if err == nil {
		t.Fatal("expected error for frame past end of capture, got nil")
	}
	terr := classify(err)
	if terr.Kind != ErrorKindFrameNumberOutOfRange {
		t.Fatalf("Kind = %q, want %q (message=%q)", terr.Kind, ErrorKindFrameNumberOutOfRange, terr.Message)
	}
	if terr.Field != "frame_number" {
		t.Fatalf("Field = %q, want %q", terr.Field, "frame_number")
	}
	// Best-effort: capinfos is normally available alongside tshark in
	// the test environment, in which case the message should name the
	// valid range. Skip the range assertion if capinfos was missing.
	if _, lookErr := exec.LookPath("capinfos"); lookErr == nil {
		if !strings.Contains(terr.Message, "frames 1..1") {
			t.Fatalf("message %q does not name the valid frame range", terr.Message)
		}
	}
}

// TestResolveFrameNumberNotOnStream covers the bug from #10 case (3):
// the frame exists but is on a non-IP / non-TCP-UDP packet (here, a
// synthetic ARP request). The pre-fix code emitted analyzer_failed
// with "frame N not found in capture" because the all-empty stream
// row was indistinguishable from "no row." The fix surfaces the
// typed frame_not_on_stream kind plus the protocol name so the
// operator understands.
func TestResolveFrameNumberNotOnStream(t *testing.T) {
	requireCommand(t, "tshark")

	root := t.TempDir()
	pcap := filepath.Join(root, "arp.pcap")
	if err := os.WriteFile(pcap, syntheticARPPcap(), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{root},
		Analysis:            config.AnalysisConfig{CommandTimeoutSeconds: 10, MaxStdoutBytes: 200000},
	})
	if err != nil {
		t.Fatal(err)
	}
	source, err := inspectArtifact(pcap, cfg, artifactExpectations{})
	if err != nil {
		t.Fatal(err)
	}

	_, _, _, err = resolveFrameNumber(context.Background(), source, cfg, 1)
	if err == nil {
		t.Fatal("expected error for non-stream frame, got nil")
	}
	terr := classify(err)
	if terr.Kind != ErrorKindFrameNotOnStream {
		t.Fatalf("Kind = %q, want %q (message=%q)", terr.Kind, ErrorKindFrameNotOnStream, terr.Message)
	}
	if terr.Field != "frame_number" {
		t.Fatalf("Field = %q, want %q", terr.Field, "frame_number")
	}
	if !strings.Contains(strings.ToUpper(terr.Message), "ARP") {
		t.Fatalf("message %q does not name the frame protocol (expected ARP)", terr.Message)
	}
}

// syntheticARPPcap returns a 1-frame libpcap file containing an
// Ethernet ARP request. ARP frames are not on a tcp/udp stream, so
// they exercise the frame_not_on_stream path. The wire format mirrors
// syntheticHTTPPcap: standard pcap global header + one record header
// + Ethernet frame.
func syntheticARPPcap() []byte {
	const ethHdr = 14
	const arpLen = 28
	frame := make([]byte, ethHdr+arpLen)

	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	binary.BigEndian.PutUint16(frame[12:14], 0x0806)

	arp := frame[ethHdr:]
	binary.BigEndian.PutUint16(arp[0:2], 0x0001)
	binary.BigEndian.PutUint16(arp[2:4], 0x0800)
	arp[4] = 6
	arp[5] = 4
	binary.BigEndian.PutUint16(arp[6:8], 0x0001)
	copy(arp[8:14], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	copy(arp[14:18], []byte{192, 0, 2, 10})
	copy(arp[18:24], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	copy(arp[24:28], []byte{192, 0, 2, 1})

	var buf bytes.Buffer
	writeLE := func(v any) {
		_ = binary.Write(&buf, binary.LittleEndian, v)
	}
	writeLE(uint32(0xa1b2c3d4))
	writeLE(uint16(2))
	writeLE(uint16(4))
	writeLE(int32(0))
	writeLE(uint32(0))
	writeLE(uint32(65535))
	writeLE(uint32(1))
	writeLE(uint32(1))
	writeLE(uint32(0))
	writeLE(uint32(len(frame)))
	writeLE(uint32(len(frame)))
	buf.Write(frame)
	return buf.Bytes()
}
