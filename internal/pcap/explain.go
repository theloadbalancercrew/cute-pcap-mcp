package pcap

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"cute-pcap-mcp/internal/config"
)

// explainInput is the wire shape for pcap_explain_connection. The
// selector fields are mutually exclusive; the caller picks exactly
// one of zeek_uid / five_tuple / frame_number to identify a single
// connection.
type explainInput struct {
	Path        string     `json:"path" jsonschema:"absolute or relative path to a pcap/pcapng under an allowed artifact directory"`
	ZeekUID     string     `json:"zeek_uid,omitempty" jsonschema:"Zeek connection UID; resolves to a 5-tuple via Zeek's conn.log"`
	FiveTuple   *FiveTuple `json:"five_tuple,omitempty" jsonschema:"explicit five-tuple selector"`
	FrameNumber int        `json:"frame_number,omitempty" jsonschema:"tshark frame number; resolves to a tcp.stream/udp.stream id"`

	// MaxPacketRows / RedactSecrets / WriteArtifacts mirror the
	// pcap_analyze knobs that are still meaningful when scoped to one
	// connection. Other analyze switches are deliberately not
	// exposed: the tool's purpose is connection-focused evidence.
	MaxPacketRows     int        `json:"max_packet_rows,omitempty" jsonschema:"maximum tshark packet summary rows, capped by server config"`
	RedactSecrets     *bool      `json:"redact_secrets,omitempty" jsonschema:"redact common credentials/token patterns in ASCII output; defaults to true"`
	WriteArtifacts    *bool      `json:"write_artifacts,omitempty" jsonschema:"write analysis.json + summary.md under workspace.output_dir; defaults to true when output_dir is configured"`
	IncludeASCII      *bool      `json:"include_ascii,omitempty" jsonschema:"include bounded printable ASCII strings; defaults to false (connection scope is usually about flow shape, not payload bytes)"`
	ExpectedSHA256    string     `json:"expected_sha256,omitempty" jsonschema:"optional caller-provided sha256 from an external artifact reference; must be exactly 64 hex digits if set; mismatched values return the typed hash_mismatch error"`
	ExpectedSizeBytes *int64     `json:"expected_size_bytes,omitempty" jsonschema:"optional caller-provided file size in bytes from an external artifact reference; must be non-negative if set; mismatched values return the typed size_mismatch error"`
	AnalysisProfile   string     `json:"analysis_profile,omitempty" jsonschema:"optional named profile that layers extra analysis on top of the connection-scoped evidence; today the only registered name is f5_ltm_tls_debug"`
	F5Context         *F5Context `json:"f5_context,omitempty" jsonschema:"optional caller-supplied load-balancer context (VIP, pool, SNAT pool); echoed back and used to classify packet evidence, never to make config claims"`
	TLSKeylogPath     string     `json:"tls_keylog_path,omitempty" jsonschema:"optional path to an SSLKEYLOGFILE under workspace.keylog_dir; same semantics as the field on pcap_analyze"`
}

// FiveTuple is the explicit connection selector. Protocol must be
// "tcp" or "udp" — those are the only connection-oriented stacks
// the explain tool builds filters for.
type FiveTuple struct {
	SourceIP   string `json:"source_ip"`
	SourcePort int    `json:"source_port"`
	DestIP     string `json:"dest_ip"`
	DestPort   int    `json:"dest_port"`
	Protocol   string `json:"protocol"`
}

// explainOutput extends analyzeOutput with the resolved selector
// echoed back. Hosts can switch on Selector.Resolution to know which
// path was used (zeek_uid, five_tuple, frame_number).
type explainOutput struct {
	analyzeOutput
	Selector ResolvedSelector `json:"selector"`
}

// ResolvedSelector echoes what the server actually used. The
// DisplayFilter field is the constructed tshark filter so the host
// can reproduce the scope outside the tool.
type ResolvedSelector struct {
	Resolution    string     `json:"resolution"`
	ZeekUID       string     `json:"zeek_uid,omitempty"`
	FiveTuple     *FiveTuple `json:"five_tuple,omitempty"`
	FrameNumber   int        `json:"frame_number,omitempty"`
	StreamID      string     `json:"stream_id,omitempty"`
	DisplayFilter string     `json:"display_filter"`
}

const (
	resolutionFiveTuple   = "five_tuple"
	resolutionZeekUID     = "zeek_uid"
	resolutionFrameNumber = "frame_number"
)

func explainErrorOutput(artifact ArtifactInfo, terr toolError) explainOutput {
	return explainOutput{
		analyzeOutput: analyzeOutput{
			SchemaVersion: SchemaVersion,
			Artifact:      artifact,
			Error:         &terr,
			// Mirror analyzeErrorOutput: always stamp tls_decryption
			// so hosts that switch on the field never see it
			// disappear on validation / path / busy / selector
			// failures from the explain tool.
			TLSDecryption: &TLSDecryptionStatus{Status: TLSDecryptionStatusNotRequested},
		},
	}
}

// validateExplainInput pins the selector contract: path required,
// exactly one of (zeek_uid, five_tuple, frame_number) set.
func validateExplainInput(input explainInput) error {
	if input.Path == "" {
		return missingFieldError("path")
	}
	count := 0
	if strings.TrimSpace(input.ZeekUID) != "" {
		count++
	}
	if input.FiveTuple != nil {
		count++
	}
	if input.FrameNumber > 0 {
		count++
	}
	if count == 0 {
		return validationError("selector", ValidationReasonEmpty, "exactly one of zeek_uid, five_tuple, or frame_number is required")
	}
	if count > 1 {
		return validationError("selector", ValidationReasonInvalidFormat, "exactly one of zeek_uid, five_tuple, or frame_number may be set; received "+strconv.Itoa(count))
	}
	if input.FiveTuple != nil {
		ft := input.FiveTuple
		if ft.SourceIP == "" || ft.DestIP == "" {
			return validationError("five_tuple", ValidationReasonEmpty, "source_ip and dest_ip are required")
		}
		// Parse IPs through net/netip so the values that get
		// concatenated into the tshark display filter are guaranteed
		// to be syntactically valid addresses, not adversarial
		// fragments that could escape the filter (e.g. embedded
		// "or" / quotes / parentheses). ParseAddr accepts both v4
		// and v6 in canonical text form; we then require both
		// endpoints to share an address family.
		srcAddr, err := netip.ParseAddr(strings.TrimSpace(ft.SourceIP))
		if err != nil {
			return validationError("five_tuple.source_ip", ValidationReasonInvalidFormat, "source_ip is not a valid IP address: "+err.Error())
		}
		dstAddr, err := netip.ParseAddr(strings.TrimSpace(ft.DestIP))
		if err != nil {
			return validationError("five_tuple.dest_ip", ValidationReasonInvalidFormat, "dest_ip is not a valid IP address: "+err.Error())
		}
		if srcAddr.Is4() != dstAddr.Is4() {
			return validationError("five_tuple", ValidationReasonInvalidFormat, "source_ip and dest_ip must be the same address family (both IPv4 or both IPv6)")
		}
		// Normalize the addresses back to their canonical form so the
		// constructed display filter is independent of caller input
		// quirks (leading zeros, mixed-case v6, zone identifiers).
		ft.SourceIP = srcAddr.WithZone("").String()
		ft.DestIP = dstAddr.WithZone("").String()
		switch strings.ToLower(ft.Protocol) {
		case "tcp", "udp":
		case "":
			return validationError("five_tuple.protocol", ValidationReasonEmpty, "protocol is required (tcp or udp)")
		default:
			return validationError("five_tuple.protocol", ValidationReasonInvalidFormat, "protocol must be tcp or udp; got "+ft.Protocol)
		}
		if ft.SourcePort < 0 || ft.SourcePort > 65535 {
			return validationError("five_tuple.source_port", ValidationReasonOutOfRange, "source_port must be in [0, 65535]")
		}
		if ft.DestPort < 0 || ft.DestPort > 65535 {
			return validationError("five_tuple.dest_port", ValidationReasonOutOfRange, "dest_port must be in [0, 65535]")
		}
	}
	if input.MaxPacketRows < 0 {
		return validationError("max_packet_rows", ValidationReasonOutOfRange, "max_packet_rows must be non-negative")
	}
	if err := validateF5Context(input.F5Context); err != nil {
		return err
	}
	return nil
}

// resolveSelector turns the operator's selector into a concrete
// tshark display filter plus a ResolvedSelector echo. The five_tuple
// path constructs the filter directly; frame_number and zeek_uid
// require auxiliary tshark/Zeek calls to map to a 5-tuple or stream
// id first.
func resolveSelector(ctx context.Context, source ArtifactInfo, cfg config.Config, input explainInput) (string, ResolvedSelector, error) {
	switch {
	case input.FiveTuple != nil:
		filter := buildFiveTupleFilter(*input.FiveTuple)
		return filter, ResolvedSelector{
			Resolution:    resolutionFiveTuple,
			FiveTuple:     input.FiveTuple,
			DisplayFilter: filter,
		}, nil
	case input.FrameNumber > 0:
		streamID, proto, ft, err := resolveFrameNumber(ctx, source, cfg, input.FrameNumber)
		if err != nil {
			return "", ResolvedSelector{}, err
		}
		filter := fmt.Sprintf("%s.stream eq %s", proto, streamID)
		return filter, ResolvedSelector{
			Resolution:    resolutionFrameNumber,
			FrameNumber:   input.FrameNumber,
			StreamID:      streamID,
			FiveTuple:     ft,
			DisplayFilter: filter,
		}, nil
	case strings.TrimSpace(input.ZeekUID) != "":
		ft, err := resolveZeekUID(ctx, source, cfg, strings.TrimSpace(input.ZeekUID))
		if err != nil {
			return "", ResolvedSelector{}, err
		}
		filter := buildFiveTupleFilter(*ft)
		return filter, ResolvedSelector{
			Resolution:    resolutionZeekUID,
			ZeekUID:       strings.TrimSpace(input.ZeekUID),
			FiveTuple:     ft,
			DisplayFilter: filter,
		}, nil
	default:
		// validateExplainInput should have caught this.
		return "", ResolvedSelector{}, missingFieldError("selector")
	}
}

// buildFiveTupleFilter returns a tshark display filter that matches
// either direction of a 5-tuple (origin → responder OR responder →
// origin). Connection evidence is symmetrical; a one-direction filter
// would lose return packets.
//
// IPs are expected to have already passed validateExplainInput, which
// parses them through net/netip and rejects mixed families. The
// family check here is via netip.ParseAddr again; if either address
// fails to parse the helper falls back to ip.addr (the safe default
// for a value that already cleared the validator).
func buildFiveTupleFilter(ft FiveTuple) string {
	proto := strings.ToLower(ft.Protocol)
	src := ft.SourceIP
	dst := ft.DestIP
	srcPort := ft.SourcePort
	dstPort := ft.DestPort
	ipField := "ip.addr"
	if a, err := netip.ParseAddr(src); err == nil && !a.Is4() {
		ipField = "ipv6.addr"
	} else if b, err := netip.ParseAddr(dst); err == nil && !b.Is4() {
		ipField = "ipv6.addr"
	}
	return fmt.Sprintf("(%s eq %s and %s eq %s and %s.port eq %d and %s.port eq %d)",
		ipField, src,
		ipField, dst,
		proto, srcPort,
		proto, dstPort,
	)
}

// resolveFrameNumber runs a single tshark call to map a frame number
// to its tcp.stream / udp.stream id and 5-tuple. Returns the stream
// id, the protocol token used in the filter ("tcp" or "udp"), and the
// derived 5-tuple for the ResolvedSelector echo.
func resolveFrameNumber(ctx context.Context, source ArtifactInfo, cfg config.Config, frame int) (string, string, *FiveTuple, error) {
	args := []string{
		"-n",
		"-r", source.Path,
		"-Y", fmt.Sprintf("frame.number == %d", frame),
		"-T", "fields",
		"-E", "header=n",
		"-E", "separator=/t",
		"-E", "occurrence=f",
		"-e", "tcp.stream",
		"-e", "udp.stream",
		"-e", "ip.src",
		"-e", "ip.dst",
		"-e", "tcp.srcport",
		"-e", "tcp.dstport",
		"-e", "udp.srcport",
		"-e", "udp.dstport",
	}
	out, err := runAnalyzerCommand(ctx, cfg.Timeout(), 64*1024, "tshark", args, "")
	if err != nil {
		return "", "", nil, err
	}
	line := strings.TrimSpace(out.Stdout)
	if line == "" {
		return "", "", nil, fmt.Errorf("%w: frame %d not found in capture", errAnalyzerFailed, frame)
	}
	cols := strings.Split(line, "\t")
	for len(cols) < 8 {
		cols = append(cols, "")
	}
	tcpStream := strings.TrimSpace(cols[0])
	udpStream := strings.TrimSpace(cols[1])
	srcIP := strings.TrimSpace(cols[2])
	dstIP := strings.TrimSpace(cols[3])
	tcpSPort := strings.TrimSpace(cols[4])
	tcpDPort := strings.TrimSpace(cols[5])
	udpSPort := strings.TrimSpace(cols[6])
	udpDPort := strings.TrimSpace(cols[7])

	if tcpStream != "" {
		ft := &FiveTuple{
			SourceIP:   srcIP,
			DestIP:     dstIP,
			SourcePort: parsePort(tcpSPort),
			DestPort:   parsePort(tcpDPort),
			Protocol:   "tcp",
		}
		return tcpStream, "tcp", ft, nil
	}
	if udpStream != "" {
		ft := &FiveTuple{
			SourceIP:   srcIP,
			DestIP:     dstIP,
			SourcePort: parsePort(udpSPort),
			DestPort:   parsePort(udpDPort),
			Protocol:   "udp",
		}
		return udpStream, "udp", ft, nil
	}
	return "", "", nil, fmt.Errorf("%w: frame %d is not on a tcp or udp stream", errAnalyzerFailed, frame)
}

// resolveZeekUID runs Zeek on the source pcap, finds the conn.log
// row for the given UID, and extracts a 5-tuple. This is the most
// expensive selector path because Zeek runs twice — once here, then
// again as part of the analyzeArtifact pass that produces the final
// output. Callers that already know the 5-tuple should pass
// five_tuple directly.
func resolveZeekUID(ctx context.Context, source ArtifactInfo, cfg config.Config, uid string) (*FiveTuple, error) {
	// resolveZeekUID runs a no-decryption pass — the UID it's
	// looking up is fixed at capture time and doesn't depend on
	// TLS decryption. Decryption (when the caller requested it)
	// happens on the second Zeek pass inside analyzeArtifact.
	report, err := runZeekReport(ctx, source.Path, cfg, cfg.Analysis.MaxZeekRecordsPerLog, "")
	if err != nil {
		return nil, err
	}
	conn := zeekLogIn(report, "conn")
	if conn == nil {
		return nil, fmt.Errorf("%w: zeek did not produce a conn.log for this capture", errAnalyzerFailed)
	}
	for _, record := range conn.Records {
		if strings.TrimSpace(record["uid"]) != uid {
			continue
		}
		ft := &FiveTuple{
			SourceIP:   strings.TrimSpace(record["id.orig_h"]),
			DestIP:     strings.TrimSpace(record["id.resp_h"]),
			SourcePort: parsePort(strings.TrimSpace(record["id.orig_p"])),
			DestPort:   parsePort(strings.TrimSpace(record["id.resp_p"])),
			Protocol:   strings.ToLower(strings.TrimSpace(record["proto"])),
		}
		if ft.Protocol != "tcp" && ft.Protocol != "udp" {
			return nil, fmt.Errorf("%w: zeek_uid %s resolved to protocol %q; only tcp/udp are supported", errAnalyzerFailed, uid, ft.Protocol)
		}
		return ft, nil
	}
	return nil, fmt.Errorf("%w: zeek_uid %s not found in conn.log", errAnalyzerFailed, uid)
}

func parsePort(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

// explainConnection runs the analyze pipeline scoped to the resolved
// selector and tags the response with a ResolvedSelector echo plus a
// connection_evidence_scoped finding. Artifact persistence still goes
// through writeAnalysisArtifacts so the JSON / Markdown carry the
// scoped evidence.
func explainConnection(ctx context.Context, source ArtifactInfo, cfg config.Config, input explainInput) explainOutput {
	displayFilter, selector, err := resolveSelector(ctx, source, cfg, input)
	if err != nil {
		return explainErrorOutput(source, classify(err))
	}

	// Zeek is required for the dns/http/tls/conn structured sections;
	// callers can disable it implicitly by setting frame_number on a
	// non-stream packet (caught earlier). For five_tuple/zeek_uid we
	// always run Zeek so the output sections stay populated.
	includeZeekTrue := true
	includeASCII := false
	if input.IncludeASCII != nil {
		includeASCII = *input.IncludeASCII
	}

	includeASCIIPtr := includeASCII
	includeCapinfosTrue := true
	includeTSharkTrue := true
	analyze := analyzeInput{
		Path:            source.Path,
		IncludeCapinfos: &includeCapinfosTrue,
		IncludeTShark:   &includeTSharkTrue,
		IncludeZeek:     &includeZeekTrue,
		IncludeASCII:    &includeASCIIPtr,
		RedactSecrets:   input.RedactSecrets,
		DisplayFilter:   displayFilter,
		MaxPacketRows:   input.MaxPacketRows,
		WriteArtifacts:  input.WriteArtifacts,
		AnalysisProfile: input.AnalysisProfile,
		F5Context:       input.F5Context,
		TLSKeylogPath:   input.TLSKeylogPath,
	}
	out := analyzeArtifact(ctx, source, cfg, analyze)

	out.Findings = append(out.Findings, PacketFinding{
		Code:     FindingConnectionEvidenceScoped,
		Severity: "info",
		Message:  fmt.Sprintf("Connection evidence scoped via %s; tshark display_filter = %q.", selector.Resolution, displayFilter),
	})

	return explainOutput{analyzeOutput: out, Selector: selector}
}
