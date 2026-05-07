package pcap

import (
	"context"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"cute-pcap-mcp/internal/config"
)

const (
	DiagnoseSchemaVersion = "1.0.0"

	DiagnoseSymptomTLSHandshakeAttemptedOnPlainPort = "tls_handshake_attempted_on_plain_port"
	DiagnoseSymptomTCPRSTAfterSYNACKNoAppData       = "tcp_rst_after_synack_no_app_data"
	DiagnoseSymptomMonitorProbeReturnsRST           = "monitor_probe_returns_rst"
	DiagnoseSymptomAsymmetricReturnPathObserved     = "asymmetric_return_path_observed"

	DiagnoseFindingFlowUnparseable        = "pcap_diagnose_flow_unparseable"
	DiagnoseFindingCaptureTruncated       = "pcap_diagnose_capture_truncated"
	DiagnoseFindingWindowTooShort         = "pcap_diagnose_window_too_short"
	DiagnoseFindingParseTimeout           = "pcap_diagnose_parse_timeout"
	DiagnoseFindingLacksInterfaceMetadata = "pcap_diagnose_capture_lacks_interface_metadata"
	DiagnoseFindingUnrecognizedPattern    = "pcap_diagnose_unrecognized_pattern_observed"
	DiagnoseFindingInputInvalid           = "pcap_diagnose_input_invalid"
	DiagnoseFindingPathInvalid            = "pcap_diagnose_path_invalid"
	DiagnoseFindingArtifactMismatch       = "pcap_diagnose_artifact_mismatch"
	diagnoseDefaultParseTimeout           = 60 * time.Second
	diagnoseHardMaxParseTimeout           = 180 * time.Second
	diagnoseMinCadenceWindowSeconds       = 90
	diagnoseMonitorCadenceMaxSeconds      = 30
	diagnoseMonitorPayloadMaxBytes        = 256
	diagnoseMaxFindingDetailBytes         = 240
)

var diagnoseSymptomVocabulary = []string{
	DiagnoseSymptomTLSHandshakeAttemptedOnPlainPort,
	DiagnoseSymptomTCPRSTAfterSYNACKNoAppData,
	DiagnoseSymptomMonitorProbeReturnsRST,
	DiagnoseSymptomAsymmetricReturnPathObserved,
}

var diagnoseSymptomSet = map[string]bool{
	DiagnoseSymptomTLSHandshakeAttemptedOnPlainPort: true,
	DiagnoseSymptomTCPRSTAfterSYNACKNoAppData:       true,
	DiagnoseSymptomMonitorProbeReturnsRST:           true,
	DiagnoseSymptomAsymmetricReturnPathObserved:     true,
}

var diagnoseFindingVocabulary = []string{
	DiagnoseFindingFlowUnparseable,
	DiagnoseFindingCaptureTruncated,
	DiagnoseFindingWindowTooShort,
	DiagnoseFindingParseTimeout,
	DiagnoseFindingLacksInterfaceMetadata,
	DiagnoseFindingUnrecognizedPattern,
	DiagnoseFindingInputInvalid,
	DiagnoseFindingPathInvalid,
	DiagnoseFindingArtifactMismatch,
}

type diagnoseInput struct {
	Path              string         `json:"path" jsonschema:"absolute or relative path to a pcap/pcapng under an allowed artifact directory"`
	ExpectedSHA256    string         `json:"expected_sha256,omitempty" jsonschema:"optional caller-provided sha256 from an external artifact reference; must be exactly 64 hex digits if set"`
	ExpectedSizeBytes *int64         `json:"expected_size_bytes,omitempty" jsonschema:"optional caller-provided file size in bytes from an external artifact reference; must be non-negative if set"`
	Scope             *diagnoseScope `json:"scope,omitempty" jsonschema:"optional flow narrowing for symptom extraction"`
	SymptomFilter     []string       `json:"symptom_filter,omitempty" jsonschema:"optional closed-vocabulary subset of symptoms to extract; unknown tokens fail closed"`
}

type diagnoseScope struct {
	SrcIP    string `json:"src_ip,omitempty" jsonschema:"optional source IP for flow narrowing"`
	DstIP    string `json:"dst_ip,omitempty" jsonschema:"optional destination IP for flow narrowing"`
	SrcPort  *int   `json:"src_port,omitempty" jsonschema:"optional source port for TCP/UDP flow narrowing"`
	DstPort  *int   `json:"dst_port,omitempty" jsonschema:"optional destination port for TCP/UDP flow narrowing"`
	Protocol string `json:"protocol,omitempty" jsonschema:"optional protocol for flow narrowing: tcp, udp, or icmp"`
}

type diagnoseOutput struct {
	SchemaVersion string            `json:"schema_version"`
	Path          string            `json:"path,omitempty"`
	SizeBytes     int64             `json:"size_bytes,omitempty"`
	SHA256        string            `json:"sha256,omitempty"`
	Symptoms      []DiagnoseSymptom `json:"symptoms"`
	Findings      []DiagnoseFinding `json:"findings"`
}

type DiagnoseSymptom struct {
	Code       string                  `json:"code"`
	Severity   string                  `json:"severity"`
	Confidence string                  `json:"confidence"`
	Evidence   DiagnoseSymptomEvidence `json:"evidence"`
	Narrative  string                  `json:"narrative"`
}

type DiagnoseSymptomEvidence struct {
	Flow              DiagnoseFlowEvidence `json:"flow"`
	PacketCount       int                  `json:"packet_count"`
	FirstSeenOffsetMS int64                `json:"first_seen_offset_ms"`
	LastSeenOffsetMS  int64                `json:"last_seen_offset_ms"`

	ClientHelloObserved *bool  `json:"client_hello_observed,omitempty"`
	ServerResponseKind  string `json:"server_response_kind,omitempty"`
	TLSVersionOffered   string `json:"tls_version_offered,omitempty"`

	HandshakeCompleted     *bool  `json:"handshake_completed,omitempty"`
	AppBytesClientToServer *int   `json:"app_bytes_client_to_server,omitempty"`
	AppBytesServerToClient *int   `json:"app_bytes_server_to_client,omitempty"`
	TimeToRSTMS            *int64 `json:"time_to_rst_ms,omitempty"`

	ProbeCount             int     `json:"probe_count,omitempty"`
	ProbeCadenceSecondsP50 float64 `json:"probe_cadence_seconds_p50,omitempty"`
	RSTRatio               float64 `json:"rst_ratio,omitempty"`

	SynSeen                       *bool    `json:"syn_seen,omitempty"`
	SynAckSeen                    *bool    `json:"syn_ack_seen,omitempty"`
	InterfacesObserved            []string `json:"interfaces_observed,omitempty"`
	FlowCompleteViaOtherInterface *bool    `json:"flow_complete_via_other_interface,omitempty"`
}

type DiagnoseFlowEvidence struct {
	SrcIP    string `json:"src_ip,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"`
	SrcPort  *int   `json:"src_port,omitempty"`
	DstPort  *int   `json:"dst_port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

type DiagnoseFinding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Detail   string `json:"detail,omitempty"`
}

type diagnosePacket struct {
	Number           int
	TimeRelative     float64
	InterfaceID      string
	InterfaceName    string
	FrameLen         int
	FrameCapLen      int
	SrcIP            string
	DstIP            string
	SrcPort          int
	DstPort          int
	Protocol         string
	SYN              bool
	ACK              bool
	RST              bool
	TCPLen           int
	PayloadHex       string
	CaptureTruncated bool
}

type diagnoseFlowState struct {
	Flow              DiagnoseFlowEvidence
	Packets           []diagnosePacket
	HasTruncation     bool
	originWasInferred bool
}

func validateDiagnoseInput(input diagnoseInput) []DiagnoseFinding {
	var findings []DiagnoseFinding
	if strings.TrimSpace(input.Path) == "" {
		findings = append(findings, diagnoseFinding(DiagnoseFindingInputInvalid, "error", "field=path reason=empty"))
	}
	if err := validateArtifactExpectations(input.ExpectedSHA256, input.ExpectedSizeBytes); err != nil {
		terr := classify(err)
		detail := "field=" + firstNonEmpty(terr.Field, "artifact_expectation")
		if terr.Reason != "" {
			detail += " reason=" + terr.Reason
		}
		findings = append(findings, diagnoseFinding(DiagnoseFindingInputInvalid, "error", detail))
	}
	if input.Scope != nil {
		findings = append(findings, validateDiagnoseScope(*input.Scope)...)
	}
	for _, token := range input.SymptomFilter {
		if !validDiagnoseTokenShape(token) {
			findings = append(findings, diagnoseFinding(DiagnoseFindingInputInvalid, "error", "field=symptom_filter reason=invalid_token"))
			continue
		}
		if !diagnoseSymptomSet[token] {
			findings = append(findings, diagnoseFinding(DiagnoseFindingInputInvalid, "error", "field=symptom_filter token="+token))
		}
	}
	return findings
}

func validateDiagnoseScope(scope diagnoseScope) []DiagnoseFinding {
	var findings []DiagnoseFinding
	for _, slot := range []struct {
		field string
		value string
	}{
		{"scope.src_ip", scope.SrcIP},
		{"scope.dst_ip", scope.DstIP},
	} {
		if strings.TrimSpace(slot.value) == "" {
			continue
		}
		if _, err := netip.ParseAddr(slot.value); err != nil {
			findings = append(findings, diagnoseFinding(DiagnoseFindingInputInvalid, "error", "field="+slot.field+" reason=invalid_format"))
		}
	}
	for _, slot := range []struct {
		field string
		value *int
	}{
		{"scope.src_port", scope.SrcPort},
		{"scope.dst_port", scope.DstPort},
	} {
		if slot.value != nil && (*slot.value < 0 || *slot.value > 65535) {
			findings = append(findings, diagnoseFinding(DiagnoseFindingInputInvalid, "error", "field="+slot.field+" reason=out_of_range"))
		}
	}
	if scope.Protocol != "" {
		switch strings.ToLower(scope.Protocol) {
		case "tcp", "udp", "icmp":
		default:
			findings = append(findings, diagnoseFinding(DiagnoseFindingInputInvalid, "error", "field=scope.protocol reason=invalid_format"))
		}
	}
	return findings
}

func diagnoseErrorOutput(findings []DiagnoseFinding) diagnoseOutput {
	return diagnoseOutput{
		SchemaVersion: DiagnoseSchemaVersion,
		Symptoms:      []DiagnoseSymptom{},
		Findings:      findings,
	}
}

func diagnoseArtifactErrorOutput(err error) diagnoseOutput {
	terr := classify(err)
	code := DiagnoseFindingPathInvalid
	if terr.Kind == ErrorKindHashMismatch || terr.Kind == ErrorKindSizeMismatch {
		code = DiagnoseFindingArtifactMismatch
	}
	detail := "kind=" + terr.Kind
	if terr.Field != "" {
		detail += " field=" + terr.Field
	}
	return diagnoseErrorOutput([]DiagnoseFinding{diagnoseFinding(code, "error", detail)})
}

func diagnoseSymptoms(ctx context.Context, artifact ArtifactInfo, cfg config.Config, input diagnoseInput) diagnoseOutput {
	out := diagnoseOutput{
		SchemaVersion: DiagnoseSchemaVersion,
		Path:          artifact.Path,
		SizeBytes:     artifact.SizeBytes,
		SHA256:        artifact.SHA256,
		Symptoms:      []DiagnoseSymptom{},
		Findings:      []DiagnoseFinding{},
	}
	filter := diagnoseFilter(input.SymptomFilter)
	packets, fileTruncated, err := runDiagnoseTSharkFields(ctx, artifact.Path, diagnoseParseTimeout(), cfg.Analysis.MaxStdoutBytes)
	forceLowConfidence := false
	if err != nil {
		switch {
		case errors.Is(err, errAnalyzerTimeout):
			out.Findings = append(out.Findings, diagnoseFinding(DiagnoseFindingParseTimeout, "warning", "analyzer=tshark timeout_seconds=60"))
			forceLowConfidence = true
		default:
			terr := classify(err)
			out.Findings = append(out.Findings, diagnoseFinding(DiagnoseFindingFlowUnparseable, "warning", "analyzer=tshark kind="+terr.Kind))
			return out
		}
	}
	if fileTruncated || anyCaptureTruncated(packets) {
		out.Findings = append(out.Findings, diagnoseFinding(DiagnoseFindingCaptureTruncated, "info", "packet_bytes_truncated=true"))
	}
	if len(packets) == 0 {
		out.Findings = append(out.Findings, diagnoseFinding(DiagnoseFindingFlowUnparseable, "warning", "packet_count=0"))
		return out
	}

	flows := buildDiagnoseFlows(packets, input.Scope)
	if filter[DiagnoseSymptomTLSHandshakeAttemptedOnPlainPort] {
		out.Symptoms = append(out.Symptoms, diagnoseTLSHandshakeAttemptedOnPlainPort(flows, forceLowConfidence)...)
	}
	if filter[DiagnoseSymptomTCPRSTAfterSYNACKNoAppData] {
		out.Symptoms = append(out.Symptoms, diagnoseTCPRSTAfterSYNACKNoAppData(flows, forceLowConfidence)...)
	}
	if filter[DiagnoseSymptomMonitorProbeReturnsRST] {
		duration := captureDurationSeconds(packets)
		if duration < diagnoseMinCadenceWindowSeconds {
			out.Findings = append(out.Findings, diagnoseFinding(DiagnoseFindingWindowTooShort, "info", fmt.Sprintf("duration_seconds=%.3f minimum_seconds=%d", duration, diagnoseMinCadenceWindowSeconds)))
		} else {
			out.Symptoms = append(out.Symptoms, diagnoseMonitorProbeReturnsRST(flows, forceLowConfidence)...)
		}
	}
	if filter[DiagnoseSymptomAsymmetricReturnPathObserved] {
		if !captureHasInterfaceMetadata(packets) {
			out.Findings = append(out.Findings, diagnoseFinding(DiagnoseFindingLacksInterfaceMetadata, "info", "interface_metadata=false"))
		} else {
			out.Symptoms = append(out.Symptoms, diagnoseAsymmetricReturnPathObserved(flows, forceLowConfidence)...)
		}
	}
	sortDiagnoseSymptoms(out.Symptoms)
	return out
}

func diagnoseParseTimeout() time.Duration {
	if diagnoseDefaultParseTimeout > diagnoseHardMaxParseTimeout {
		return diagnoseHardMaxParseTimeout
	}
	return diagnoseDefaultParseTimeout
}

func diagnoseFilter(tokens []string) map[string]bool {
	filter := map[string]bool{}
	if len(tokens) == 0 {
		for _, token := range diagnoseSymptomVocabulary {
			filter[token] = true
		}
		return filter
	}
	for _, token := range tokens {
		if diagnoseSymptomSet[token] {
			filter[token] = true
		}
	}
	return filter
}

func runDiagnoseTSharkFields(parent context.Context, path string, timeout time.Duration, maxBytes int) ([]diagnosePacket, bool, error) {
	args := []string{
		"-n",
		"-r", path,
		"-Y", "tcp",
		"-T", "fields",
		"-E", "header=y",
		"-E", "separator=/t",
		"-E", "quote=d",
		"-E", "occurrence=f",
		"-e", "frame.number",
		"-e", "frame.time_relative",
		"-e", "frame.interface_id",
		"-e", "frame.interface_name",
		"-e", "frame.len",
		"-e", "frame.cap_len",
		"-e", "ip.src",
		"-e", "ipv6.src",
		"-e", "ip.dst",
		"-e", "ipv6.dst",
		"-e", "tcp.srcport",
		"-e", "tcp.dstport",
		"-e", "tcp.flags.syn",
		"-e", "tcp.flags.ack",
		"-e", "tcp.flags.reset",
		"-e", "tcp.len",
		"-e", "tcp.payload",
	}
	out, truncated, err := runAnalyzerCommandTolerant(parent, timeout, maxBytes, "tshark", args, "")
	if err != nil {
		packets, parseErr := parseDiagnoseTSharkFields(out.Stdout)
		if parseErr == nil {
			return packets, truncated, err
		}
		return nil, truncated, err
	}
	packets, parseErr := parseDiagnoseTSharkFields(out.Stdout)
	if parseErr != nil {
		return nil, truncated, parseErr
	}
	return packets, truncated, nil
}

func parseDiagnoseTSharkFields(raw string) ([]diagnosePacket, error) {
	reader := csv.NewReader(strings.NewReader(raw))
	reader.Comma = '\t'
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("%w: parse diagnose tshark fields: %v", errAnalyzerFailed, err)
	}
	if len(records) <= 1 {
		return nil, nil
	}
	packets := make([]diagnosePacket, 0, len(records)-1)
	for _, record := range records[1:] {
		field := func(idx int) string {
			if idx >= len(record) {
				return ""
			}
			return strings.TrimSpace(record[idx])
		}
		srcPort, _ := strconv.Atoi(field(10))
		dstPort, _ := strconv.Atoi(field(11))
		frameLen, _ := strconv.Atoi(field(4))
		frameCapLen, _ := strconv.Atoi(field(5))
		tcpLen, _ := strconv.Atoi(field(15))
		packet := diagnosePacket{
			Number:        atoiDefault(field(0), 0),
			TimeRelative:  atofDefault(field(1), 0),
			InterfaceID:   field(2),
			InterfaceName: field(3),
			FrameLen:      frameLen,
			FrameCapLen:   frameCapLen,
			SrcIP:         firstNonEmpty(field(6), field(7)),
			DstIP:         firstNonEmpty(field(8), field(9)),
			SrcPort:       srcPort,
			DstPort:       dstPort,
			Protocol:      "tcp",
			SYN:           parseTSharkBool(field(12)),
			ACK:           parseTSharkBool(field(13)),
			RST:           parseTSharkBool(field(14)),
			TCPLen:        tcpLen,
			PayloadHex:    strings.ToLower(strings.ReplaceAll(field(16), ":", "")),
		}
		packet.CaptureTruncated = packet.FrameCapLen > 0 && packet.FrameLen > packet.FrameCapLen
		if packet.SrcIP == "" || packet.DstIP == "" || packet.SrcPort == 0 || packet.DstPort == 0 {
			continue
		}
		packets = append(packets, packet)
	}
	return packets, nil
}

func buildDiagnoseFlows(packets []diagnosePacket, scope *diagnoseScope) []*diagnoseFlowState {
	byKey := map[string]*diagnoseFlowState{}
	for _, packet := range packets {
		key := diagnoseCanonicalFlowKey(packet)
		if key == "" {
			continue
		}
		flow := byKey[key]
		if flow == nil {
			flow = &diagnoseFlowState{}
			byKey[key] = flow
		}
		if flow.Flow.Protocol == "" || flow.originWasInferred {
			if packet.SYN && !packet.ACK {
				flow.Flow = diagnosePacketFlow(packet)
				flow.originWasInferred = false
			} else if packet.SYN && packet.ACK {
				flow.Flow = diagnoseReversePacketFlow(packet)
				flow.originWasInferred = false
			} else if flow.Flow.Protocol == "" {
				flow.Flow = diagnosePacketFlow(packet)
				flow.originWasInferred = true
			}
		}
		flow.Packets = append(flow.Packets, packet)
		if packet.CaptureTruncated {
			flow.HasTruncation = true
		}
	}
	flows := make([]*diagnoseFlowState, 0, len(byKey))
	for _, flow := range byKey {
		sort.Slice(flow.Packets, func(i, j int) bool {
			return flow.Packets[i].TimeRelative < flow.Packets[j].TimeRelative
		})
		if scope == nil || diagnoseFlowMatchesScope(flow.Flow, *scope) {
			flows = append(flows, flow)
		}
	}
	sort.Slice(flows, func(i, j int) bool {
		return flowFirstTime(flows[i]) < flowFirstTime(flows[j])
	})
	return flows
}

func diagnoseTLSHandshakeAttemptedOnPlainPort(flows []*diagnoseFlowState, forceLow bool) []DiagnoseSymptom {
	var symptoms []DiagnoseSymptom
	for _, flow := range flows {
		clientHelloIndex := -1
		tlsVersion := ""
		for idx, packet := range flow.Packets {
			if !diagnoseIsClientToServer(flow, packet) {
				continue
			}
			payload := decodePacketPayload(packet)
			if isTLSClientHello(payload) {
				clientHelloIndex = idx
				tlsVersion = tlsClientHelloVersion(payload)
				break
			}
		}
		if clientHelloIndex < 0 {
			continue
		}
		serverResponseKind := "none"
		serverHelloObserved := false
		for _, packet := range flow.Packets[clientHelloIndex+1:] {
			if diagnoseIsClientToServer(flow, packet) {
				continue
			}
			payload := decodePacketPayload(packet)
			switch {
			case isTLSServerHello(payload):
				serverHelloObserved = true
			case packet.RST:
				serverResponseKind = "rst"
			case len(payload) > 0 && isHTTPPlaintext(payload):
				serverResponseKind = "http_plaintext"
			case len(payload) > 0 && !isTLSRecord(payload):
				serverResponseKind = "other_plaintext"
			}
			if serverResponseKind != "none" || serverHelloObserved {
				break
			}
		}
		if serverHelloObserved {
			continue
		}
		trueValue := true
		evidence := baseDiagnoseEvidence(flow)
		evidence.ClientHelloObserved = &trueValue
		evidence.ServerResponseKind = serverResponseKind
		evidence.TLSVersionOffered = tlsVersion
		symptoms = append(symptoms, DiagnoseSymptom{
			Code:       DiagnoseSymptomTLSHandshakeAttemptedOnPlainPort,
			Severity:   "warning",
			Confidence: diagnoseConfidence("high", forceLow || flow.HasTruncation),
			Evidence:   evidence,
			Narrative:  "TLS Client Hello was observed, but the responder did not return a TLS Server Hello on this flow.",
		})
	}
	return symptoms
}

func diagnoseTCPRSTAfterSYNACKNoAppData(flows []*diagnoseFlowState, forceLow bool) []DiagnoseSymptom {
	var symptoms []DiagnoseSymptom
	for _, flow := range flows {
		synSeen := false
		synAckSeen := false
		finalACKSeen := false
		finalACKTime := 0.0
		appBytesC2S := 0
		appBytesS2C := 0
		var rstPacket *diagnosePacket
		for i := range flow.Packets {
			packet := flow.Packets[i]
			c2s := diagnoseIsClientToServer(flow, packet)
			switch {
			case c2s && packet.SYN && !packet.ACK:
				synSeen = true
			case !c2s && packet.SYN && packet.ACK && synSeen:
				synAckSeen = true
			case c2s && packet.ACK && !packet.SYN && !packet.RST && packet.TCPLen == 0 && synAckSeen:
				finalACKSeen = true
				finalACKTime = packet.TimeRelative
			case !c2s && packet.RST && finalACKSeen:
				p := packet
				rstPacket = &p
			}
			if finalACKSeen && rstPacket == nil && packet.TCPLen > 0 {
				if c2s {
					appBytesC2S += packet.TCPLen
				} else {
					appBytesS2C += packet.TCPLen
				}
			}
			if rstPacket != nil {
				break
			}
		}
		if !(synSeen && synAckSeen && finalACKSeen && rstPacket != nil) {
			continue
		}
		if appBytesC2S != 0 || appBytesS2C != 0 {
			continue
		}
		trueValue := true
		timeToRST := msOffset(rstPacket.TimeRelative - finalACKTime)
		evidence := baseDiagnoseEvidence(flow)
		evidence.HandshakeCompleted = &trueValue
		evidence.AppBytesClientToServer = intPtr(0)
		evidence.AppBytesServerToClient = intPtr(0)
		evidence.TimeToRSTMS = &timeToRST
		symptoms = append(symptoms, DiagnoseSymptom{
			Code:       DiagnoseSymptomTCPRSTAfterSYNACKNoAppData,
			Severity:   "warning",
			Confidence: diagnoseConfidence("high", forceLow || flow.HasTruncation),
			Evidence:   evidence,
			Narrative:  "TCP handshake completed and the responder reset the flow before application bytes were exchanged.",
		})
	}
	return symptoms
}

func diagnoseMonitorProbeReturnsRST(flows []*diagnoseFlowState, forceLow bool) []DiagnoseSymptom {
	groups := map[string][]*diagnoseFlowState{}
	for _, flow := range flows {
		if !diagnoseShortProbeCandidate(flow) {
			continue
		}
		key := strings.Join([]string{
			flow.Flow.SrcIP,
			flow.Flow.DstIP,
			strconv.Itoa(derefInt(flow.Flow.DstPort)),
			flow.Flow.Protocol,
		}, "|")
		groups[key] = append(groups[key], flow)
	}
	var symptoms []DiagnoseSymptom
	for _, group := range groups {
		if len(group) < 3 {
			continue
		}
		sort.Slice(group, func(i, j int) bool {
			return flowFirstTime(group[i]) < flowFirstTime(group[j])
		})
		rstCount := 0
		truncated := forceLow
		times := make([]float64, 0, len(group))
		for _, flow := range group {
			if diagnoseFlowHasServerRST(flow) {
				rstCount++
			}
			if flow.HasTruncation {
				truncated = true
			}
			times = append(times, flowFirstTime(flow))
		}
		rstRatio := float64(rstCount) / float64(len(group))
		cadence := p50CadenceSeconds(times)
		if rstRatio < 0.9 || cadence > diagnoseMonitorCadenceMaxSeconds {
			continue
		}
		evidence := baseDiagnoseEvidence(group[0])
		evidence.PacketCount = 0
		for _, flow := range group {
			evidence.PacketCount += len(flow.Packets)
			if flowFirstTime(flow) < float64(evidence.FirstSeenOffsetMS)/1000 {
				evidence.FirstSeenOffsetMS = msOffset(flowFirstTime(flow))
			}
			if flowLastTime(flow) > float64(evidence.LastSeenOffsetMS)/1000 {
				evidence.LastSeenOffsetMS = msOffset(flowLastTime(flow))
			}
		}
		evidence.ProbeCount = len(group)
		evidence.ProbeCadenceSecondsP50 = roundFloat(cadence, 3)
		evidence.RSTRatio = roundFloat(rstRatio, 3)
		symptoms = append(symptoms, DiagnoseSymptom{
			Code:       DiagnoseSymptomMonitorProbeReturnsRST,
			Severity:   "info",
			Confidence: diagnoseConfidence("medium", truncated),
			Evidence:   evidence,
			Narrative:  "Repeated short probes to the same TCP service were reset by the responder.",
		})
	}
	return symptoms
}

func diagnoseAsymmetricReturnPathObserved(flows []*diagnoseFlowState, forceLow bool) []DiagnoseSymptom {
	var symptoms []DiagnoseSymptom
	for _, flow := range flows {
		var synPacket *diagnosePacket
		var sameInterfaceSynAck *diagnosePacket
		var otherInterfaceSynAck *diagnosePacket
		interfaces := map[string]bool{}
		for i := range flow.Packets {
			packet := flow.Packets[i]
			if packet.InterfaceName != "" {
				interfaces[packet.InterfaceName] = true
			} else if packet.InterfaceID != "" {
				interfaces["id:"+packet.InterfaceID] = true
			}
			if diagnoseIsClientToServer(flow, packet) && packet.SYN && !packet.ACK {
				p := packet
				synPacket = &p
			}
		}
		if synPacket == nil {
			continue
		}
		for i := range flow.Packets {
			packet := flow.Packets[i]
			if diagnoseIsClientToServer(flow, packet) || !packet.SYN || !packet.ACK {
				continue
			}
			p := packet
			if sameDiagnoseInterface(*synPacket, packet) {
				sameInterfaceSynAck = &p
			} else {
				otherInterfaceSynAck = &p
			}
		}
		if sameInterfaceSynAck != nil {
			continue
		}
		if otherInterfaceSynAck == nil {
			// No return packet at all can be a one-sided capture. Keep the
			// symptom, but the confidence remains medium per the contract.
		}
		trueValue := true
		synAckSeen := otherInterfaceSynAck != nil
		flowCompleteOther := otherInterfaceSynAck != nil
		evidence := baseDiagnoseEvidence(flow)
		evidence.SynSeen = &trueValue
		evidence.SynAckSeen = &synAckSeen
		evidence.InterfacesObserved = sortedMapKeys(interfaces)
		evidence.FlowCompleteViaOtherInterface = &flowCompleteOther
		symptoms = append(symptoms, DiagnoseSymptom{
			Code:       DiagnoseSymptomAsymmetricReturnPathObserved,
			Severity:   "warning",
			Confidence: diagnoseConfidence("medium", forceLow || flow.HasTruncation),
			Evidence:   evidence,
			Narrative:  "Return traffic for a TCP SYN was not observed on the same capture interface.",
		})
	}
	return symptoms
}

func diagnoseShortProbeCandidate(flow *diagnoseFlowState) bool {
	if flow.Flow.Protocol != "tcp" {
		return false
	}
	c2sBytes := 0
	for _, packet := range flow.Packets {
		if diagnoseIsClientToServer(flow, packet) {
			c2sBytes += packet.TCPLen
		}
	}
	return c2sBytes <= diagnoseMonitorPayloadMaxBytes && diagnoseFlowHasServerRST(flow)
}

func diagnoseFlowHasServerRST(flow *diagnoseFlowState) bool {
	for _, packet := range flow.Packets {
		if !diagnoseIsClientToServer(flow, packet) && packet.RST {
			return true
		}
	}
	return false
}

func baseDiagnoseEvidence(flow *diagnoseFlowState) DiagnoseSymptomEvidence {
	return DiagnoseSymptomEvidence{
		Flow:              flow.Flow,
		PacketCount:       len(flow.Packets),
		FirstSeenOffsetMS: msOffset(flowFirstTime(flow)),
		LastSeenOffsetMS:  msOffset(flowLastTime(flow)),
	}
}

func diagnosePacketFlow(packet diagnosePacket) DiagnoseFlowEvidence {
	return DiagnoseFlowEvidence{
		SrcIP:    packet.SrcIP,
		DstIP:    packet.DstIP,
		SrcPort:  intPtr(packet.SrcPort),
		DstPort:  intPtr(packet.DstPort),
		Protocol: packet.Protocol,
	}
}

func diagnoseReversePacketFlow(packet diagnosePacket) DiagnoseFlowEvidence {
	return DiagnoseFlowEvidence{
		SrcIP:    packet.DstIP,
		DstIP:    packet.SrcIP,
		SrcPort:  intPtr(packet.DstPort),
		DstPort:  intPtr(packet.SrcPort),
		Protocol: packet.Protocol,
	}
}

func diagnoseIsClientToServer(flow *diagnoseFlowState, packet diagnosePacket) bool {
	return flow.Flow.SrcIP == packet.SrcIP &&
		flow.Flow.DstIP == packet.DstIP &&
		derefInt(flow.Flow.SrcPort) == packet.SrcPort &&
		derefInt(flow.Flow.DstPort) == packet.DstPort
}

func diagnoseFlowMatchesScope(flow DiagnoseFlowEvidence, scope diagnoseScope) bool {
	if scope.Protocol != "" && strings.ToLower(scope.Protocol) != flow.Protocol {
		return false
	}
	if scope.SrcIP != "" && scope.SrcIP != flow.SrcIP {
		return false
	}
	if scope.DstIP != "" && scope.DstIP != flow.DstIP {
		return false
	}
	if scope.SrcPort != nil && *scope.SrcPort != derefInt(flow.SrcPort) {
		return false
	}
	if scope.DstPort != nil && *scope.DstPort != derefInt(flow.DstPort) {
		return false
	}
	return true
}

func diagnoseCanonicalFlowKey(packet diagnosePacket) string {
	a := fmt.Sprintf("%s:%d", packet.SrcIP, packet.SrcPort)
	b := fmt.Sprintf("%s:%d", packet.DstIP, packet.DstPort)
	if a == ":" || b == ":" {
		return ""
	}
	if a < b {
		return packet.Protocol + "|" + a + "|" + b
	}
	return packet.Protocol + "|" + b + "|" + a
}

func isTLSClientHello(payload []byte) bool {
	return len(payload) >= 6 && isTLSRecord(payload) && payload[5] == 0x01
}

func isTLSServerHello(payload []byte) bool {
	return len(payload) >= 6 && isTLSRecord(payload) && payload[5] == 0x02
}

func isTLSRecord(payload []byte) bool {
	if len(payload) < 5 {
		return false
	}
	if payload[0] != 0x16 {
		return false
	}
	return payload[1] == 0x03 && payload[2] >= 0x00 && payload[2] <= 0x04
}

func tlsClientHelloVersion(payload []byte) string {
	if len(payload) < 11 {
		return ""
	}
	return tlsVersionName(payload[9], payload[10])
}

func tlsVersionName(major, minor byte) string {
	if major != 0x03 {
		return fmt.Sprintf("0x%02x%02x", major, minor)
	}
	switch minor {
	case 0x00:
		return "SSL3.0"
	case 0x01:
		return "TLS1.0"
	case 0x02:
		return "TLS1.1"
	case 0x03:
		return "TLS1.2"
	case 0x04:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%02x%02x", major, minor)
	}
}

func isHTTPPlaintext(payload []byte) bool {
	prefixes := [][]byte{
		[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("DELETE "),
		[]byte("HEAD "), []byte("OPTIONS "), []byte("PATCH "), []byte("TRACE "),
		[]byte("CONNECT "), []byte("HTTP/1."),
	}
	for _, prefix := range prefixes {
		if len(payload) >= len(prefix) && string(payload[:len(prefix)]) == string(prefix) {
			return true
		}
	}
	return false
}

func decodePacketPayload(packet diagnosePacket) []byte {
	if packet.PayloadHex == "" {
		return nil
	}
	payload, err := hex.DecodeString(packet.PayloadHex)
	if err != nil {
		return nil
	}
	return payload
}

func captureDurationSeconds(packets []diagnosePacket) float64 {
	if len(packets) == 0 {
		return 0
	}
	minTime := packets[0].TimeRelative
	maxTime := packets[0].TimeRelative
	for _, packet := range packets[1:] {
		if packet.TimeRelative < minTime {
			minTime = packet.TimeRelative
		}
		if packet.TimeRelative > maxTime {
			maxTime = packet.TimeRelative
		}
	}
	return maxTime - minTime
}

func captureHasInterfaceMetadata(packets []diagnosePacket) bool {
	for _, packet := range packets {
		if packet.InterfaceName != "" {
			return true
		}
	}
	return false
}

func anyCaptureTruncated(packets []diagnosePacket) bool {
	for _, packet := range packets {
		if packet.CaptureTruncated {
			return true
		}
	}
	return false
}

func sameDiagnoseInterface(a, b diagnosePacket) bool {
	if a.InterfaceName != "" || b.InterfaceName != "" {
		return a.InterfaceName != "" && a.InterfaceName == b.InterfaceName
	}
	return a.InterfaceID != "" && a.InterfaceID == b.InterfaceID
}

func flowFirstTime(flow *diagnoseFlowState) float64 {
	if len(flow.Packets) == 0 {
		return 0
	}
	return flow.Packets[0].TimeRelative
}

func flowLastTime(flow *diagnoseFlowState) float64 {
	if len(flow.Packets) == 0 {
		return 0
	}
	return flow.Packets[len(flow.Packets)-1].TimeRelative
}

func p50CadenceSeconds(times []float64) float64 {
	if len(times) < 2 {
		return 0
	}
	intervals := make([]float64, 0, len(times)-1)
	for i := 1; i < len(times); i++ {
		intervals = append(intervals, times[i]-times[i-1])
	}
	sort.Float64s(intervals)
	return intervals[len(intervals)/2]
}

func diagnoseConfidence(defaultConfidence string, low bool) string {
	if low {
		return "low"
	}
	return defaultConfidence
}

func diagnoseFinding(code, severity, detail string) DiagnoseFinding {
	return DiagnoseFinding{
		Code:     code,
		Severity: severity,
		Detail:   boundDiagnoseDetail(detail),
	}
}

func boundDiagnoseDetail(detail string) string {
	detail = strings.Map(func(r rune) rune {
		if r == '\x00' || r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, strings.TrimSpace(detail))
	if len(detail) > diagnoseMaxFindingDetailBytes {
		return detail[:diagnoseMaxFindingDetailBytes] + "...[truncated]"
	}
	return detail
}

func validDiagnoseTokenShape(token string) bool {
	if token == "" || len(token) > 128 {
		return false
	}
	for _, r := range token {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			continue
		}
		return false
	}
	return true
}

func parseTSharkBool(value string) bool {
	return strings.EqualFold(value, "true") || value == "1"
}

func atoiDefault(value string, fallback int) int {
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func atofDefault(value string, fallback float64) float64 {
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func msOffset(seconds float64) int64 {
	return int64(math.Round(seconds * 1000))
}

func intPtr(value int) *int {
	return &value
}

func derefInt(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}

func roundFloat(value float64, places int) float64 {
	scale := math.Pow10(places)
	return math.Round(value*scale) / scale
}

func sortedMapKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortDiagnoseSymptoms(symptoms []DiagnoseSymptom) {
	sort.SliceStable(symptoms, func(i, j int) bool {
		if symptoms[i].Code != symptoms[j].Code {
			return symptoms[i].Code < symptoms[j].Code
		}
		if symptoms[i].Evidence.FirstSeenOffsetMS != symptoms[j].Evidence.FirstSeenOffsetMS {
			return symptoms[i].Evidence.FirstSeenOffsetMS < symptoms[j].Evidence.FirstSeenOffsetMS
		}
		return symptoms[i].Evidence.LastSeenOffsetMS < symptoms[j].Evidence.LastSeenOffsetMS
	})
}
