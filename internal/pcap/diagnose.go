package pcap

import (
	"context"
	"encoding/csv"
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"cute-pcap-mcp/internal/config"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const DiagnoseSchemaVersion = "1.0.0"

const (
	SymptomTLSHandshakeAttemptedOnPlainPort = "tls_handshake_attempted_on_plain_port"
	SymptomTCPRSTAfterSYNACKNoAppData       = "tcp_rst_after_synack_no_app_data"
	SymptomMonitorProbeReturnsRST           = "monitor_probe_returns_rst"
	SymptomAsymmetricReturnPathObserved     = "asymmetric_return_path_observed"
)

const (
	FindingDiagnoseFlowUnparseable        = "pcap_diagnose_flow_unparseable"
	FindingDiagnoseCaptureTruncated       = "pcap_diagnose_capture_truncated"
	FindingDiagnoseWindowTooShort         = "pcap_diagnose_window_too_short"
	FindingDiagnoseParseTimeout           = "pcap_diagnose_parse_timeout"
	FindingDiagnoseLacksInterfaceMetadata = "pcap_diagnose_capture_lacks_interface_metadata"
	FindingDiagnoseUnrecognizedPattern    = "pcap_diagnose_unrecognized_pattern_observed"
	FindingDiagnoseInputInvalid           = "pcap_diagnose_input_invalid"
	FindingDiagnosePathInvalid            = "pcap_diagnose_path_invalid"
	FindingDiagnoseArtifactMismatch       = "pcap_diagnose_artifact_mismatch"
)

const (
	diagnoseMinCadenceWindowMS = 90_000
	diagnoseMaxProbeCadenceMS  = 30_000
	diagnoseMaxProbePayload    = 256
	diagnoseMinProbeCount      = 3
)

type diagnoseInput struct {
	Path              string         `json:"path,omitempty" jsonschema:"absolute or relative path to a pcap/pcapng under an allowed artifact directory; required by the tool and validated fail-closed"`
	ExpectedSHA256    string         `json:"expected_sha256,omitempty" jsonschema:"optional caller-provided sha256 from an external artifact reference; must be exactly 64 hex digits if set"`
	ExpectedSizeBytes *int64         `json:"expected_size_bytes,omitempty" jsonschema:"optional caller-provided file size in bytes from an external artifact reference; must be non-negative if set"`
	Scope             *diagnoseScope `json:"scope,omitempty" jsonschema:"optional flow scope; v1 symptoms are TCP-only but protocol may be tcp, udp, or icmp"`
	SymptomFilter     []string       `json:"symptom_filter,omitempty" jsonschema:"optional closed-vocabulary subset of symptoms to evaluate; unknown tokens fail closed"`
}

type diagnoseScope struct {
	SourceIP        string `json:"src_ip,omitempty" jsonschema:"optional source IP for flow narrowing"`
	DestinationIP   string `json:"dst_ip,omitempty" jsonschema:"optional destination IP for flow narrowing"`
	SourcePort      *int   `json:"src_port,omitempty" jsonschema:"optional source port for TCP/UDP flow narrowing"`
	DestinationPort *int   `json:"dst_port,omitempty" jsonschema:"optional destination port for TCP/UDP flow narrowing"`
	Protocol        string `json:"protocol,omitempty" jsonschema:"optional protocol for flow narrowing: tcp, udp, or icmp"`
}

type diagnoseOutput struct {
	SchemaVersion string            `json:"schema_version"`
	Path          string            `json:"path,omitempty"`
	SizeBytes     int64             `json:"size_bytes,omitempty"`
	SHA256        string            `json:"sha256,omitempty"`
	Symptoms      []diagnoseSymptom `json:"symptoms"`
	Findings      []diagnoseFinding `json:"findings"`
}

type diagnoseSymptom struct {
	Code       string           `json:"code"`
	Severity   string           `json:"severity"`
	Confidence string           `json:"confidence"`
	Evidence   diagnoseEvidence `json:"evidence"`
	Narrative  string           `json:"narrative"`
}

type diagnoseEvidence struct {
	Flow                          *diagnoseFlow `json:"flow,omitempty"`
	PacketCount                   int           `json:"packet_count,omitempty"`
	PacketNumbers                 []int         `json:"packet_numbers,omitempty"`
	FirstSeenOffsetMS             int64         `json:"first_seen_offset_ms,omitempty"`
	LastSeenOffsetMS              int64         `json:"last_seen_offset_ms,omitempty"`
	ClientHelloObserved           *bool         `json:"client_hello_observed,omitempty"`
	ServerResponseKind            string        `json:"server_response_kind,omitempty"`
	TLSVersionOffered             string        `json:"tls_version_offered,omitempty"`
	HandshakeCompleted            *bool         `json:"handshake_completed,omitempty"`
	AppBytesClientToServer        int           `json:"app_bytes_client_to_server,omitempty"`
	AppBytesServerToClient        int           `json:"app_bytes_server_to_client,omitempty"`
	TimeToRSTMS                   int64         `json:"time_to_rst_ms,omitempty"`
	ProbeCount                    int           `json:"probe_count,omitempty"`
	ProbeCadenceSecondsP50        float64       `json:"probe_cadence_seconds_p50,omitempty"`
	RSTRatio                      float64       `json:"rst_ratio,omitempty"`
	SYNSeen                       *bool         `json:"syn_seen,omitempty"`
	SYNACKSeen                    *bool         `json:"syn_ack_seen,omitempty"`
	InterfacesObserved            []string      `json:"interfaces_observed,omitempty"`
	FlowCompleteViaOtherInterface *bool         `json:"flow_complete_via_other_interface,omitempty"`
}

type diagnoseFlow struct {
	SourceIP        string `json:"src_ip"`
	DestinationIP   string `json:"dst_ip"`
	SourcePort      int    `json:"src_port,omitempty"`
	DestinationPort int    `json:"dst_port,omitempty"`
	Protocol        string `json:"protocol"`
}

type diagnoseFinding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Detail   string `json:"detail,omitempty"`
}

type diagnosePacket struct {
	Number            int
	TimeMS            int64
	FrameLen          int
	CapturedLen       int
	InterfaceID       string
	InterfaceName     string
	SrcIP             string
	DstIP             string
	SrcPort           int
	DstPort           int
	Protocol          string
	SYN               bool
	ACK               bool
	RST               bool
	FIN               bool
	TCPLen            int
	DataLen           int
	TLSHandshakeTypes []int
	TLSRecordVersion  string
	HTTPPlaintext     bool
}

func (p diagnosePacket) interfaceLabel() string {
	if p.InterfaceName != "" {
		return p.InterfaceName
	}
	if p.InterfaceID != "" {
		return "if" + p.InterfaceID
	}
	return ""
}

func (p diagnosePacket) truncated() bool {
	return p.FrameLen > 0 && p.CapturedLen > 0 && p.CapturedLen < p.FrameLen
}

type diagnoseEndpoint struct {
	ip   string
	port int
}

type diagnoseFlowGroup struct {
	flow    diagnoseFlow
	packets []diagnosePacket
}

type diagnoseRunOptions struct {
	enabled map[string]bool
	scope   *diagnoseScope
}

func (s *serverState) diagnoseHandler(toolName string) func(ctx context.Context, _ *mcp.CallToolRequest, input diagnoseInput) (*mcp.CallToolResult, diagnoseOutput, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, input diagnoseInput) (*mcp.CallToolResult, diagnoseOutput, error) {
		s.logger.InfoContext(ctx, "tool.start", slog.String("tool", toolName))
		out := newDiagnoseOutput()

		if err := validateDiagnoseInput(input); err != nil {
			finding := diagnoseFindingForError(err)
			out.Findings = append(out.Findings, finding)
			s.logger.InfoContext(ctx, "tool.result", slog.String("tool", toolName), slog.String("outcome", "fail_closed"), slog.String("finding", finding.Code))
			return nil, out, nil
		}

		artifact, err := inspectArtifact(input.Path, s.cfg, artifactExpectations{
			SHA256:    input.ExpectedSHA256,
			SizeBytes: input.ExpectedSizeBytes,
		})
		if err != nil {
			finding := diagnoseFindingForError(err)
			out.Findings = append(out.Findings, finding)
			s.logger.InfoContext(ctx, "tool.result", slog.String("tool", toolName), slog.String("outcome", "fail_closed"), slog.String("finding", finding.Code))
			return nil, out, nil
		}
		out.Path = artifact.Path
		out.SizeBytes = artifact.SizeBytes
		out.SHA256 = artifact.SHA256

		if err := s.acquireAnalyzerSlot(); err != nil {
			finding := diagnoseAnalyzerFinding(err)
			out.Findings = append(out.Findings, finding)
			s.logger.InfoContext(ctx, "tool.result", slog.String("tool", toolName), slog.String("outcome", "partial_success"), slog.String("finding", finding.Code))
			return nil, out, nil
		}
		defer s.releaseAnalyzerSlot()

		packets, truncated, err := runDiagnosePacketRows(ctx, artifact, s.cfg)
		if err != nil {
			finding := diagnoseAnalyzerFinding(err)
			out.Findings = append(out.Findings, finding)
			s.logger.InfoContext(ctx, "tool.result", slog.String("tool", toolName), slog.String("outcome", "partial_success"), slog.String("finding", finding.Code))
			return nil, out, nil
		}
		if truncated || packetsContainTruncation(packets) {
			out.Findings = append(out.Findings, diagnoseFinding{
				Code:     FindingDiagnoseCaptureTruncated,
				Severity: "info",
				Detail:   "capture truncation observed by packet metadata or analyzer diagnostic",
			})
		}

		symptoms, findings := diagnoseSymptomsFromPackets(packets, diagnoseRunOptions{
			enabled: enabledDiagnoseSymptoms(input.SymptomFilter),
			scope:   input.Scope,
		})
		out.Symptoms = append(out.Symptoms, symptoms...)
		out.Findings = append(out.Findings, findings...)

		outcome := "success"
		if len(out.Findings) > 0 {
			outcome = "partial_success"
		}
		s.logger.InfoContext(ctx, "tool.result",
			slog.String("tool", toolName),
			slog.String("outcome", outcome),
			slog.Int("symptom_count", len(out.Symptoms)),
			slog.Int("finding_count", len(out.Findings)),
		)
		return nil, out, nil
	}
}

func newDiagnoseOutput() diagnoseOutput {
	return diagnoseOutput{
		SchemaVersion: DiagnoseSchemaVersion,
		Symptoms:      []diagnoseSymptom{},
		Findings:      []diagnoseFinding{},
	}
}

func validateDiagnoseInput(input diagnoseInput) error {
	if strings.TrimSpace(input.Path) == "" {
		return missingFieldError("path")
	}
	if err := validateArtifactExpectations(input.ExpectedSHA256, input.ExpectedSizeBytes); err != nil {
		return err
	}
	if err := validateDiagnoseScope(input.Scope); err != nil {
		return err
	}
	for _, token := range input.SymptomFilter {
		if !isDiagnoseSymptomCode(token) {
			return validationError("symptom_filter", ValidationReasonInvalidFormat, "unknown symptom_filter token: "+token)
		}
	}
	return nil
}

func validateDiagnoseScope(scope *diagnoseScope) error {
	if scope == nil {
		return nil
	}
	for _, slot := range []struct {
		field string
		value string
	}{
		{"scope.src_ip", scope.SourceIP},
		{"scope.dst_ip", scope.DestinationIP},
	} {
		if strings.TrimSpace(slot.value) == "" {
			continue
		}
		if _, err := netip.ParseAddr(strings.TrimSpace(slot.value)); err != nil {
			return validationError(slot.field, ValidationReasonInvalidFormat, slot.field+" must be a valid IP address")
		}
	}
	for _, slot := range []struct {
		field string
		value *int
	}{
		{"scope.src_port", scope.SourcePort},
		{"scope.dst_port", scope.DestinationPort},
	} {
		if slot.value == nil {
			continue
		}
		if *slot.value < 0 || *slot.value > 65535 {
			return validationError(slot.field, ValidationReasonOutOfRange, slot.field+" must be in [0, 65535]")
		}
	}
	protocol := strings.ToLower(strings.TrimSpace(scope.Protocol))
	if protocol != "" && protocol != "tcp" && protocol != "udp" && protocol != "icmp" {
		return validationError("scope.protocol", ValidationReasonInvalidFormat, "scope.protocol must be tcp, udp, or icmp")
	}
	if protocol == "icmp" && (scope.SourcePort != nil || scope.DestinationPort != nil) {
		return validationError("scope", ValidationReasonInvalidFormat, "icmp scope must not set src_port or dst_port")
	}
	return nil
}

func diagnoseFindingForError(err error) diagnoseFinding {
	terr := classify(err)
	detail := boundedDiagnoseDetail(diagnoseToolErrorDetail(terr))
	switch terr.Kind {
	case ErrorKindHashMismatch, ErrorKindSizeMismatch:
		return diagnoseFinding{Code: FindingDiagnoseArtifactMismatch, Severity: "error", Detail: detail}
	case ErrorKindPathOutsideAllowlist, ErrorKindArtifactNotRegularFile, ErrorKindArtifactNotFound, ErrorKindPCAPTooLarge:
		return diagnoseFinding{Code: FindingDiagnosePathInvalid, Severity: "error", Detail: detail}
	default:
		return diagnoseFinding{Code: FindingDiagnoseInputInvalid, Severity: "error", Detail: detail}
	}
}

func diagnoseToolErrorDetail(terr toolError) string {
	var parts []string
	if terr.Kind != "" {
		parts = append(parts, "kind="+terr.Kind)
	}
	if terr.Field != "" {
		parts = append(parts, "field="+terr.Field)
	}
	if terr.Reason != "" {
		parts = append(parts, "reason="+terr.Reason)
	}
	if len(parts) == 0 {
		return "input rejected"
	}
	return strings.Join(parts, " ")
}

func diagnoseAnalyzerFinding(err error) diagnoseFinding {
	terr := classify(err)
	if terr.Kind == ErrorKindAnalyzerTimeout {
		return diagnoseFinding{
			Code:     FindingDiagnoseParseTimeout,
			Severity: "warning",
			Detail:   "kind=" + terr.Kind,
		}
	}
	return diagnoseFinding{
		Code:     FindingDiagnoseFlowUnparseable,
		Severity: "warning",
		Detail:   boundedDiagnoseDetail("kind=" + terr.Kind),
	}
}

func boundedDiagnoseDetail(detail string) string {
	detail = strings.TrimSpace(detail)
	if len(detail) <= 240 {
		return detail
	}
	return detail[:240] + "...[truncated]"
}

func runDiagnosePacketRows(parent context.Context, artifact ArtifactInfo, cfg config.Config) ([]diagnosePacket, bool, error) {
	args := []string{
		"-n",
		"-r", artifact.Path,
		"-c", strconv.Itoa(cfg.Analysis.MaxPacketRows),
		"-T", "fields",
		"-E", "header=y",
		"-E", "separator=/t",
		"-E", "quote=d",
		"-E", "occurrence=f",
		"-e", "frame.number",
		"-e", "frame.time_relative",
		"-e", "frame.len",
		"-e", "frame.cap_len",
		"-e", "frame.interface_id",
		"-e", "frame.interface_name",
		"-e", "ip.src",
		"-e", "ipv6.src",
		"-e", "tcp.srcport",
		"-e", "udp.srcport",
		"-e", "ip.dst",
		"-e", "ipv6.dst",
		"-e", "tcp.dstport",
		"-e", "udp.dstport",
		"-e", "_ws.col.Protocol",
		"-e", "tcp.flags.syn",
		"-e", "tcp.flags.ack",
		"-e", "tcp.flags.reset",
		"-e", "tcp.flags.fin",
		"-e", "tcp.len",
		"-e", "tls.handshake.type",
		"-e", "tls.record.version",
		"-e", "http.request.method",
		"-e", "http.response.code",
		"-e", "data.len",
	}
	out, truncated, err := runAnalyzerCommandTolerant(parent, diagnoseParseTimeout(cfg), cfg.Analysis.MaxStdoutBytes, "tshark", args, "")
	if err != nil {
		return nil, false, err
	}
	packets, parseErr := parseDiagnosePacketRows(out.Stdout)
	if parseErr != nil {
		return nil, false, parseErr
	}
	return packets, truncated, nil
}

func diagnoseParseTimeout(cfg config.Config) time.Duration {
	timeout := cfg.Timeout()
	if timeout <= 0 {
		return 60 * time.Second
	}
	if timeout > 180*time.Second {
		return 180 * time.Second
	}
	return timeout
}

func parseDiagnosePacketRows(raw string) ([]diagnosePacket, error) {
	reader := csv.NewReader(strings.NewReader(raw))
	reader.Comma = '\t'
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("%w: parse diagnose packet fields: %v", errAnalyzerFailed, err)
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
		protocol := strings.ToLower(firstNonEmpty(field(14), protocolFromPorts(field(8), field(9), field(12), field(13))))
		packets = append(packets, diagnosePacket{
			Number:            atoiDefault(field(0), 0),
			TimeMS:            secondsToMS(field(1)),
			FrameLen:          atoiDefault(field(2), 0),
			CapturedLen:       atoiDefault(field(3), 0),
			InterfaceID:       field(4),
			InterfaceName:     field(5),
			SrcIP:             firstNonEmpty(field(6), field(7)),
			SrcPort:           atoiDefault(firstNonEmpty(field(8), field(9)), 0),
			DstIP:             firstNonEmpty(field(10), field(11)),
			DstPort:           atoiDefault(firstNonEmpty(field(12), field(13)), 0),
			Protocol:          normalizeDiagnoseProtocol(protocol),
			SYN:               parseTSharkBool(field(15)),
			ACK:               parseTSharkBool(field(16)),
			RST:               parseTSharkBool(field(17)),
			FIN:               parseTSharkBool(field(18)),
			TCPLen:            atoiDefault(field(19), 0),
			TLSHandshakeTypes: parseHandshakeTypes(field(20)),
			TLSRecordVersion:  normalizeTLSVersion(field(21)),
			HTTPPlaintext:     field(22) != "" || field(23) != "",
			DataLen:           atoiDefault(field(24), 0),
		})
	}
	return packets, nil
}

func normalizeDiagnoseProtocol(protocol string) string {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	switch {
	case strings.Contains(protocol, "tcp") || strings.Contains(protocol, "tls") || strings.Contains(protocol, "http"):
		return "tcp"
	case strings.Contains(protocol, "udp") || protocol == "dns":
		return "udp"
	case strings.Contains(protocol, "icmp"):
		return "icmp"
	default:
		return protocol
	}
}

func protocolFromPorts(tcpSrc, udpSrc, tcpDst, udpDst string) string {
	switch {
	case tcpSrc != "" || tcpDst != "":
		return "tcp"
	case udpSrc != "" || udpDst != "":
		return "udp"
	default:
		return ""
	}
}

func parseTSharkBool(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	return value == "1" || value == "true"
}

func parseHandshakeTypes(value string) []int {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == ' '
	})
	var out []int
	for _, part := range parts {
		if n, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func normalizeTLSVersion(value string) string {
	value = strings.TrimSpace(value)
	switch strings.ToLower(value) {
	case "0x0301", "tls 1.0", "tls1.0":
		return "TLS1.0"
	case "0x0302", "tls 1.1", "tls1.1":
		return "TLS1.1"
	case "0x0303", "tls 1.2", "tls1.2":
		return "TLS1.2"
	case "0x0304", "tls 1.3", "tls1.3":
		return "TLS1.3"
	default:
		return value
	}
}

func atoiDefault(value string, fallback int) int {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return fallback
	}
	return n
}

func secondsToMS(value string) int64 {
	f, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil {
		return 0
	}
	return int64(math.Round(f * 1000))
}

func packetsContainTruncation(packets []diagnosePacket) bool {
	for _, p := range packets {
		if p.truncated() {
			return true
		}
	}
	return false
}

func diagnoseSymptomsFromPackets(packets []diagnosePacket, opts diagnoseRunOptions) ([]diagnoseSymptom, []diagnoseFinding) {
	if opts.enabled == nil {
		opts.enabled = allDiagnoseSymptomSet()
	}

	groups := flowGroups(packets)
	var symptoms []diagnoseSymptom
	for _, group := range groups {
		if !flowMatchesDiagnoseScope(group.flow, opts.scope) {
			continue
		}
		if opts.enabled[SymptomTLSHandshakeAttemptedOnPlainPort] {
			if symptom, ok := diagnoseTLSHandshakeAttemptedOnPlainPort(group); ok {
				symptoms = append(symptoms, symptom)
			}
		}
		if opts.enabled[SymptomTCPRSTAfterSYNACKNoAppData] {
			if symptom, ok := diagnoseTCPRSTAfterSYNACKNoAppData(group); ok {
				symptoms = append(symptoms, symptom)
			}
		}
	}

	var findings []diagnoseFinding
	if opts.enabled[SymptomMonitorProbeReturnsRST] {
		if captureDurationMS(packets) < diagnoseMinCadenceWindowMS {
			findings = append(findings, diagnoseFinding{
				Code:     FindingDiagnoseWindowTooShort,
				Severity: "info",
				Detail:   "duration_ms below cadence window for monitor_probe_returns_rst",
			})
		} else {
			symptoms = append(symptoms, diagnoseMonitorProbeReturnsRST(groups, opts.scope)...)
		}
	}

	if opts.enabled[SymptomAsymmetricReturnPathObserved] {
		if !captureHasInterfaceMetadata(packets) {
			findings = append(findings, diagnoseFinding{
				Code:     FindingDiagnoseLacksInterfaceMetadata,
				Severity: "info",
				Detail:   "interface metadata absent or single unnamed interface only",
			})
		} else {
			symptoms = append(symptoms, diagnoseAsymmetricReturnPathObserved(groups, opts.scope)...)
		}
	}

	truncatedPacketNumbers := map[int]bool{}
	for _, p := range packets {
		if p.truncated() {
			truncatedPacketNumbers[p.Number] = true
		}
	}
	if len(truncatedPacketNumbers) > 0 {
		for i := range symptoms {
			for _, n := range symptoms[i].Evidence.PacketNumbers {
				if truncatedPacketNumbers[n] {
					symptoms[i].Confidence = "low"
					break
				}
			}
		}
	}

	sortDiagnoseSymptoms(symptoms)
	return symptoms, findings
}

func flowGroups(packets []diagnosePacket) []diagnoseFlowGroup {
	grouped := map[string][]diagnosePacket{}
	for _, p := range packets {
		if p.Protocol != "tcp" || p.SrcIP == "" || p.DstIP == "" || p.SrcPort == 0 || p.DstPort == 0 {
			continue
		}
		key := canonicalFlowKey(p)
		grouped[key] = append(grouped[key], p)
	}

	keys := make([]string, 0, len(grouped))
	for key := range grouped {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	groups := make([]diagnoseFlowGroup, 0, len(keys))
	for _, key := range keys {
		packets := grouped[key]
		sort.SliceStable(packets, func(i, j int) bool {
			if packets[i].TimeMS == packets[j].TimeMS {
				return packets[i].Number < packets[j].Number
			}
			return packets[i].TimeMS < packets[j].TimeMS
		})
		groups = append(groups, diagnoseFlowGroup{
			flow:    inferFlowOrientation(packets),
			packets: packets,
		})
	}
	return groups
}

func canonicalFlowKey(p diagnosePacket) string {
	a := diagnoseEndpoint{ip: p.SrcIP, port: p.SrcPort}
	b := diagnoseEndpoint{ip: p.DstIP, port: p.DstPort}
	if endpointLess(b, a) {
		a, b = b, a
	}
	return fmt.Sprintf("%s:%d-%s:%d/%s", a.ip, a.port, b.ip, b.port, p.Protocol)
}

func endpointLess(a, b diagnoseEndpoint) bool {
	if a.ip == b.ip {
		return a.port < b.port
	}
	return a.ip < b.ip
}

func inferFlowOrientation(packets []diagnosePacket) diagnoseFlow {
	for _, p := range packets {
		if p.SYN && !p.ACK {
			return diagnoseFlow{
				SourceIP:        p.SrcIP,
				DestinationIP:   p.DstIP,
				SourcePort:      p.SrcPort,
				DestinationPort: p.DstPort,
				Protocol:        "tcp",
			}
		}
	}
	if len(packets) == 0 {
		return diagnoseFlow{Protocol: "tcp"}
	}
	p := packets[0]
	return diagnoseFlow{
		SourceIP:        p.SrcIP,
		DestinationIP:   p.DstIP,
		SourcePort:      p.SrcPort,
		DestinationPort: p.DstPort,
		Protocol:        "tcp",
	}
}

func flowMatchesDiagnoseScope(flow diagnoseFlow, scope *diagnoseScope) bool {
	if scope == nil {
		return true
	}
	if protocol := strings.ToLower(strings.TrimSpace(scope.Protocol)); protocol != "" && flow.Protocol != protocol {
		return false
	}
	if scope.SourceIP != "" && flow.SourceIP != strings.TrimSpace(scope.SourceIP) {
		return false
	}
	if scope.DestinationIP != "" && flow.DestinationIP != strings.TrimSpace(scope.DestinationIP) {
		return false
	}
	if scope.SourcePort != nil && flow.SourcePort != *scope.SourcePort {
		return false
	}
	if scope.DestinationPort != nil && flow.DestinationPort != *scope.DestinationPort {
		return false
	}
	return true
}

func packetDirection(flow diagnoseFlow, p diagnosePacket) int {
	if p.SrcIP == flow.SourceIP && p.SrcPort == flow.SourcePort && p.DstIP == flow.DestinationIP && p.DstPort == flow.DestinationPort {
		return 1
	}
	if p.SrcIP == flow.DestinationIP && p.SrcPort == flow.DestinationPort && p.DstIP == flow.SourceIP && p.DstPort == flow.SourcePort {
		return -1
	}
	return 0
}

func diagnoseTLSHandshakeAttemptedOnPlainPort(group diagnoseFlowGroup) (diagnoseSymptom, bool) {
	var clientHello *diagnosePacket
	serverHelloObserved := false
	serverResponseKind := "none"
	var response *diagnosePacket
	for i := range group.packets {
		p := group.packets[i]
		dir := packetDirection(group.flow, p)
		if dir == 1 && containsHandshakeType(p.TLSHandshakeTypes, 1) && clientHello == nil {
			clientHello = &group.packets[i]
		}
		if dir == -1 && containsHandshakeType(p.TLSHandshakeTypes, 2) {
			serverHelloObserved = true
		}
	}
	if clientHello == nil || serverHelloObserved {
		return diagnoseSymptom{}, false
	}
	for i := range group.packets {
		p := group.packets[i]
		if p.TimeMS < clientHello.TimeMS || packetDirection(group.flow, p) != -1 {
			continue
		}
		switch {
		case p.RST:
			serverResponseKind = "rst"
			response = &group.packets[i]
		case p.HTTPPlaintext:
			serverResponseKind = "http_plaintext"
			response = &group.packets[i]
		case p.TCPLen > 0 || p.DataLen > 0:
			serverResponseKind = "other_plaintext"
			response = &group.packets[i]
		}
		if response != nil {
			break
		}
	}

	version := clientHello.TLSRecordVersion
	if version == "" {
		version = "unknown"
	}
	packets := packetsBetween(group.packets, clientHello, response)
	trueValue := true
	return diagnoseSymptom{
		Code:       SymptomTLSHandshakeAttemptedOnPlainPort,
		Severity:   "warning",
		Confidence: "high",
		Evidence: diagnoseEvidence{
			Flow:                &group.flow,
			PacketCount:         len(packets),
			PacketNumbers:       packetNumbers(packets),
			FirstSeenOffsetMS:   firstPacketMS(packets),
			LastSeenOffsetMS:    lastPacketMS(packets),
			ClientHelloObserved: &trueValue,
			ServerResponseKind:  serverResponseKind,
			TLSVersionOffered:   version,
		},
		Narrative: "TLS Client Hello was observed on a flow that did not return a TLS Server Hello; the observed server response was " + serverResponseKind + ".",
	}, true
}

func diagnoseTCPRSTAfterSYNACKNoAppData(group diagnoseFlowGroup) (diagnoseSymptom, bool) {
	var syn, synack, ack, rst *diagnosePacket
	for i := range group.packets {
		p := group.packets[i]
		dir := packetDirection(group.flow, p)
		switch {
		case syn == nil && dir == 1 && p.SYN && !p.ACK:
			syn = &group.packets[i]
		case syn != nil && synack == nil && dir == -1 && p.SYN && p.ACK:
			synack = &group.packets[i]
		case synack != nil && ack == nil && dir == 1 && !p.SYN && p.ACK:
			ack = &group.packets[i]
		case ack != nil && rst == nil && dir == -1 && p.RST:
			rst = &group.packets[i]
		}
	}
	if syn == nil || synack == nil || ack == nil || rst == nil {
		return diagnoseSymptom{}, false
	}

	var clientBytes, serverBytes int
	for _, p := range group.packets {
		if p.TimeMS <= ack.TimeMS || p.TimeMS > rst.TimeMS {
			continue
		}
		switch packetDirection(group.flow, p) {
		case 1:
			clientBytes += p.TCPLen
		case -1:
			if !p.RST {
				serverBytes += p.TCPLen
			}
		}
	}
	if clientBytes != 0 || serverBytes != 0 {
		return diagnoseSymptom{}, false
	}

	packets := packetsBetween(group.packets, syn, rst)
	trueValue := true
	return diagnoseSymptom{
		Code:       SymptomTCPRSTAfterSYNACKNoAppData,
		Severity:   "warning",
		Confidence: "high",
		Evidence: diagnoseEvidence{
			Flow:                   &group.flow,
			PacketCount:            len(packets),
			PacketNumbers:          packetNumbers(packets),
			FirstSeenOffsetMS:      firstPacketMS(packets),
			LastSeenOffsetMS:       lastPacketMS(packets),
			HandshakeCompleted:     &trueValue,
			AppBytesClientToServer: clientBytes,
			AppBytesServerToClient: serverBytes,
			TimeToRSTMS:            rst.TimeMS - ack.TimeMS,
		},
		Narrative: "TCP handshake completed and the responder sent RST before application bytes were observed in either direction.",
	}, true
}

type diagnoseProbeGroup struct {
	flow       diagnoseFlow
	startMS    []int64
	packetNums []int
	total      int
	rst        int
	maxPayload int
}

func diagnoseMonitorProbeReturnsRST(groups []diagnoseFlowGroup, scope *diagnoseScope) []diagnoseSymptom {
	probes := map[string]*diagnoseProbeGroup{}
	for _, group := range groups {
		if !flowMatchesDiagnoseScope(group.flow, scope) {
			continue
		}
		start := firstSYN(group)
		if start == nil {
			continue
		}
		keyFlow := diagnoseFlow{
			SourceIP:        group.flow.SourceIP,
			DestinationIP:   group.flow.DestinationIP,
			DestinationPort: group.flow.DestinationPort,
			Protocol:        group.flow.Protocol,
		}
		key := fmt.Sprintf("%s-%s:%d/%s", keyFlow.SourceIP, keyFlow.DestinationIP, keyFlow.DestinationPort, keyFlow.Protocol)
		entry := probes[key]
		if entry == nil {
			entry = &diagnoseProbeGroup{flow: keyFlow}
			probes[key] = entry
		}
		entry.total++
		entry.startMS = append(entry.startMS, start.TimeMS)
		entry.packetNums = append(entry.packetNums, start.Number)
		if flowHasServerRST(group) {
			entry.rst++
			if nums := serverRSTPacketNumbers(group); len(nums) > 0 {
				entry.packetNums = append(entry.packetNums, nums...)
			}
		}
		payload := maxClientPayload(group)
		if payload > entry.maxPayload {
			entry.maxPayload = payload
		}
	}

	var symptoms []diagnoseSymptom
	for _, entry := range probes {
		if entry.total < diagnoseMinProbeCount || entry.maxPayload > diagnoseMaxProbePayload {
			continue
		}
		ratio := float64(entry.rst) / float64(entry.total)
		if ratio < 0.9 {
			continue
		}
		cadenceMS := medianInterval(entry.startMS)
		if cadenceMS > diagnoseMaxProbeCadenceMS {
			continue
		}
		sort.Ints(entry.packetNums)
		entry.packetNums = uniqueInts(entry.packetNums)
		symptoms = append(symptoms, diagnoseSymptom{
			Code:       SymptomMonitorProbeReturnsRST,
			Severity:   "info",
			Confidence: "medium",
			Evidence: diagnoseEvidence{
				Flow:                   &entry.flow,
				PacketCount:            len(entry.packetNums),
				PacketNumbers:          entry.packetNums,
				FirstSeenOffsetMS:      minInt64(entry.startMS),
				LastSeenOffsetMS:       maxInt64(entry.startMS),
				ProbeCount:             entry.total,
				ProbeCadenceSecondsP50: float64(cadenceMS) / 1000,
				RSTRatio:               ratio,
			},
			Narrative: "Short periodic probe-shaped flows from the same source to the same destination consistently received TCP RST responses.",
		})
	}
	return symptoms
}

func diagnoseAsymmetricReturnPathObserved(groups []diagnoseFlowGroup, scope *diagnoseScope) []diagnoseSymptom {
	var symptoms []diagnoseSymptom
	for _, group := range groups {
		if !flowMatchesDiagnoseScope(group.flow, scope) {
			continue
		}
		syn := firstSYN(group)
		if syn == nil || syn.interfaceLabel() == "" {
			continue
		}
		var synacks []diagnosePacket
		for _, p := range group.packets {
			if packetDirection(group.flow, p) == -1 && p.SYN && p.ACK {
				synacks = append(synacks, p)
			}
		}
		if len(synacks) == 0 {
			trueValue := true
			falseValue := false
			packets := []diagnosePacket{*syn}
			symptoms = append(symptoms, diagnoseSymptom{
				Code:       SymptomAsymmetricReturnPathObserved,
				Severity:   "warning",
				Confidence: "medium",
				Evidence: diagnoseEvidence{
					Flow:                          &group.flow,
					PacketCount:                   len(packets),
					PacketNumbers:                 packetNumbers(packets),
					FirstSeenOffsetMS:             syn.TimeMS,
					LastSeenOffsetMS:              syn.TimeMS,
					SYNSeen:                       &trueValue,
					SYNACKSeen:                    &falseValue,
					InterfacesObserved:            flowInterfaces(group.packets),
					FlowCompleteViaOtherInterface: &falseValue,
				},
				Narrative: "TCP SYN was observed with interface metadata, but the matching SYN ACK was not observed in this capture.",
			})
			continue
		}

		var otherInterface *diagnosePacket
		for i := range synacks {
			if synacks[i].interfaceLabel() != "" && synacks[i].interfaceLabel() != syn.interfaceLabel() {
				otherInterface = &synacks[i]
				break
			}
		}
		if otherInterface == nil {
			continue
		}
		trueValue := true
		packets := packetsBetween(group.packets, syn, otherInterface)
		symptoms = append(symptoms, diagnoseSymptom{
			Code:       SymptomAsymmetricReturnPathObserved,
			Severity:   "warning",
			Confidence: "medium",
			Evidence: diagnoseEvidence{
				Flow:                          &group.flow,
				PacketCount:                   len(packets),
				PacketNumbers:                 packetNumbers(packets),
				FirstSeenOffsetMS:             firstPacketMS(packets),
				LastSeenOffsetMS:              lastPacketMS(packets),
				SYNSeen:                       &trueValue,
				SYNACKSeen:                    &trueValue,
				InterfacesObserved:            flowInterfaces(group.packets),
				FlowCompleteViaOtherInterface: &trueValue,
			},
			Narrative: "TCP SYN and matching SYN ACK were observed on different capture interfaces for the same flow.",
		})
	}
	return symptoms
}

func containsHandshakeType(types []int, want int) bool {
	for _, got := range types {
		if got == want {
			return true
		}
	}
	return false
}

func packetsBetween(packets []diagnosePacket, start, end *diagnosePacket) []diagnosePacket {
	if start == nil {
		return nil
	}
	endMS := start.TimeMS
	if end != nil {
		endMS = end.TimeMS
	}
	var out []diagnosePacket
	for _, p := range packets {
		if p.TimeMS >= start.TimeMS && p.TimeMS <= endMS {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		out = append(out, *start)
	}
	return out
}

func packetNumbers(packets []diagnosePacket) []int {
	out := make([]int, 0, len(packets))
	for _, p := range packets {
		if p.Number > 0 {
			out = append(out, p.Number)
		}
	}
	return uniqueInts(out)
}

func uniqueInts(values []int) []int {
	if len(values) == 0 {
		return nil
	}
	sort.Ints(values)
	out := values[:0]
	var last int
	for i, v := range values {
		if i == 0 || v != last {
			out = append(out, v)
		}
		last = v
	}
	return out
}

func firstPacketMS(packets []diagnosePacket) int64 {
	if len(packets) == 0 {
		return 0
	}
	min := packets[0].TimeMS
	for _, p := range packets[1:] {
		if p.TimeMS < min {
			min = p.TimeMS
		}
	}
	return min
}

func lastPacketMS(packets []diagnosePacket) int64 {
	if len(packets) == 0 {
		return 0
	}
	max := packets[0].TimeMS
	for _, p := range packets[1:] {
		if p.TimeMS > max {
			max = p.TimeMS
		}
	}
	return max
}

func firstSYN(group diagnoseFlowGroup) *diagnosePacket {
	for i := range group.packets {
		p := group.packets[i]
		if packetDirection(group.flow, p) == 1 && p.SYN && !p.ACK {
			return &group.packets[i]
		}
	}
	return nil
}

func flowHasServerRST(group diagnoseFlowGroup) bool {
	for _, p := range group.packets {
		if packetDirection(group.flow, p) == -1 && p.RST {
			return true
		}
	}
	return false
}

func serverRSTPacketNumbers(group diagnoseFlowGroup) []int {
	var out []int
	for _, p := range group.packets {
		if packetDirection(group.flow, p) == -1 && p.RST && p.Number > 0 {
			out = append(out, p.Number)
		}
	}
	return out
}

func maxClientPayload(group diagnoseFlowGroup) int {
	maxPayload := 0
	for _, p := range group.packets {
		if packetDirection(group.flow, p) == 1 && p.TCPLen > maxPayload {
			maxPayload = p.TCPLen
		}
	}
	return maxPayload
}

func captureDurationMS(packets []diagnosePacket) int64 {
	if len(packets) < 2 {
		return 0
	}
	return lastPacketMS(packets) - firstPacketMS(packets)
}

func medianInterval(times []int64) int64 {
	if len(times) < 2 {
		return 0
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	intervals := make([]int64, 0, len(times)-1)
	for i := 1; i < len(times); i++ {
		intervals = append(intervals, times[i]-times[i-1])
	}
	sort.Slice(intervals, func(i, j int) bool { return intervals[i] < intervals[j] })
	mid := len(intervals) / 2
	if len(intervals)%2 == 1 {
		return intervals[mid]
	}
	return (intervals[mid-1] + intervals[mid]) / 2
}

func minInt64(values []int64) int64 {
	if len(values) == 0 {
		return 0
	}
	min := values[0]
	for _, v := range values[1:] {
		if v < min {
			min = v
		}
	}
	return min
}

func maxInt64(values []int64) int64 {
	if len(values) == 0 {
		return 0
	}
	max := values[0]
	for _, v := range values[1:] {
		if v > max {
			max = v
		}
	}
	return max
}

func captureHasInterfaceMetadata(packets []diagnosePacket) bool {
	names := map[string]bool{}
	ids := map[string]bool{}
	for _, p := range packets {
		if p.InterfaceName != "" {
			names[p.InterfaceName] = true
		}
		if p.InterfaceID != "" {
			ids[p.InterfaceID] = true
		}
	}
	return len(names) > 0 || len(ids) > 1
}

func flowInterfaces(packets []diagnosePacket) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range packets {
		label := p.interfaceLabel()
		if label == "" || seen[label] {
			continue
		}
		seen[label] = true
		out = append(out, label)
	}
	sort.Strings(out)
	return out
}

func sortDiagnoseSymptoms(symptoms []diagnoseSymptom) {
	order := map[string]int{}
	for i, code := range diagnoseSymptomCodes() {
		order[code] = i
	}
	sort.SliceStable(symptoms, func(i, j int) bool {
		oi, okI := order[symptoms[i].Code]
		oj, okJ := order[symptoms[j].Code]
		if okI && okJ && oi != oj {
			return oi < oj
		}
		if symptoms[i].Evidence.FirstSeenOffsetMS == symptoms[j].Evidence.FirstSeenOffsetMS {
			return symptoms[i].Code < symptoms[j].Code
		}
		return symptoms[i].Evidence.FirstSeenOffsetMS < symptoms[j].Evidence.FirstSeenOffsetMS
	})
}

func enabledDiagnoseSymptoms(filter []string) map[string]bool {
	if len(filter) == 0 {
		return allDiagnoseSymptomSet()
	}
	out := map[string]bool{}
	for _, token := range filter {
		out[token] = true
	}
	return out
}

func allDiagnoseSymptomSet() map[string]bool {
	out := map[string]bool{}
	for _, token := range diagnoseSymptomCodes() {
		out[token] = true
	}
	return out
}

func isDiagnoseSymptomCode(token string) bool {
	for _, code := range diagnoseSymptomCodes() {
		if token == code {
			return true
		}
	}
	return false
}

func diagnoseSymptomCodes() []string {
	return []string{
		SymptomTLSHandshakeAttemptedOnPlainPort,
		SymptomTCPRSTAfterSYNACKNoAppData,
		SymptomMonitorProbeReturnsRST,
		SymptomAsymmetricReturnPathObserved,
	}
}

func diagnoseFindingCodes() []string {
	return []string{
		FindingDiagnoseFlowUnparseable,
		FindingDiagnoseCaptureTruncated,
		FindingDiagnoseWindowTooShort,
		FindingDiagnoseParseTimeout,
		FindingDiagnoseLacksInterfaceMetadata,
		FindingDiagnoseUnrecognizedPattern,
		FindingDiagnoseInputInvalid,
		FindingDiagnosePathInvalid,
		FindingDiagnoseArtifactMismatch,
	}
}
