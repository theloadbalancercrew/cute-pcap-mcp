package pcap

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const summaryRecordLimit = 25

type AnalysisSummary struct {
	ZeekLogRecords []ZeekLogRecordCount  `json:"zeek_log_records,omitempty"`
	Connections    []ConnectionSummary   `json:"connections,omitempty"`
	DNSQueries     []DNSQuerySummary     `json:"dns_queries,omitempty"`
	HTTPRequests   []HTTPRequestSummary  `json:"http_requests,omitempty"`
	TLSHandshakes  []TLSHandshakeSummary `json:"tls_handshakes,omitempty"`
	Notices        []ZeekEventSummary    `json:"notices,omitempty"`
	WeirdEvents    []ZeekEventSummary    `json:"weird_events,omitempty"`
	Signals        map[string]int        `json:"signals,omitempty"`
	Metadata       map[string]string     `json:"metadata,omitempty"`
}

type ZeekLogRecordCount struct {
	Name      string `json:"name"`
	Records   int    `json:"records"`
	Truncated bool   `json:"truncated,omitempty"`
}

type ConnectionSummary struct {
	UID         string `json:"uid,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	Service     string `json:"service,omitempty"`
	Source      string `json:"source,omitempty"`
	SourcePort  string `json:"source_port,omitempty"`
	Destination string `json:"destination,omitempty"`
	DestPort    string `json:"dest_port,omitempty"`
	Duration    string `json:"duration,omitempty"`
	ConnState   string `json:"conn_state,omitempty"`
	History     string `json:"history,omitempty"`
	OrigBytes   int64  `json:"orig_bytes,omitempty"`
	RespBytes   int64  `json:"resp_bytes,omitempty"`
	TotalBytes  int64  `json:"total_bytes,omitempty"`
}

type DNSQuerySummary struct {
	UID      string   `json:"uid,omitempty"`
	Source   string   `json:"source,omitempty"`
	Query    string   `json:"query,omitempty"`
	Type     string   `json:"type,omitempty"`
	Response string   `json:"response,omitempty"`
	Answers  []string `json:"answers,omitempty"`
	Rejected bool     `json:"rejected,omitempty"`
}

type HTTPRequestSummary struct {
	UID         string `json:"uid,omitempty"`
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination,omitempty"`
	Method      string `json:"method,omitempty"`
	Host        string `json:"host,omitempty"`
	URI         string `json:"uri,omitempty"`
	UserAgent   string `json:"user_agent,omitempty"`
	StatusCode  int    `json:"status_code,omitempty"`
	StatusMsg   string `json:"status_msg,omitempty"`
	MimeType    string `json:"mime_type,omitempty"`
	Redacted    bool   `json:"redacted,omitempty"`
}

type TLSHandshakeSummary struct {
	UID              string `json:"uid,omitempty"`
	Source           string `json:"source,omitempty"`
	Destination      string `json:"destination,omitempty"`
	ServerName       string `json:"server_name,omitempty"`
	Version          string `json:"version,omitempty"`
	Cipher           string `json:"cipher,omitempty"`
	JA3              string `json:"ja3,omitempty"`
	JA3S             string `json:"ja3s,omitempty"`
	ValidationStatus string `json:"validation_status,omitempty"`
}

type ZeekEventSummary struct {
	UID         string `json:"uid,omitempty"`
	Name        string `json:"name,omitempty"`
	Note        string `json:"note,omitempty"`
	Message     string `json:"message,omitempty"`
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination,omitempty"`
}

func buildAnalysisSummary(zeek ZeekReport) *AnalysisSummary {
	if len(zeek.Logs) == 0 {
		return nil
	}
	summary := &AnalysisSummary{
		Signals: map[string]int{},
		Metadata: map[string]string{
			"record_scope": "Derived from bounded Zeek log records returned by this tool call.",
		},
	}
	for _, log := range zeek.Logs {
		summary.ZeekLogRecords = append(summary.ZeekLogRecords, ZeekLogRecordCount{
			Name:      log.Name,
			Records:   len(log.Records),
			Truncated: log.Truncated,
		})
	}
	sort.Slice(summary.ZeekLogRecords, func(i, j int) bool {
		return summary.ZeekLogRecords[i].Name < summary.ZeekLogRecords[j].Name
	})

	summary.Connections = summarizeConnections(zeekLogIn(zeek, "conn"))
	summary.DNSQueries = summarizeDNS(zeekLogIn(zeek, "dns"))
	summary.HTTPRequests = summarizeHTTP(zeekLogIn(zeek, "http"))
	summary.TLSHandshakes = summarizeTLS(firstZeekLogIn(zeek, "ssl", "tls"))
	summary.Notices = summarizeEvents(zeekLogIn(zeek, "notice"), "note", "msg")
	summary.WeirdEvents = summarizeEvents(zeekLogIn(zeek, "weird"), "name", "notice")

	summary.Signals["connections"] = len(summary.Connections)
	summary.Signals["dns_queries"] = len(summary.DNSQueries)
	summary.Signals["http_requests"] = len(summary.HTTPRequests)
	summary.Signals["tls_handshakes"] = len(summary.TLSHandshakes)
	summary.Signals["notices"] = len(summary.Notices)
	summary.Signals["weird_events"] = len(summary.WeirdEvents)
	for _, conn := range summary.Connections {
		if connectionLooksReset(conn) {
			summary.Signals["tcp_resets"]++
		}
	}
	for _, req := range summary.HTTPRequests {
		if req.StatusCode >= 400 {
			summary.Signals["http_error_statuses"]++
		}
	}
	for _, query := range summary.DNSQueries {
		if query.Rejected {
			summary.Signals["dns_rejections"]++
		}
	}
	if len(summary.Signals) == 0 && len(summary.ZeekLogRecords) == 0 {
		return nil
	}
	return summary
}

func summarizeConnections(log *ZeekLog) []ConnectionSummary {
	if log == nil {
		return nil
	}
	connections := make([]ConnectionSummary, 0, len(log.Records))
	for _, record := range log.Records {
		origBytes := parseZeekInt(recordValue(record, "orig_bytes", "orig_ip_bytes"))
		respBytes := parseZeekInt(recordValue(record, "resp_bytes", "resp_ip_bytes"))
		connections = append(connections, ConnectionSummary{
			UID:         recordValue(record, "uid"),
			Protocol:    recordValue(record, "proto"),
			Service:     recordValue(record, "service"),
			Source:      recordValue(record, "id.orig_h"),
			SourcePort:  recordValue(record, "id.orig_p"),
			Destination: recordValue(record, "id.resp_h"),
			DestPort:    recordValue(record, "id.resp_p"),
			Duration:    recordValue(record, "duration"),
			ConnState:   recordValue(record, "conn_state"),
			History:     recordValue(record, "history"),
			OrigBytes:   origBytes,
			RespBytes:   respBytes,
			TotalBytes:  origBytes + respBytes,
		})
	}
	sort.SliceStable(connections, func(i, j int) bool {
		return connections[i].TotalBytes > connections[j].TotalBytes
	})
	return capConnections(connections)
}

func summarizeDNS(log *ZeekLog) []DNSQuerySummary {
	if log == nil {
		return nil
	}
	queries := make([]DNSQuerySummary, 0, len(log.Records))
	for _, record := range log.Records {
		response := recordValue(record, "rcode_name", "rcode")
		query := DNSQuerySummary{
			UID:      recordValue(record, "uid"),
			Source:   recordValue(record, "id.orig_h"),
			Query:    recordValue(record, "query"),
			Type:     recordValue(record, "qtype_name", "qtype"),
			Response: response,
			Answers:  zeekSet(recordValue(record, "answers")),
			Rejected: dnsRejected(response),
		}
		queries = append(queries, query)
	}
	return capDNS(queries)
}

func summarizeHTTP(log *ZeekLog) []HTTPRequestSummary {
	if log == nil {
		return nil
	}
	requests := make([]HTTPRequestSummary, 0, len(log.Records))
	for _, record := range log.Records {
		uri, redacted := redactASCIISecrets(recordValue(record, "uri"))
		request := HTTPRequestSummary{
			UID:         recordValue(record, "uid"),
			Source:      recordValue(record, "id.orig_h"),
			Destination: recordValue(record, "id.resp_h"),
			Method:      recordValue(record, "method"),
			Host:        recordValue(record, "host"),
			URI:         uri,
			UserAgent:   recordValue(record, "user_agent"),
			StatusCode:  int(parseZeekInt(recordValue(record, "status_code"))),
			StatusMsg:   recordValue(record, "status_msg"),
			MimeType:    recordValue(record, "resp_mime_types"),
			Redacted:    redacted,
		}
		requests = append(requests, request)
	}
	sort.SliceStable(requests, func(i, j int) bool {
		return requests[i].StatusCode > requests[j].StatusCode
	})
	return capHTTP(requests)
}

func summarizeTLS(log *ZeekLog) []TLSHandshakeSummary {
	if log == nil {
		return nil
	}
	handshakes := make([]TLSHandshakeSummary, 0, len(log.Records))
	for _, record := range log.Records {
		handshakes = append(handshakes, TLSHandshakeSummary{
			UID:              recordValue(record, "uid"),
			Source:           recordValue(record, "id.orig_h"),
			Destination:      recordValue(record, "id.resp_h"),
			ServerName:       recordValue(record, "server_name"),
			Version:          recordValue(record, "version"),
			Cipher:           recordValue(record, "cipher"),
			JA3:              recordValue(record, "ja3"),
			JA3S:             recordValue(record, "ja3s"),
			ValidationStatus: recordValue(record, "validation_status"),
		})
	}
	return capTLS(handshakes)
}

func summarizeEvents(log *ZeekLog, nameField, messageField string) []ZeekEventSummary {
	if log == nil {
		return nil
	}
	events := make([]ZeekEventSummary, 0, len(log.Records))
	for _, record := range log.Records {
		events = append(events, ZeekEventSummary{
			UID:         recordValue(record, "uid", "conn_uids"),
			Name:        recordValue(record, nameField),
			Note:        recordValue(record, "note"),
			Message:     recordValue(record, messageField, "msg", "notice"),
			Source:      recordValue(record, "id.orig_h", "src"),
			Destination: recordValue(record, "id.resp_h", "dst"),
		})
	}
	return capEvents(events)
}

func summaryFindings(summary *AnalysisSummary) []PacketFinding {
	if summary == nil {
		return nil
	}
	var findings []PacketFinding
	if count := summary.Signals["notices"]; count > 0 {
		findings = append(findings, PacketFinding{
			Code:     FindingZeekNoticesPresent,
			Severity: "warning",
			Message:  fmt.Sprintf("Zeek emitted %d notice records in the bounded output.", count),
		})
	}
	if count := summary.Signals["weird_events"]; count > 0 {
		findings = append(findings, PacketFinding{
			Code:     FindingZeekWeirdEventsPresent,
			Severity: "warning",
			Message:  fmt.Sprintf("Zeek emitted %d weird-event records in the bounded output.", count),
		})
	}
	if count := summary.Signals["http_error_statuses"]; count > 0 {
		findings = append(findings, PacketFinding{
			Code:     FindingHTTPErrorStatuses,
			Severity: "warning",
			Message:  fmt.Sprintf("Observed %d HTTP responses with status code 400 or greater in the bounded output.", count),
		})
	}
	if count := summary.Signals["dns_rejections"]; count > 0 {
		findings = append(findings, PacketFinding{
			Code:     FindingDNSRejectionsPresent,
			Severity: "info",
			Message:  fmt.Sprintf("Observed %d DNS queries with non-success response codes in the bounded output.", count),
		})
	}
	if count := summary.Signals["tcp_resets"]; count > 0 {
		findings = append(findings, PacketFinding{
			Code:     FindingTCPResetsPresent,
			Severity: "warning",
			Message:  fmt.Sprintf("Observed %d connections with reset-like Zeek connection states or history markers.", count),
		})
	}
	return findings
}

func zeekLogIn(report ZeekReport, name string) *ZeekLog {
	for idx := range report.Logs {
		if report.Logs[idx].Name == name {
			return &report.Logs[idx]
		}
	}
	return nil
}

func firstZeekLogIn(report ZeekReport, names ...string) *ZeekLog {
	for _, name := range names {
		if log := zeekLogIn(report, name); log != nil {
			return log
		}
	}
	return nil
}

func recordValue(record map[string]string, keys ...string) string {
	for _, key := range keys {
		value := strings.TrimSpace(record[key])
		if value != "" && value != "-" {
			return value
		}
	}
	return ""
}

func parseZeekInt(value string) int64 {
	if value == "" || value == "-" {
		return 0
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err == nil {
		return n
	}
	f, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0
	}
	return int64(f)
}

func zeekSet(value string) []string {
	if value == "" || value == "-" {
		return nil
	}
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';'
	})
	var out []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" && part != "-" {
			out = append(out, part)
		}
	}
	return out
}

func dnsRejected(response string) bool {
	response = strings.ToUpper(strings.TrimSpace(response))
	return response != "" && response != "NOERROR" && response != "0"
}

func connectionLooksReset(conn ConnectionSummary) bool {
	state := strings.ToUpper(conn.ConnState)
	if strings.Contains(state, "RST") {
		return true
	}
	return strings.Contains(strings.ToUpper(conn.History), "R")
}

func capConnections(values []ConnectionSummary) []ConnectionSummary {
	if len(values) > summaryRecordLimit {
		return values[:summaryRecordLimit]
	}
	return values
}

func capDNS(values []DNSQuerySummary) []DNSQuerySummary {
	if len(values) > summaryRecordLimit {
		return values[:summaryRecordLimit]
	}
	return values
}

func capHTTP(values []HTTPRequestSummary) []HTTPRequestSummary {
	if len(values) > summaryRecordLimit {
		return values[:summaryRecordLimit]
	}
	return values
}

func capTLS(values []TLSHandshakeSummary) []TLSHandshakeSummary {
	if len(values) > summaryRecordLimit {
		return values[:summaryRecordLimit]
	}
	return values
}

func capEvents(values []ZeekEventSummary) []ZeekEventSummary {
	if len(values) > summaryRecordLimit {
		return values[:summaryRecordLimit]
	}
	return values
}
