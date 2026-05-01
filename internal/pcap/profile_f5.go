package pcap

import (
	"net/netip"
	"sort"
	"strings"
)

// F5Context is the optional caller-supplied context for the
// f5_ltm_tls_debug profile. Every field is opaque to the server: the
// profile echoes the provided values back and uses them only to
// classify packet evidence (e.g. "this connection's destination
// matches the configured VIP"). The server makes no API calls based
// on these values.
type F5Context struct {
	VirtualServerName string `json:"virtual_server_name,omitempty"`
	VirtualServerIP   string `json:"virtual_server_ip,omitempty"`
	VirtualServerPort int    `json:"virtual_server_port,omitempty"`
	SNATPoolName      string `json:"snat_pool_name,omitempty"`
	PoolName          string `json:"pool_name,omitempty"`
	Notes             string `json:"notes,omitempty"`
}

// F5LTMTLSDebugSection is the per-profile evidence under
// AnalysisProfileResult.f5_ltm_tls_debug. Every sub-section is
// derived from the generic pcap_analyze evidence (TCPHealth, TLS,
// HTTP) plus optional F5Context for clientside/serverside framing.
// The profile never invents load-balancer config facts.
type F5LTMTLSDebugSection struct {
	Context *F5Context       `json:"context,omitempty"`
	Resets  *F5ResetEvidence `json:"resets,omitempty"`
	TLS     *F5TLSEvidence   `json:"tls,omitempty"`
	HTTP    *F5HTTPEvidence  `json:"http,omitempty"`
	SNAT    []F5SNATHint     `json:"snat_hints,omitempty"`
}

type F5ResetEvidence struct {
	Total            int                 `json:"total"`
	OriginatorResets int                 `json:"originator_resets"`
	ResponderResets  int                 `json:"responder_resets"`
	Connections      []ConnectionSummary `json:"connections,omitempty"`
}

type F5TLSEvidence struct {
	HandshakeCount   int                   `json:"handshake_count"`
	DistinctSNINames []string              `json:"distinct_sni,omitempty"`
	Versions         map[string]int        `json:"versions,omitempty"`
	Ciphers          map[string]int        `json:"ciphers,omitempty"`
	Handshakes       []TLSHandshakeSummary `json:"handshakes,omitempty"`
}

type F5HTTPEvidence struct {
	RequestCount      int                  `json:"request_count"`
	StatusClassCounts map[string]int       `json:"status_class_counts,omitempty"`
	Requests          []HTTPRequestSummary `json:"requests,omitempty"`
}

// F5SNATHint is a single observation about clientside/serverside
// flow shape. Every hint carries an "evidence" string describing the
// packet observation that triggered it. Hints are NOT claims: a
// matching Description still requires operator interpretation in
// the context of the load-balancer config.
type F5SNATHint struct {
	Description string `json:"description"`
	Evidence    string `json:"evidence,omitempty"`
}

// buildF5LTMTLSDebugProfile assembles the profile section from the
// already-populated analyzeOutput plus the internal AnalysisSummary
// (which carries every Zeek connection, not just the reset-bearing
// ones surfaced on TCPHealth) and optional F5Context. It returns nil
// when the analyze pass produced no evidence the profile would
// meaningfully restate.
func buildF5LTMTLSDebugProfile(out analyzeOutput, summary *AnalysisSummary, ctx *F5Context) *AnalysisProfileResult {
	section := &F5LTMTLSDebugSection{Context: ctx}

	if out.TCPHealth != nil && out.TCPHealth.ResetCount > 0 {
		section.Resets = &F5ResetEvidence{
			Total:            out.TCPHealth.ResetCount,
			OriginatorResets: out.TCPHealth.ResetsByOriginator,
			ResponderResets:  out.TCPHealth.ResetsByResponder,
			Connections:      out.TCPHealth.ResetConnections,
		}
	}

	if len(out.TLS) > 0 {
		tls := &F5TLSEvidence{
			HandshakeCount: len(out.TLS),
			Handshakes:     out.TLS,
			Versions:       map[string]int{},
			Ciphers:        map[string]int{},
		}
		sniSet := map[string]struct{}{}
		for _, h := range out.TLS {
			if name := strings.TrimSpace(h.ServerName); name != "" {
				sniSet[name] = struct{}{}
			}
			if v := strings.TrimSpace(h.Version); v != "" {
				tls.Versions[v]++
			}
			if c := strings.TrimSpace(h.Cipher); c != "" {
				tls.Ciphers[c]++
			}
		}
		for sni := range sniSet {
			tls.DistinctSNINames = append(tls.DistinctSNINames, sni)
		}
		sort.Strings(tls.DistinctSNINames)
		section.TLS = tls
	}

	if len(out.HTTP) > 0 {
		http := &F5HTTPEvidence{
			RequestCount:      len(out.HTTP),
			Requests:          out.HTTP,
			StatusClassCounts: map[string]int{},
		}
		for _, r := range out.HTTP {
			http.StatusClassCounts[httpStatusClass(r.StatusCode)]++
		}
		section.HTTP = http
	}

	section.SNAT = buildSNATHints(summary, ctx)

	if section.Resets == nil && section.TLS == nil && section.HTTP == nil && len(section.SNAT) == 0 && ctx == nil {
		return nil
	}

	result := &AnalysisProfileResult{
		Name:          AnalysisProfileF5LTMTLSDebug,
		Limitations:   append([]string{}, f5LTMTLSDebugLimitations...),
		F5LTMTLSDebug: section,
	}
	result.Findings = buildF5ProfileFindings(section)
	return result
}

// buildSNATHints classifies every visible Zeek connection against
// the optional caller-supplied F5Context. Two truth-over-closure
// rules apply:
//
//  1. Without f5_context, the profile refuses to guess and emits a
//     single hint stating the lack of context. No connection is
//     classified.
//  2. With f5_context but **without** virtual_server_ip, the profile
//     also refuses to claim "clientside_to_vip" — a port number
//     alone is not a VIP (port 443 is everyone's HTTPS), and labeling
//     every dst-port match as "destined for the configured VIP"
//     would overclaim. The profile emits an insufficient-context
//     hint instead.
//
// With virtual_server_ip set, connections whose destination matches
// the VIP IP (and port, if also set) are flagged as
// clientside_to_vip_observed; everything else is non_vip_destinations.
//
// The summary parameter is the AnalysisSummary built from every
// returned Zeek conn record, not just the reset-bearing subset on
// TCPHealth. This keeps normal non-reset flows visible to the
// classifier.
func buildSNATHints(summary *AnalysisSummary, ctx *F5Context) []F5SNATHint {
	var hints []F5SNATHint

	if ctx == nil || (strings.TrimSpace(ctx.VirtualServerIP) == "" && strings.TrimSpace(ctx.VirtualServerName) == "" && ctx.VirtualServerPort == 0 && strings.TrimSpace(ctx.PoolName) == "" && strings.TrimSpace(ctx.SNATPoolName) == "") {
		hints = append(hints, F5SNATHint{
			Description: "clientside_classification_skipped_no_context",
			Evidence:    "no f5_context supplied; profile reports the unknown rather than guessing",
		})
		return hints
	}

	vipIP := strings.TrimSpace(ctx.VirtualServerIP)
	if vipIP == "" {
		// Context is present (probably names / notes / pool fields)
		// but the IP that drives the classifier isn't. A bare port
		// number cannot identify "the VIP" — port 443 is everyone's
		// HTTPS — so we explicitly refuse rather than over-claim.
		hints = append(hints, F5SNATHint{
			Description: "clientside_classification_skipped_no_vip_ip",
			Evidence:    "f5_context.virtual_server_ip is required for clientside_to_vip classification; a port alone is insufficient",
		})
		return hints
	}

	vipAddr, err := netip.ParseAddr(vipIP)
	if err != nil {
		// validateF5Context should have caught this already, but
		// guard so a future bypass of the validator does not produce
		// nonsense hints.
		hints = append(hints, F5SNATHint{
			Description: "clientside_classification_skipped_invalid_vip_ip",
			Evidence:    "f5_context.virtual_server_ip did not parse as an IP address",
		})
		return hints
	}
	wantPort := ctx.VirtualServerPort

	connections := allConnectionsForSNATAnalysis(summary)
	if len(connections) == 0 {
		hints = append(hints, F5SNATHint{
			Description: "no_zeek_connections_visible_to_classify",
			Evidence:    "the analyze pass returned no Zeek conn records under the active limits",
		})
		return hints
	}

	clientside := 0
	serverside := 0
	for _, conn := range connections {
		if matchesVIP(conn, vipAddr, wantPort) {
			clientside++
		} else {
			serverside++
		}
	}
	if clientside > 0 {
		hints = append(hints, F5SNATHint{
			Description: "clientside_to_vip_observed",
			Evidence:    formatSNATEvidence("connection(s) destined for the configured VIP", clientside),
		})
	}
	if serverside > 0 {
		hints = append(hints, F5SNATHint{
			Description: "non_vip_destinations_observed",
			Evidence:    formatSNATEvidence("connection(s) destined for non-VIP addresses (possibly serverside, possibly unrelated traffic)", serverside),
		})
	}
	return hints
}

// allConnectionsForSNATAnalysis returns every visible Zeek conn
// record from the AnalysisSummary. The summary is built from the
// entire bounded conn.log, not just reset-bearing connections, so
// the classifier sees normal flows as well as resets.
func allConnectionsForSNATAnalysis(summary *AnalysisSummary) []ConnectionSummary {
	if summary == nil {
		return nil
	}
	return summary.Connections
}

func matchesVIP(conn ConnectionSummary, vipAddr netip.Addr, wantPort int) bool {
	dest, err := netip.ParseAddr(strings.TrimSpace(conn.Destination))
	if err != nil || dest != vipAddr {
		return false
	}
	if wantPort > 0 {
		if strings.TrimSpace(conn.DestPort) != intToString(wantPort) {
			return false
		}
	}
	return true
}

func formatSNATEvidence(label string, count int) string {
	if count == 1 {
		return "1 " + label
	}
	return intToString(count) + " " + label
}

func intToString(n int) string {
	// strconv.Itoa would work but pulling a tiny helper avoids
	// shuffling imports if this file picks up more conversions.
	if n == 0 {
		return "0"
	}
	negative := false
	if n < 0 {
		negative = true
		n = -n
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if negative {
		digits = append([]byte{'-'}, digits...)
	}
	return string(digits)
}

// httpStatusClass maps a numeric HTTP status code to a stable bucket
// label. Codes outside the 100-599 range collapse to "unknown" so the
// bucket map never carries unbounded keys.
func httpStatusClass(code int) string {
	switch {
	case code >= 100 && code < 200:
		return "1xx"
	case code >= 200 && code < 300:
		return "2xx"
	case code >= 300 && code < 400:
		return "3xx"
	case code >= 400 && code < 500:
		return "4xx"
	case code >= 500 && code < 600:
		return "5xx"
	default:
		return "unknown"
	}
}

// buildF5ProfileFindings emits info-level findings about what the
// profile observed. Findings here mirror the structured evidence
// rather than introduce new claims; they exist so an LLM scanning
// the findings array sees the profile output without re-parsing
// the nested section.
func buildF5ProfileFindings(section *F5LTMTLSDebugSection) []PacketFinding {
	var findings []PacketFinding
	if section.Resets != nil {
		findings = append(findings, PacketFinding{
			Code:     FindingF5ProfileResetsObserved,
			Severity: "warning",
			Message:  formatF5ResetMessage(section.Resets),
		})
	}
	if section.TLS != nil && section.TLS.HandshakeCount > 0 {
		findings = append(findings, PacketFinding{
			Code:     FindingF5ProfileTLSObserved,
			Severity: "info",
			Message:  formatF5TLSMessage(section.TLS),
		})
	}
	if section.HTTP != nil && section.HTTP.RequestCount > 0 {
		findings = append(findings, PacketFinding{
			Code:     FindingF5ProfileHTTPObserved,
			Severity: "info",
			Message:  formatF5HTTPMessage(section.HTTP),
		})
	}
	return findings
}

func formatF5ResetMessage(r *F5ResetEvidence) string {
	return "Profile observed " + intToString(r.Total) +
		" reset connection(s); originator side=" + intToString(r.OriginatorResets) +
		", responder side=" + intToString(r.ResponderResets)
}

func formatF5TLSMessage(t *F5TLSEvidence) string {
	msg := "Profile observed " + intToString(t.HandshakeCount) + " TLS handshake(s)"
	if len(t.DistinctSNINames) > 0 {
		msg += " across " + intToString(len(t.DistinctSNINames)) + " SNI name(s)"
	}
	return msg + "."
}

func formatF5HTTPMessage(h *F5HTTPEvidence) string {
	return "Profile observed " + intToString(h.RequestCount) + " HTTP request(s) bucketed by status class."
}
