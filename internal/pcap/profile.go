package pcap

// Analysis profile names. Stable model-facing tokens; never rename,
// only add. Profiles layer additional analysis on top of the generic
// pcap_analyze evidence; selecting a profile never replaces or
// suppresses the generic sections.
const (
	AnalysisProfileF5LTMTLSDebug = "f5_ltm_tls_debug"
)

// AnalysisProfileResult is the wire shape returned under
// analyzeOutput.Profile when the caller selects analysis_profile. The
// Name field is always set; per-profile data lands under a typed
// nested field discriminated by Name. Limitations is always
// populated — every profile must document what packet evidence
// alone cannot prove.
//
// Adding a new profile is additive: declare a new constant in this
// file, register it in profileBuilders, add a new nested field on
// this struct (with omitempty), and emit per-profile limitations.
type AnalysisProfileResult struct {
	Name          string                `json:"name"`
	Limitations   []string              `json:"limitations"`
	Findings      []PacketFinding       `json:"findings,omitempty"`
	F5LTMTLSDebug *F5LTMTLSDebugSection `json:"f5_ltm_tls_debug,omitempty"`
}

// f5LTMTLSDebugLimitations is the always-included limitations list
// for the f5_ltm_tls_debug profile. Packet evidence alone is the
// hard ceiling; every claim that requires load-balancer config must come
// from explicit f5_context the operator supplied, not from
// inference. Hosts switch on these strings as fixed warnings; the
// list only grows.
var f5LTMTLSDebugLimitations = []string{
	"Packet evidence alone cannot prove virtual server, pool, SNAT pool, profile, persistence, or policy configuration on the load balancer.",
	"Reset-side classification uses Zeek conn_state (RSTO = originator, RSTR = responder) and is silent on which side is the client when no f5_context is supplied.",
	"SNAT/clientside/serverside hints are derived from optional f5_context only; without f5_context.virtual_server the profile reports the unknown rather than guessing.",
	"TLS handshake fields (SNI, version, cipher, validation_status) come from Zeek's ssl/tls log on the wire; absence does not prove TLS was not negotiated.",
	"HTTP status classes are bounded by analysis.max_zeek_records_per_log; counts reflect only the records returned in this call.",
}
