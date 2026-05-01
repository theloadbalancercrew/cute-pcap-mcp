package pcap

// SchemaVersion is the stable wire-shape version for analyzeOutput. It
// is bumped on additive changes (new optional fields → minor) and on
// breaking changes (removed fields, renamed fields, retyped values →
// major). Hosts may switch on this value but should not break on
// minor bumps.
const SchemaVersion = "1.0.0"

// analyzeOutput is the model-facing shape returned by both
// pcap_analyze (the new stable name) and analyze_pcap (its
// compatibility alias). The top-level layout is the contract
// described in docs/PCAP_SERVER_CONTRACT.md.
//
// Section pointers are nil when the operator opted out via
// include_capinfos / include_tshark / include_zeek / include_ascii.
// Non-nil sections may still be empty if the source capture had no
// matching evidence (e.g. no DNS records).
type analyzeOutput struct {
	SchemaVersion string `json:"schema_version"`

	// Artifact identifies the input pcap (path, size, sha256). It is
	// always populated.
	Artifact ArtifactInfo `json:"artifact"`

	// Top-level sections in the order documented by the contract.
	CaptureSummary *CaptureSummary       `json:"capture_summary,omitempty"`
	Protocols      *ProtocolsSection     `json:"protocols,omitempty"`
	Conversations  map[string]string     `json:"conversations,omitempty"`
	Packets        []TSharkPacketSummary `json:"packets,omitempty"`
	DNS            []DNSQuerySummary     `json:"dns,omitempty"`
	HTTP           []HTTPRequestSummary  `json:"http,omitempty"`
	TLS            []TLSHandshakeSummary `json:"tls,omitempty"`
	TCPHealth      *TCPHealthSection     `json:"tcp_health,omitempty"`
	Notices        []ZeekEventSummary    `json:"notices,omitempty"`
	WeirdEvents    []ZeekEventSummary    `json:"weird_events,omitempty"`
	ZeekLogs       []ZeekLog             `json:"zeek_logs,omitempty"`
	ASCII          *ASCIIReport          `json:"ascii,omitempty"`
	TLSDecryption  *TLSDecryptionStatus  `json:"tls_decryption,omitempty"`
	Profile        *AnalysisProfileResult `json:"profile,omitempty"`
	Findings       []PacketFinding       `json:"findings"`
	Artifacts      []OutputArtifact      `json:"artifacts,omitempty"`

	// Errors collects per-section partial failures. Errors and Error
	// are mutually exclusive: a non-nil Error means the whole call
	// failed before any section ran.
	Errors []toolError `json:"errors,omitempty"`
	Error  *toolError  `json:"error,omitempty"`

	Metadata map[string]string `json:"metadata,omitempty"`
}

// CaptureSummary is the structured view over capinfos output. The
// raw capinfos text is preserved verbatim in Raw; parsed fields are
// best-effort and may be empty when the tshark suite changes its
// capinfos output format.
type CaptureSummary struct {
	PacketCount       int64   `json:"packet_count,omitempty"`
	DurationSeconds   float64 `json:"duration_seconds,omitempty"`
	StartTime         string  `json:"start_time,omitempty"`
	EndTime           string  `json:"end_time,omitempty"`
	DataByteRate      string  `json:"data_byte_rate,omitempty"`
	PacketRate        string  `json:"packet_rate,omitempty"`
	FileType          string  `json:"file_type,omitempty"`
	Encapsulation     string  `json:"encapsulation,omitempty"`
	SnapshotLength    int     `json:"snapshot_length,omitempty"`
	FileSizeBytes     int64   `json:"file_size_bytes,omitempty"`
	AveragePacketSize float64 `json:"average_packet_size,omitempty"`

	// Raw is the verbatim capinfos human-readable text, bounded by
	// analysis.max_stdout_bytes.
	Raw string `json:"raw,omitempty"`
}

// ProtocolsSection wraps the tshark `-z io,phs` protocol-hierarchy
// table. The hierarchy field stays as raw text because the tshark
// table is meaningfully tree-shaped; structuring it would lose the
// nesting an LLM relies on.
type ProtocolsSection struct {
	Hierarchy string `json:"hierarchy,omitempty"`
}

// TCPHealthSection collects tshark + Zeek evidence about TCP-layer
// problems (resets, reset-side hints, connections with reset-like
// history). Reset-side inference uses Zeek conn_state semantics:
// RSTO = originator reset, RSTR = responder reset.
type TCPHealthSection struct {
	ResetCount         int                 `json:"reset_count,omitempty"`
	ResetsByOriginator int                 `json:"resets_by_originator,omitempty"`
	ResetsByResponder  int                 `json:"resets_by_responder,omitempty"`
	ResetConnections   []ConnectionSummary `json:"reset_connections,omitempty"`
}

// OutputArtifact is the wire shape for a server-written derived
// artifact (analysis.json, summary.md, or pcap_filter outputs). The
// path is server-generated under
// `cfg.Workspace.OutputDir`; the operator never supplies output
// paths.
type OutputArtifact struct {
	Path          string `json:"path"`
	SizeBytes     int64  `json:"size_bytes"`
	SHA256        string `json:"sha256"`
	ContentType   string `json:"content_type"`
	SchemaVersion string `json:"schema_version,omitempty"`
	GeneratedAt   string `json:"generated_at"`
	Kind          string `json:"kind"`
}

// Output artifact kind tokens. Switch on these, not on file
// extension. Stable across releases.
const (
	OutputArtifactKindAnalysisJSON   = "analysis_json"
	OutputArtifactKindSummaryMarkdown = "summary_markdown"
	OutputArtifactKindFilteredPCAP    = "filtered_pcap"
)
