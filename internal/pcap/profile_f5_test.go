package pcap

import (
	"os"
	"strings"
	"testing"

	"cute-pcap-mcp/internal/config"
)

// fixtureAnalysisSummaryForProfile mirrors what buildAnalysisSummary
// would produce on the same synthetic capture: every Zeek conn
// record (reset and non-reset), so the SNAT classifier sees the
// full set, not just resets.
func fixtureAnalysisSummaryForProfile() *AnalysisSummary {
	return &AnalysisSummary{
		Connections: []ConnectionSummary{
			{UID: "C1", Protocol: "tcp", Source: "10.0.0.1", SourcePort: "55555", Destination: "203.0.113.10", DestPort: "443", ConnState: "RSTO"},
			{UID: "C2", Protocol: "tcp", Source: "10.0.0.2", SourcePort: "33333", Destination: "198.51.100.20", DestPort: "8443", ConnState: "RSTR"},
			{UID: "C3", Protocol: "tcp", Source: "10.0.0.3", SourcePort: "44444", Destination: "203.0.113.10", DestPort: "443", ConnState: "SF"},
			{UID: "C4", Protocol: "tcp", Source: "10.0.0.4", SourcePort: "55555", Destination: "192.0.2.99", DestPort: "80", ConnState: "SF"},
		},
	}
}

// fixtureAnalyzeOutputForProfile builds a populated analyzeOutput
// without running tshark/Zeek so the profile builder tests stay
// always-running. The fixture mirrors what the analyze pipeline
// would emit on a small synthetic capture: two reset connections,
// two TLS handshakes (one TLSv1.2, one TLSv1.3), three HTTP
// requests (one 2xx, one 4xx, one 5xx).
func fixtureAnalyzeOutputForProfile() analyzeOutput {
	return analyzeOutput{
		SchemaVersion: SchemaVersion,
		TCPHealth: &TCPHealthSection{
			ResetCount:         2,
			ResetsByOriginator: 1,
			ResetsByResponder:  1,
			ResetConnections: []ConnectionSummary{
				{
					UID:         "C1",
					Protocol:    "tcp",
					Source:      "10.0.0.1",
					SourcePort:  "55555",
					Destination: "203.0.113.10",
					DestPort:    "443",
					ConnState:   "RSTO",
				},
				{
					UID:         "C2",
					Protocol:    "tcp",
					Source:      "10.0.0.2",
					SourcePort:  "33333",
					Destination: "198.51.100.20",
					DestPort:    "8443",
					ConnState:   "RSTR",
				},
			},
		},
		TLS: []TLSHandshakeSummary{
			{ServerName: "api.example.test", Version: "TLSv12", Cipher: "TLS_AES_128_GCM_SHA256"},
			{ServerName: "api.example.test", Version: "TLSv13", Cipher: "TLS_AES_256_GCM_SHA384"},
		},
		HTTP: []HTTPRequestSummary{
			{Method: "GET", Host: "api.example.test", URI: "/v1/status", StatusCode: 200},
			{Method: "GET", Host: "api.example.test", URI: "/v1/missing", StatusCode: 404},
			{Method: "POST", Host: "api.example.test", URI: "/v1/error", StatusCode: 503},
		},
	}
}

// TestF5ProfileBuildsResetTLSAndHTTPSections pins the basic
// derivation: every populated input section produces the matching
// profile sub-section with structured counts.
func TestF5ProfileBuildsResetTLSAndHTTPSections(t *testing.T) {
	out := fixtureAnalyzeOutputForProfile()
	profile := buildF5LTMTLSDebugProfile(out, fixtureAnalysisSummaryForProfile(), nil)
	if profile == nil {
		t.Fatal("profile = nil, want populated")
	}
	if profile.Name != AnalysisProfileF5LTMTLSDebug {
		t.Fatalf("Name = %q", profile.Name)
	}
	if len(profile.Limitations) == 0 {
		t.Fatal("Limitations is empty; every profile must declare its bounds")
	}
	if profile.F5LTMTLSDebug == nil {
		t.Fatal("F5LTMTLSDebug = nil")
	}

	if r := profile.F5LTMTLSDebug.Resets; r == nil {
		t.Fatal("Resets = nil")
	} else if r.Total != 2 || r.OriginatorResets != 1 || r.ResponderResets != 1 {
		t.Fatalf("Resets = %+v", r)
	}

	if tls := profile.F5LTMTLSDebug.TLS; tls == nil {
		t.Fatal("TLS = nil")
	} else {
		if tls.HandshakeCount != 2 {
			t.Fatalf("HandshakeCount = %d", tls.HandshakeCount)
		}
		if len(tls.DistinctSNINames) != 1 || tls.DistinctSNINames[0] != "api.example.test" {
			t.Fatalf("DistinctSNINames = %v", tls.DistinctSNINames)
		}
		if tls.Versions["TLSv12"] != 1 || tls.Versions["TLSv13"] != 1 {
			t.Fatalf("Versions = %v", tls.Versions)
		}
	}

	if http := profile.F5LTMTLSDebug.HTTP; http == nil {
		t.Fatal("HTTP = nil")
	} else {
		if http.RequestCount != 3 {
			t.Fatalf("RequestCount = %d", http.RequestCount)
		}
		if http.StatusClassCounts["2xx"] != 1 ||
			http.StatusClassCounts["4xx"] != 1 ||
			http.StatusClassCounts["5xx"] != 1 {
			t.Fatalf("StatusClassCounts = %v", http.StatusClassCounts)
		}
	}
}

// TestF5ProfileWithoutContextRefusesToGuessSides pins the
// truth-over-closure rule: without f5_context the profile must NOT
// classify connections as clientside / serverside, and must emit a
// hint that says so explicitly.
func TestF5ProfileWithoutContextRefusesToGuessSides(t *testing.T) {
	out := fixtureAnalyzeOutputForProfile()
	profile := buildF5LTMTLSDebugProfile(out, fixtureAnalysisSummaryForProfile(), nil)
	if profile == nil {
		t.Fatal("profile = nil")
	}
	hints := profile.F5LTMTLSDebug.SNAT
	if len(hints) != 1 {
		t.Fatalf("expected exactly one hint without context, got %v", hints)
	}
	if hints[0].Description != "clientside_classification_skipped_no_context" {
		t.Fatalf("hint Description = %q", hints[0].Description)
	}
}

// TestF5ProfilePortOnlyContextRefusesClientsideClaim pins the
// truth-over-closure rule that a bare port number is not a VIP. A
// caller who supplies only virtual_server_port (no IP) must NOT see
// every connection on that port labeled clientside_to_vip — port
// 443 is everyone's HTTPS — so the profile emits an
// insufficient-context hint instead.
func TestF5ProfilePortOnlyContextRefusesClientsideClaim(t *testing.T) {
	out := fixtureAnalyzeOutputForProfile()
	profile := buildF5LTMTLSDebugProfile(out, fixtureAnalysisSummaryForProfile(), &F5Context{
		VirtualServerPort: 443,
	})
	if profile == nil {
		t.Fatal("profile = nil")
	}
	hints := profile.F5LTMTLSDebug.SNAT
	if len(hints) != 1 {
		t.Fatalf("expected exactly one insufficient-context hint, got %v", hints)
	}
	if hints[0].Description != "clientside_classification_skipped_no_vip_ip" {
		t.Fatalf("hint Description = %q", hints[0].Description)
	}
	for _, h := range hints {
		if strings.Contains(h.Description, "clientside_to_vip_observed") {
			t.Fatalf("port-only context should not produce clientside_to_vip_observed; got %v", h)
		}
	}
}

// TestF5ProfileSNATHintsClassifyAllConnections pins the fix for the
// "ignores normal flows" finding: a non-reset connection to the VIP
// is classified as clientside, and a non-reset connection to a
// non-VIP IP is classified as non-VIP. The previous version only
// looked at TCPHealth.ResetConnections.
func TestF5ProfileSNATHintsClassifyAllConnections(t *testing.T) {
	// Strip TCPHealth from the analyzeOutput so the test cannot rely
	// on the reset-only legacy path. Pass a summary with two normal
	// (non-reset) connections instead.
	out := analyzeOutput{}
	summary := &AnalysisSummary{
		Connections: []ConnectionSummary{
			{UID: "C1", Destination: "203.0.113.10", DestPort: "443", ConnState: "SF"},
			{UID: "C2", Destination: "192.0.2.99", DestPort: "80", ConnState: "SF"},
		},
	}
	profile := buildF5LTMTLSDebugProfile(out, summary, &F5Context{
		VirtualServerIP:   "203.0.113.10",
		VirtualServerPort: 443,
	})
	if profile == nil {
		t.Fatal("profile = nil")
	}
	var sawClient, sawNonVIP bool
	for _, h := range profile.F5LTMTLSDebug.SNAT {
		switch h.Description {
		case "clientside_to_vip_observed":
			sawClient = true
		case "non_vip_destinations_observed":
			sawNonVIP = true
		}
	}
	if !sawClient {
		t.Fatalf("expected clientside_to_vip_observed for the SF→VIP flow; got %v", profile.F5LTMTLSDebug.SNAT)
	}
	if !sawNonVIP {
		t.Fatalf("expected non_vip_destinations_observed for the SF→non-VIP flow; got %v", profile.F5LTMTLSDebug.SNAT)
	}
}

// TestF5ProfileWithVIPClassifiesConnections pins the contextful
// classification: when f5_context.virtual_server_ip + port match a
// connection's destination, that connection is hinted as
// clientside_to_vip; non-matching destinations are hinted as
// non_vip_destinations.
func TestF5ProfileWithVIPClassifiesConnections(t *testing.T) {
	out := fixtureAnalyzeOutputForProfile()
	profile := buildF5LTMTLSDebugProfile(out, fixtureAnalysisSummaryForProfile(), &F5Context{
		VirtualServerIP:   "203.0.113.10",
		VirtualServerPort: 443,
	})
	if profile == nil {
		t.Fatal("profile = nil")
	}
	hints := profile.F5LTMTLSDebug.SNAT
	if len(hints) == 0 {
		t.Fatalf("expected SNAT hints with VIP context, got none")
	}
	var clientside, serverside bool
	for _, h := range hints {
		switch h.Description {
		case "clientside_to_vip_observed":
			clientside = true
		case "non_vip_destinations_observed":
			serverside = true
		case "no_zeek_connections_visible_to_classify":
			t.Fatalf("classifier said no connections; fixture has 2: %v", hints)
		}
	}
	if !clientside {
		t.Fatalf("expected clientside_to_vip_observed; hints = %v", hints)
	}
	if !serverside {
		t.Fatalf("expected non_vip_destinations_observed; hints = %v", hints)
	}
}

// TestApplyAnalysisProfileSurfacesUnknownNames pins the
// truth-over-closure path for unknown profile names: the analyze
// pipeline must NOT silently skip — it emits a warning finding
// (analysis_profile_unknown) so the host knows the requested name
// was not honored.
func TestApplyAnalysisProfileSurfacesUnknownNames(t *testing.T) {
	out := fixtureAnalyzeOutputForProfile()
	findings := applyAnalysisProfile(&out, fixtureAnalysisSummaryForProfile(), "totally_made_up_profile", nil)
	if out.Profile != nil {
		t.Fatalf("expected nil Profile for unknown name; got %+v", out.Profile)
	}
	var found bool
	for _, f := range findings {
		if f.Code == FindingProfileUnknown {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing analysis_profile_unknown finding; got %#v", findings)
	}
}

func TestValidateF5ContextRejectsBadInputs(t *testing.T) {
	cases := []struct {
		name string
		ctx  *F5Context
	}{
		{name: "garbage_vip", ctx: &F5Context{VirtualServerIP: "not.an.ip"}},
		{name: "vip_filter_injection", ctx: &F5Context{VirtualServerIP: "10.0.0.1 or 1=1"}},
		{name: "port_too_high", ctx: &F5Context{VirtualServerPort: 65536}},
		{name: "port_negative", ctx: &F5Context{VirtualServerPort: -1}},
		{name: "vs_name_too_long", ctx: &F5Context{VirtualServerName: strings.Repeat("a", f5ContextNameMaxLen+1)}},
		{name: "pool_name_too_long", ctx: &F5Context{PoolName: strings.Repeat("a", f5ContextNameMaxLen+1)}},
		{name: "snat_pool_name_too_long", ctx: &F5Context{SNATPoolName: strings.Repeat("a", f5ContextNameMaxLen+1)}},
		{name: "notes_too_long", ctx: &F5Context{Notes: strings.Repeat("a", f5ContextNotesMaxLen+1)}},
		{name: "vs_name_with_nul", ctx: &F5Context{VirtualServerName: "vs\x00inject"}},
		{name: "notes_with_nul", ctx: &F5Context{Notes: "ok\x00bad"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateF5Context(tc.ctx)
			if err == nil {
				t.Fatal("expected validation error, got nil")
			}
			if got := classify(err).Kind; got != ErrorKindValidationFailed {
				t.Fatalf("Kind = %q", got)
			}
		})
	}

	if err := validateF5Context(&F5Context{
		VirtualServerName: "free-form name",
		VirtualServerIP:   "10.0.0.1",
		VirtualServerPort: 443,
		PoolName:          "pool-1",
		Notes:             "produced by foo on bar",
	}); err != nil {
		t.Fatalf("legitimate context rejected: %v", err)
	}

	if err := validateF5Context(nil); err != nil {
		t.Fatalf("nil context should pass: %v", err)
	}
}

// TestAnalyzeArtifactDispatcherFindingsSurviveBuildFindings is the
// always-running pin for the M4-round-2 fix. Even with no analyzers
// available (capinfos / tshark / zeek all missing), analyzeArtifact
// still runs to completion and should merge the dispatcher's
// analysis_profile_unknown finding into out.Findings AFTER
// buildFindings runs. The earlier code overwrote the slice, hiding
// the dispatcher's signal from MCP callers.
func TestAnalyzeArtifactDispatcherFindingsSurviveBuildFindings(t *testing.T) {
	dir := t.TempDir()
	pcap := dir + "/empty.pcap"
	if err := os.WriteFile(pcap, libpcapHeaderOnly(), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Normalize(config.Config{AllowedArtifactDirs: []string{dir}})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := inspectArtifact(pcap, cfg, artifactExpectations{})
	if err != nil {
		t.Fatal(err)
	}
	out := analyzeArtifact(t.Context(), artifact, cfg, analyzeInput{
		Path:            pcap,
		AnalysisProfile: "definitely-not-a-profile",
	})
	if !findingPresent(out.Findings, FindingProfileUnknown) {
		t.Fatalf("dispatcher finding analysis_profile_unknown was lost; findings = %v", out.Findings)
	}
}

// TestAnalyzeArtifactIntegrationProfileFindingsSurvive covers the
// fix for the P2 "findings overwritten" review finding. The
// dispatcher returns findings to the caller now, and the caller
// merges them AFTER buildFindings. Without that change, every
// dispatcher finding (analysis_profile_applied / _unknown) was
// silently overwritten.
//
// The test exercises the real analyze pipeline (so it runs only
// when tshark + Zeek are available) and asserts that both the
// dispatcher finding and the per-profile findings appear in
// out.Findings.
func TestAnalyzeArtifactIntegrationProfileFindingsSurvive(t *testing.T) {
	requireCommand(t, "tshark")
	requireCommand(t, "zeek")
	root := t.TempDir()
	pcapDir := root + "/pcaps"
	if err := os.MkdirAll(pcapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pcap := pcapDir + "/http.pcap"
	if err := os.WriteFile(pcap, syntheticHTTPPcap(), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Normalize(config.Config{
		AllowedArtifactDirs: []string{pcapDir},
		Workspace: config.WorkspaceConfig{
			TmpDir: root + "/tmp",
		},
		Analysis: config.AnalysisConfig{
			CommandTimeoutSeconds: 10,
			MaxStdoutBytes:        200000,
			MaxPacketRows:         20,
			MaxASCIIStrings:       20,
			MaxASCIIBytes:         20000,
			MaxZeekRecordsPerLog:  20,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := inspectArtifact(pcap, cfg, artifactExpectations{})
	if err != nil {
		t.Fatal(err)
	}

	out := analyzeArtifact(t.Context(), artifact, cfg, analyzeInput{
		Path:            pcap,
		AnalysisProfile: AnalysisProfileF5LTMTLSDebug,
		F5Context: &F5Context{
			VirtualServerIP:   "198.51.100.20",
			VirtualServerPort: 80,
		},
	})

	if out.Profile == nil {
		t.Fatalf("Profile = nil; got errors=%v findings=%v", out.Errors, out.Findings)
	}
	if !findingPresent(out.Findings, FindingProfileApplied) {
		t.Errorf("missing analysis_profile_applied; findings=%v", out.Findings)
	}

	// Now the unknown-profile path through the full pipeline.
	out2 := analyzeArtifact(t.Context(), artifact, cfg, analyzeInput{
		Path:            pcap,
		AnalysisProfile: "definitely-not-a-profile",
	})
	if out2.Profile != nil {
		t.Errorf("unknown profile name should not populate Profile; got %+v", out2.Profile)
	}
	if !findingPresent(out2.Findings, FindingProfileUnknown) {
		t.Errorf("missing analysis_profile_unknown finding; got %v", out2.Findings)
	}
}

func findingPresent(findings []PacketFinding, code string) bool {
	for _, f := range findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func TestHTTPStatusClassBuckets(t *testing.T) {
	cases := []struct {
		code int
		want string
	}{
		{100, "1xx"}, {199, "1xx"},
		{200, "2xx"}, {299, "2xx"},
		{301, "3xx"},
		{418, "4xx"},
		{503, "5xx"},
		{0, "unknown"}, {600, "unknown"}, {-1, "unknown"},
	}
	for _, tc := range cases {
		if got := httpStatusClass(tc.code); got != tc.want {
			t.Errorf("httpStatusClass(%d) = %q, want %q", tc.code, got, tc.want)
		}
	}
}
