package pcap

import "testing"

func TestBuildAnalysisSummaryAndFindings(t *testing.T) {
	zeek := ZeekReport{Logs: []ZeekLog{
		{
			Name: "conn",
			Records: []map[string]string{{
				"uid":        "C1",
				"proto":      "tcp",
				"service":    "http",
				"id.orig_h":  "192.0.2.10",
				"id.orig_p":  "55000",
				"id.resp_h":  "198.51.100.20",
				"id.resp_p":  "80",
				"conn_state": "RSTO",
				"history":    "ShADadR",
				"orig_bytes": "100",
				"resp_bytes": "200",
			}},
		},
		{
			Name: "dns",
			Records: []map[string]string{{
				"uid":        "D1",
				"id.orig_h":  "192.0.2.10",
				"query":      "missing.example",
				"qtype_name": "A",
				"rcode_name": "NXDOMAIN",
			}},
		},
		{
			Name: "http",
			Records: []map[string]string{{
				"uid":         "H1",
				"id.orig_h":   "192.0.2.10",
				"id.resp_h":   "198.51.100.20",
				"method":      "GET",
				"host":        "example.test",
				"uri":         "/login?token=secret&x=1",
				"status_code": "500",
				"status_msg":  "Internal Server Error",
			}},
		},
		{
			Name: "ssl",
			Records: []map[string]string{{
				"uid":         "S1",
				"id.orig_h":   "192.0.2.10",
				"id.resp_h":   "203.0.113.40",
				"server_name": "tls.example",
				"version":     "TLSv12",
				"cipher":      "TLS_AES_128_GCM_SHA256",
			}},
		},
		{
			Name: "notice",
			Records: []map[string]string{{
				"uid":  "N1",
				"note": "Scan::Port_Scan",
				"msg":  "scan observed",
				"src":  "192.0.2.10",
				"dst":  "198.51.100.20",
			}},
		},
		{
			Name: "weird",
			Records: []map[string]string{{
				"uid":    "W1",
				"name":   "bad_TCP_checksum",
				"notice": "F",
			}},
		},
	}}

	summary := buildAnalysisSummary(zeek)
	if summary == nil {
		t.Fatal("summary = nil")
	}
	if got := summary.Signals["tcp_resets"]; got != 1 {
		t.Fatalf("tcp_resets = %d, want 1", got)
	}
	if got := summary.Signals["http_error_statuses"]; got != 1 {
		t.Fatalf("http_error_statuses = %d, want 1", got)
	}
	if got := summary.Signals["dns_rejections"]; got != 1 {
		t.Fatalf("dns_rejections = %d, want 1", got)
	}
	if got := len(summary.TLSHandshakes); got != 1 {
		t.Fatalf("len(TLSHandshakes) = %d, want 1", got)
	}
	if got := summary.HTTPRequests[0].URI; got != "/login?token=[REDACTED]&x=1" {
		t.Fatalf("redacted URI = %q", got)
	}
	if !summary.HTTPRequests[0].Redacted {
		t.Fatal("HTTP request Redacted = false, want true")
	}

	findings := summaryFindings(summary)
	for _, code := range []string{
		"zeek_notices_present",
		"zeek_weird_events_present",
		"http_error_statuses_present",
		"dns_rejections_present",
		"tcp_resets_present",
	} {
		if !hasFinding(findings, code) {
			t.Fatalf("missing finding %q in %#v", code, findings)
		}
	}
}

func TestValidateAnalyzeInputRejectsInvalidDisplayFilter(t *testing.T) {
	if err := validateAnalyzeInput(analyzeInput{DisplayFilter: "http\x00"}); err == nil {
		t.Fatal("validateAnalyzeInput returned nil, want error")
	}
}

func hasFinding(findings []PacketFinding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}
