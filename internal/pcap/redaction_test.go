package pcap

import (
	"strings"
	"testing"
)

// TestRedactASCIISecretsCoversDocumentedPatterns is the always-running
// pin for the redaction patterns documented in
// PCAP_SERVER_CONTRACT.md. Each row exercises one of the substrings
// the contract claims redact_secrets catches; together they cover the
// full pattern set declared in asciiSecretPatterns.
//
// New patterns added to the redactor MUST land here in the same MR;
// removed patterns MUST be removed from the contract doc in the same
// MR. The integration test (TestNoSecretLeaksAcrossEntireResponse)
// covers end-to-end leakage via tshark/Zeek; this test covers the
// pure pattern set without any external analyzers.
func TestRedactASCIISecretsCoversDocumentedPatterns(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		mustMask  string // substring that must NOT appear in the output
		mustKeep  string // sentinel value that must remain
		mustEmit  bool   // expects redacted=true
	}{
		{
			name:     "authorization_bearer",
			input:    "Authorization: Bearer super-secret-bearer-token-do-not-leak",
			mustMask: "super-secret-bearer-token-do-not-leak",
			mustKeep: "Authorization:",
			mustEmit: true,
		},
		{
			name:     "proxy_authorization",
			input:    "Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==",
			mustMask: "dXNlcjpwYXNzd29yZA==",
			mustKeep: "Proxy-Authorization:",
			mustEmit: true,
		},
		{
			name:     "cookie",
			input:    "Cookie: session=abcd1234sessionvalue",
			mustMask: "abcd1234sessionvalue",
			mustKeep: "Cookie:",
			mustEmit: true,
		},
		{
			name:     "set_cookie",
			input:    "Set-Cookie: SID=raw-session-cookie; HttpOnly",
			mustMask: "raw-session-cookie",
			mustKeep: "Set-Cookie:",
			mustEmit: true,
		},
		{
			name:     "password_param",
			input:    "GET /login?password=plaintext-password-leak HTTP/1.1",
			mustMask: "plaintext-password-leak",
			mustKeep: "/login",
			mustEmit: true,
		},
		{
			name:     "token_param",
			input:    "GET /resource?token=top-level-api-key-leak&id=42 HTTP/1.1",
			mustMask: "top-level-api-key-leak",
			mustKeep: "id=42",
			mustEmit: true,
		},
		{
			name:     "api_key_param",
			input:    "GET /v1?api_key=00112233aabb HTTP/1.1",
			mustMask: "00112233aabb",
			mustKeep: "/v1",
			mustEmit: true,
		},
		{
			name:     "secret_param",
			input:    "POST /webhook?secret=hmac-shared-secret HTTP/1.1",
			mustMask: "hmac-shared-secret",
			mustKeep: "/webhook",
			mustEmit: true,
		},
		{
			name:     "session_id_param",
			input:    "GET /me?session_id=opaque-cookie-bytes HTTP/1.1",
			mustMask: "opaque-cookie-bytes",
			mustKeep: "/me",
			mustEmit: true,
		},
		{
			name:     "no_match_keeps_text_intact",
			input:    "GET /index.html HTTP/1.1\r\nHost: example.test",
			mustMask: "",
			mustKeep: "GET /index.html",
			mustEmit: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, redacted := redactASCIISecrets(tc.input)
			if tc.mustMask != "" && strings.Contains(got, tc.mustMask) {
				t.Fatalf("output contains unredacted secret %q\n  in: %q\n out: %q", tc.mustMask, tc.input, got)
			}
			if tc.mustKeep != "" && !strings.Contains(got, tc.mustKeep) {
				t.Fatalf("output dropped sentinel %q\n  in: %q\n out: %q", tc.mustKeep, tc.input, got)
			}
			if tc.mustEmit && !redacted {
				t.Fatalf("expected redacted=true; got false for %q", tc.input)
			}
			if !tc.mustEmit && redacted {
				t.Fatalf("expected redacted=false on no-match path; got true for %q", tc.input)
			}
		})
	}
}
