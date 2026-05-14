package pcap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"cute-pcap-mcp/internal/config"
)

func TestListPCAPArtifactsEmptyRoot(t *testing.T) {
	cfg := normalizedInventoryConfig(t, t.TempDir())

	out, err := listPCAPArtifactsWithOptions(context.Background(), cfg, listArtifactsInput{}, artifactInventoryOptions{
		MaxScanEntries:  10,
		HashBudgetBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Count != 0 || len(out.Artifacts) != 0 {
		t.Fatalf("inventory returned artifacts for empty root: %#v", out.Artifacts)
	}
	if out.Truncated {
		t.Fatal("Truncated = true for empty root")
	}
	if out.NextCursor != "" {
		t.Fatalf("NextCursor = %q, want empty", out.NextCursor)
	}
	if out.ScanStatus != artifactInventoryScanComplete {
		t.Fatalf("ScanStatus = %q, want %q", out.ScanStatus, artifactInventoryScanComplete)
	}
}

func TestListPCAPArtifactsPopulatedRootMetadataAndOrder(t *testing.T) {
	root := t.TempDir()
	writeInventoryFile(t, filepath.Join(root, "b.pcapng"), []byte("second"))
	writeInventoryFile(t, filepath.Join(root, "a.pcap"), []byte("first"))
	writeInventoryFile(t, filepath.Join(root, "ignored.txt"), []byte("ignore me"))
	writeInventoryFile(t, filepath.Join(root, "nested", "c.pcap"), []byte("third"))
	cfg := normalizedInventoryConfig(t, root)

	out, err := listPCAPArtifactsWithOptions(context.Background(), cfg, listArtifactsInput{}, artifactInventoryOptions{
		MaxScanEntries:  20,
		HashBudgetBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := inventoryBasenames(out), []string{"a.pcap", "b.pcapng", "c.pcap"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("basenames = %v, want %v", got, want)
	}
	if out.Truncated {
		t.Fatalf("Truncated = true, want false")
	}
	for _, artifact := range out.Artifacts {
		if artifact.Path == "" || !filepath.IsAbs(artifact.Path) {
			t.Fatalf("artifact path is not absolute: %#v", artifact)
		}
		if artifact.SizeBytes == 0 {
			t.Fatalf("artifact size missing: %#v", artifact)
		}
		if artifact.HashStatus != artifactInventoryHashComputed || artifact.SHA256 == "" {
			t.Fatalf("artifact hash not computed: %#v", artifact)
		}
		if artifact.ModifiedAt == "" {
			t.Fatalf("artifact modified_at missing: %#v", artifact)
		}
	}
	if out.Artifacts[0].ContentType != "application/vnd.tcpdump.pcap" {
		t.Fatalf("pcap content type = %q", out.Artifacts[0].ContentType)
	}
	if out.Artifacts[1].ContentType != "application/x-pcapng" {
		t.Fatalf("pcapng content type = %q", out.Artifacts[1].ContentType)
	}
	if out.Artifacts[0].SHA256 != sha256Hex([]byte("first")) {
		t.Fatalf("a.pcap sha256 = %q, want %q", out.Artifacts[0].SHA256, sha256Hex([]byte("first")))
	}
}

func TestListPCAPArtifactsPaginatesWithLastScannedCursor(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.pcap", "b.pcap", "c.pcap"} {
		writeInventoryFile(t, filepath.Join(root, name), []byte(name))
	}
	cfg := normalizedInventoryConfig(t, root)

	first, err := listPCAPArtifactsWithOptions(context.Background(), cfg, listArtifactsInput{Limit: inventoryLimit(2)}, artifactInventoryOptions{
		MaxScanEntries:  10,
		HashBudgetBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := inventoryBasenames(first), []string{"a.pcap", "b.pcap"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("first page basenames = %v, want %v", got, want)
	}
	if !first.Truncated || first.NextCursor == "" {
		t.Fatalf("first page should be truncated with cursor: %#v", first)
	}
	if first.ScanStatus != artifactInventoryScanPageLimit {
		t.Fatalf("first ScanStatus = %q, want %q", first.ScanStatus, artifactInventoryScanPageLimit)
	}

	second, err := listPCAPArtifactsWithOptions(context.Background(), cfg, listArtifactsInput{
		Limit:  inventoryLimit(2),
		Cursor: first.NextCursor,
	}, artifactInventoryOptions{
		MaxScanEntries:  10,
		HashBudgetBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := inventoryBasenames(second), []string{"c.pcap"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("second page basenames = %v, want %v", got, want)
	}
	if second.Truncated || second.NextCursor != "" {
		t.Fatalf("second page should be complete without cursor: %#v", second)
	}
}

func TestListPCAPArtifactsScanBudgetCursorUsesLastScannedKey(t *testing.T) {
	root := t.TempDir()
	writeInventoryFile(t, filepath.Join(root, "a.txt"), []byte("not pcap"))
	writeInventoryFile(t, filepath.Join(root, "b.txt"), []byte("not pcap either"))
	writeInventoryFile(t, filepath.Join(root, "c.pcap"), []byte("pcap one"))
	writeInventoryFile(t, filepath.Join(root, "d.pcap"), []byte("pcap two"))
	cfg := normalizedInventoryConfig(t, root)

	first, err := listPCAPArtifactsWithOptions(context.Background(), cfg, listArtifactsInput{Limit: inventoryLimit(10)}, artifactInventoryOptions{
		MaxScanEntries:  2,
		HashBudgetBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Count != 0 {
		t.Fatalf("first page Count = %d, want 0", first.Count)
	}
	if !first.Truncated || first.NextCursor == "" {
		t.Fatalf("scan-budget page should be truncated with cursor: %#v", first)
	}
	if first.ScanStatus != artifactInventoryScanBudgetReached {
		t.Fatalf("ScanStatus = %q, want %q", first.ScanStatus, artifactInventoryScanBudgetReached)
	}

	second, err := listPCAPArtifactsWithOptions(context.Background(), cfg, listArtifactsInput{
		Limit:  inventoryLimit(10),
		Cursor: first.NextCursor,
	}, artifactInventoryOptions{
		MaxScanEntries:  10,
		HashBudgetBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := inventoryBasenames(second), []string{"c.pcap", "d.pcap"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("second page basenames = %v, want %v", got, want)
	}
}

func TestListPCAPArtifactsHashBudgetOmissionsArePerEntry(t *testing.T) {
	root := t.TempDir()
	writeInventoryFile(t, filepath.Join(root, "a.pcap"), []byte("12345678"))
	writeInventoryFile(t, filepath.Join(root, "b.pcap"), []byte("abcdefgh"))
	cfg := normalizedInventoryConfig(t, root)

	out, err := listPCAPArtifactsWithOptions(context.Background(), cfg, listArtifactsInput{Limit: inventoryLimit(10)}, artifactInventoryOptions{
		MaxScanEntries:  10,
		HashBudgetBytes: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := inventoryBasenames(out), []string{"a.pcap", "b.pcap"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("basenames = %v, want %v", got, want)
	}
	if out.Artifacts[0].HashStatus != artifactInventoryHashComputed || out.Artifacts[0].SHA256 == "" {
		t.Fatalf("first artifact should be hashed: %#v", out.Artifacts[0])
	}
	second := out.Artifacts[1]
	if second.HashStatus != artifactInventoryHashOmitted {
		t.Fatalf("second HashStatus = %q, want %q", second.HashStatus, artifactInventoryHashOmitted)
	}
	if second.SHA256 != "" {
		t.Fatalf("second SHA256 = %q, want empty", second.SHA256)
	}
	if got, want := second.OmittedReasons, []string{artifactInventoryOmitHashBudgetReached}; !reflect.DeepEqual(got, want) {
		t.Fatalf("second OmittedReasons = %v, want %v", got, want)
	}
	if out.HashBytesUsed != 8 {
		t.Fatalf("HashBytesUsed = %d, want 8", out.HashBytesUsed)
	}
}

func TestListPCAPArtifactsFailSoftSkipsSymlinkEscapeBesideGoodFile(t *testing.T) {
	allowed := t.TempDir()
	outside := t.TempDir()
	outsidePath := filepath.Join(outside, "outside.pcap")
	writeInventoryFile(t, outsidePath, []byte("outside"))
	if err := os.Symlink(outsidePath, filepath.Join(allowed, "escape.pcap")); err != nil {
		t.Skipf("os.Symlink unavailable: %v", err)
	}
	writeInventoryFile(t, filepath.Join(allowed, "good.pcap"), []byte("good"))
	cfg := normalizedInventoryConfig(t, allowed)

	out, err := listPCAPArtifactsWithOptions(context.Background(), cfg, listArtifactsInput{Limit: inventoryLimit(10)}, artifactInventoryOptions{
		MaxScanEntries:  10,
		HashBudgetBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := inventoryBasenames(out), []string{"good.pcap"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("basenames = %v, want %v", got, want)
	}
	if got := inventorySkipCount(out, ErrorKindPathOutsideAllowlist); got != 1 {
		t.Fatalf("path_outside_allowlist skip count = %d, want 1 (skips=%v)", got, out.Skips)
	}
}

func TestListPCAPArtifactsSkipsSymlinkWhoseResolvedPathIsNotPCAP(t *testing.T) {
	allowed := t.TempDir()
	target := filepath.Join(allowed, "notes.txt")
	writeInventoryFile(t, target, []byte("not a pcap"))
	if err := os.Symlink(target, filepath.Join(allowed, "link.pcap")); err != nil {
		t.Skipf("os.Symlink unavailable: %v", err)
	}
	writeInventoryFile(t, filepath.Join(allowed, "good.pcap"), []byte("good"))
	cfg := normalizedInventoryConfig(t, allowed)

	out, err := listPCAPArtifactsWithOptions(context.Background(), cfg, listArtifactsInput{Limit: inventoryLimit(10)}, artifactInventoryOptions{
		MaxScanEntries:  10,
		HashBudgetBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := inventoryBasenames(out), []string{"good.pcap"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("basenames = %v, want %v", got, want)
	}
	if got := inventorySkipCount(out, artifactInventorySkipUnsupported); got != 1 {
		t.Fatalf("unsupported extension skip count = %d, want 1 (skips=%v)", got, out.Skips)
	}
}

func TestListPCAPArtifactsRejectsBadCallerInput(t *testing.T) {
	cfg := normalizedInventoryConfig(t, t.TempDir())

	_, err := listPCAPArtifacts(context.Background(), cfg, listArtifactsInput{Limit: inventoryLimit(maxArtifactInventoryLimit + 1)})
	assertInventoryValidationError(t, err, "limit", ValidationReasonOutOfRange)

	_, err = listPCAPArtifacts(context.Background(), cfg, listArtifactsInput{Limit: inventoryLimit(0)})
	assertInventoryValidationError(t, err, "limit", ValidationReasonOutOfRange)

	_, err = listPCAPArtifacts(context.Background(), cfg, listArtifactsInput{Cursor: "not-a-valid-cursor"})
	assertInventoryValidationError(t, err, "cursor", ValidationReasonInvalidFormat)
}

func inventoryLimit(limit int) *int {
	return &limit
}

func normalizedInventoryConfig(t *testing.T, root string) config.Config {
	t.Helper()
	cfg, err := config.Normalize(config.Config{AllowedArtifactDirs: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func writeInventoryFile(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func inventoryBasenames(out listArtifactsOutput) []string {
	names := make([]string, 0, len(out.Artifacts))
	for _, artifact := range out.Artifacts {
		names = append(names, artifact.Basename)
	}
	return names
}

func inventorySkipCount(out listArtifactsOutput, reason string) int {
	for _, skip := range out.Skips {
		if skip.Reason == reason {
			return skip.Count
		}
	}
	return 0
}

func assertInventoryValidationError(t *testing.T, err error, field, reason string) {
	t.Helper()
	if err == nil {
		t.Fatal("err = nil, want validation_failed")
	}
	if !errors.Is(err, errValidationFailed) {
		t.Fatalf("err = %v, want validation_failed", err)
	}
	terr := classify(err)
	if terr.Kind != ErrorKindValidationFailed || terr.Field != field || terr.Reason != reason {
		t.Fatalf("classified error = %#v, want kind=%s field=%s reason=%s", terr, ErrorKindValidationFailed, field, reason)
	}
}
