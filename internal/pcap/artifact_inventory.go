package pcap

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"cute-pcap-mcp/internal/config"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	defaultArtifactInventoryLimit = 10
	maxArtifactInventoryLimit     = 10
	maxArtifactInventoryCursorLen = 2048
	artifactInventoryCursorV1     = 1

	defaultArtifactInventoryScanBudgetEntries = 500
	defaultArtifactInventoryHashBudgetBytes   = int64(32 << 20)

	artifactInventoryScanComplete      = "complete"
	artifactInventoryScanPageLimit     = "page_limit_reached"
	artifactInventoryScanBudgetReached = "scan_budget_reached"

	artifactInventoryHashComputed = "computed"
	artifactInventoryHashOmitted  = "omitted"

	artifactInventoryOmitHashBudgetReached = "hash_budget_reached"
	artifactInventoryOmitHashUnavailable   = "hash_unavailable"

	artifactInventorySkipInaccessible = "artifact_inaccessible"
)

var (
	errArtifactInventoryStop              = errors.New("artifact inventory stopped")
	errArtifactInventoryHashBudgetReached = errors.New(artifactInventoryOmitHashBudgetReached)
)

type listArtifactsInput struct {
	Limit  int    `json:"limit,omitempty" jsonschema:"maximum artifacts to return; default 10, hard maximum 10"`
	Cursor string `json:"cursor,omitempty" jsonschema:"opaque cursor from a prior truncated list_pcap_artifacts response; cursors are versioned and not secret"`
}

type listArtifactsOutput struct {
	Artifacts         []artifactInventoryEntry `json:"artifacts"`
	Count             int                      `json:"count"`
	Limit             int                      `json:"limit"`
	Truncated         bool                     `json:"truncated"`
	NextCursor        string                   `json:"next_cursor,omitempty"`
	ScanStatus        string                   `json:"scan_status"`
	ScanBudgetEntries int                      `json:"scan_budget_entries"`
	HashBudgetBytes   int64                    `json:"hash_budget_bytes"`
	HashBytesUsed     int64                    `json:"hash_bytes_used"`
	Skips             []artifactInventorySkip  `json:"skips,omitempty"`
	Error             *toolError               `json:"error,omitempty"`
}

type artifactInventoryEntry struct {
	Path           string   `json:"path"`
	Basename       string   `json:"basename"`
	SizeBytes      int64    `json:"size_bytes"`
	SHA256         string   `json:"sha256,omitempty"`
	HashStatus     string   `json:"hash_status"`
	OmittedReasons []string `json:"omitted_reasons,omitempty"`
	ModifiedAt     string   `json:"modified_at"`
	ContentType    string   `json:"content_type"`
}

type artifactInventorySkip struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

type artifactInventoryCursor struct {
	Version      int    `json:"v"`
	RootIndex    int    `json:"root_index"`
	RelativePath string `json:"relative_path"`
}

type artifactInventoryOptions struct {
	MaxScanEntries  int
	HashBudgetBytes int64
}

type artifactInventoryKey struct {
	RootIndex    int
	RelativePath string
}

func (s *serverState) listArtifactsHandler(toolName string) func(ctx context.Context, _ *mcp.CallToolRequest, input listArtifactsInput) (*mcp.CallToolResult, listArtifactsOutput, error) {
	return func(ctx context.Context, _ *mcp.CallToolRequest, input listArtifactsInput) (*mcp.CallToolResult, listArtifactsOutput, error) {
		s.logger.InfoContext(ctx, "tool.start", slog.String("tool", toolName))
		out, err := listPCAPArtifacts(ctx, s.cfg, input)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, listArtifactsOutput{}, err
			}
			terr := classify(err)
			s.logger.InfoContext(ctx, "tool.result", slog.String("tool", toolName), slog.String("outcome", "error"), slog.String("error_kind", terr.Kind))
			return &mcp.CallToolResult{IsError: true}, listArtifactsOutput{Error: &terr}, nil
		}
		s.logger.InfoContext(ctx, "tool.result",
			slog.String("tool", toolName),
			slog.String("outcome", "success"),
			slog.Int("count", out.Count),
			slog.Bool("truncated", out.Truncated),
			slog.String("scan_status", out.ScanStatus),
		)
		return nil, out, nil
	}
}

func listPCAPArtifacts(ctx context.Context, cfg config.Config, input listArtifactsInput) (listArtifactsOutput, error) {
	return listPCAPArtifactsWithOptions(ctx, cfg, input, artifactInventoryOptions{
		MaxScanEntries:  defaultArtifactInventoryScanBudgetEntries,
		HashBudgetBytes: defaultArtifactInventoryHashBudgetBytes,
	})
}

func listPCAPArtifactsWithOptions(ctx context.Context, cfg config.Config, input listArtifactsInput, opts artifactInventoryOptions) (listArtifactsOutput, error) {
	if opts.MaxScanEntries <= 0 {
		opts.MaxScanEntries = defaultArtifactInventoryScanBudgetEntries
	}
	if opts.HashBudgetBytes < 0 {
		opts.HashBudgetBytes = defaultArtifactInventoryHashBudgetBytes
	}

	limit, err := normalizeArtifactInventoryLimit(input.Limit)
	if err != nil {
		return listArtifactsOutput{}, err
	}
	cursor, err := decodeArtifactInventoryCursor(input.Cursor, len(cfg.AllowedArtifactDirs))
	if err != nil {
		return listArtifactsOutput{}, err
	}

	remainingHashBudget := opts.HashBudgetBytes
	skipCounts := map[string]int{}
	out := listArtifactsOutput{
		Artifacts:         []artifactInventoryEntry{},
		Limit:             limit,
		ScanStatus:        artifactInventoryScanComplete,
		ScanBudgetEntries: opts.MaxScanEntries,
		HashBudgetBytes:   opts.HashBudgetBytes,
	}

	scanned := 0
	var lastScanned *artifactInventoryKey

	for rootIndex, root := range cfg.AllowedArtifactDirs {
		if cursor != nil && rootIndex < cursor.RootIndex {
			continue
		}
		walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, entryErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}

			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				addArtifactInventorySkip(skipCounts, artifactInventorySkipInaccessible)
				return stopArtifactInventoryIfNeeded(&out, scanned, opts.MaxScanEntries, lastScanned)
			}
			rel = filepath.Clean(rel)
			if rel == "." {
				return nil
			}
			relSlash := filepath.ToSlash(rel)

			skip, cursorAncestor := skipArtifactInventoryCursorEntry(rootIndex, relSlash, d != nil && d.IsDir(), cursor)
			if skip {
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if cursorAncestor {
				return nil
			}

			scanned++
			lastScanned = &artifactInventoryKey{RootIndex: rootIndex, RelativePath: relSlash}

			if entryErr != nil {
				addArtifactInventorySkip(skipCounts, artifactInventorySkipInaccessible)
				return stopArtifactInventoryIfNeeded(&out, scanned, opts.MaxScanEntries, lastScanned)
			}
			if d == nil {
				addArtifactInventorySkip(skipCounts, artifactInventorySkipInaccessible)
				return stopArtifactInventoryIfNeeded(&out, scanned, opts.MaxScanEntries, lastScanned)
			}

			if d.IsDir() {
				if isPCAPArtifactName(relSlash) {
					addArtifactInventorySkip(skipCounts, ErrorKindArtifactNotRegularFile)
				}
				return stopArtifactInventoryIfNeeded(&out, scanned, opts.MaxScanEntries, lastScanned)
			}

			if !isPCAPArtifactName(relSlash) {
				return stopArtifactInventoryIfNeeded(&out, scanned, opts.MaxScanEntries, lastScanned)
			}

			contentType := artifactInventoryContentType(relSlash)
			entry, err := artifactInventoryEntryForPath(ctx, path, cfg, contentType, &remainingHashBudget)
			if err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return err
				}
				addArtifactInventorySkip(skipCounts, artifactInventorySkipReason(err))
				return stopArtifactInventoryIfNeeded(&out, scanned, opts.MaxScanEntries, lastScanned)
			}
			out.Artifacts = append(out.Artifacts, entry)

			if scanned >= opts.MaxScanEntries {
				out.Truncated = true
				out.ScanStatus = artifactInventoryScanBudgetReached
				return errArtifactInventoryStop
			}
			if len(out.Artifacts) >= limit {
				out.Truncated = true
				out.ScanStatus = artifactInventoryScanPageLimit
				return errArtifactInventoryStop
			}
			return nil
		})
		if errors.Is(walkErr, errArtifactInventoryStop) {
			break
		}
		if walkErr != nil {
			return listArtifactsOutput{}, walkErr
		}
	}

	out.Count = len(out.Artifacts)
	out.HashBytesUsed = opts.HashBudgetBytes - remainingHashBudget
	out.Skips = sortedArtifactInventorySkips(skipCounts)
	if out.Truncated && lastScanned != nil {
		next, err := encodeArtifactInventoryCursor(artifactInventoryCursor{
			Version:      artifactInventoryCursorV1,
			RootIndex:    lastScanned.RootIndex,
			RelativePath: lastScanned.RelativePath,
		})
		if err != nil {
			return listArtifactsOutput{}, err
		}
		out.NextCursor = next
	}
	return out, nil
}

func normalizeArtifactInventoryLimit(limit int) (int, error) {
	if limit == 0 {
		return defaultArtifactInventoryLimit, nil
	}
	if limit < 0 || limit > maxArtifactInventoryLimit {
		return 0, validationError("limit", ValidationReasonOutOfRange,
			fmt.Sprintf("limit must be between 1 and %d", maxArtifactInventoryLimit))
	}
	return limit, nil
}

func skipArtifactInventoryCursorEntry(rootIndex int, relSlash string, isDir bool, cursor *artifactInventoryCursor) (bool, bool) {
	if cursor == nil || rootIndex != cursor.RootIndex {
		return false, false
	}
	cursorRel := cursor.RelativePath
	if relSlash == cursorRel && isDir {
		return false, true
	}
	if relSlash <= cursorRel {
		if isDir && strings.HasPrefix(cursorRel, relSlash+"/") {
			return false, true
		}
		return true, false
	}
	return false, false
}

func stopArtifactInventoryIfNeeded(out *listArtifactsOutput, scanned, maxScanEntries int, lastScanned *artifactInventoryKey) error {
	if scanned >= maxScanEntries && lastScanned != nil {
		out.Truncated = true
		out.ScanStatus = artifactInventoryScanBudgetReached
		return errArtifactInventoryStop
	}
	return nil
}

func artifactInventoryEntryForPath(ctx context.Context, path string, cfg config.Config, contentType string, remainingHashBudget *int64) (artifactInventoryEntry, error) {
	resolved, info, err := resolveArtifactFile(path, cfg)
	if err != nil {
		return artifactInventoryEntry{}, err
	}

	entry := artifactInventoryEntry{
		Path:        resolved,
		Basename:    filepath.Base(resolved),
		SizeBytes:   info.Size(),
		HashStatus:  artifactInventoryHashComputed,
		ModifiedAt:  info.ModTime().UTC().Format(time.RFC3339),
		ContentType: contentType,
	}

	if info.Size() > *remainingHashBudget {
		entry.HashStatus = artifactInventoryHashOmitted
		entry.OmittedReasons = []string{artifactInventoryOmitHashBudgetReached}
		return entry, nil
	}

	hash, bytesRead, err := hashFileWithContext(ctx, resolved, *remainingHashBudget)
	if bytesRead > 0 {
		*remainingHashBudget -= bytesRead
		if *remainingHashBudget < 0 {
			*remainingHashBudget = 0
		}
	}
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return artifactInventoryEntry{}, err
		}
		entry.HashStatus = artifactInventoryHashOmitted
		if errors.Is(err, errArtifactInventoryHashBudgetReached) {
			entry.OmittedReasons = []string{artifactInventoryOmitHashBudgetReached}
		} else {
			entry.OmittedReasons = []string{artifactInventoryOmitHashUnavailable}
		}
		return entry, nil
	}

	entry.SHA256 = hash
	return entry, nil
}

func hashFileWithContext(ctx context.Context, path string, maxBytes int64) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()

	hash := sha256.New()
	buf := make([]byte, 32*1024)
	var bytesRead int64
	for {
		if err := ctx.Err(); err != nil {
			return "", bytesRead, err
		}
		if bytesRead >= maxBytes {
			one := []byte{0}
			n, readErr := file.Read(one)
			if n > 0 {
				return "", bytesRead, errArtifactInventoryHashBudgetReached
			}
			if readErr == io.EOF {
				return hex.EncodeToString(hash.Sum(nil)), bytesRead, nil
			}
			if readErr != nil {
				return "", bytesRead, readErr
			}
			continue
		}
		readSize := len(buf)
		if remaining := maxBytes - bytesRead; remaining < int64(readSize) {
			readSize = int(remaining)
		}
		n, readErr := file.Read(buf[:readSize])
		if n > 0 {
			bytesRead += int64(n)
			if _, err := hash.Write(buf[:n]); err != nil {
				return "", bytesRead, err
			}
		}
		if readErr == io.EOF {
			return hex.EncodeToString(hash.Sum(nil)), bytesRead, nil
		}
		if readErr != nil {
			return "", bytesRead, readErr
		}
	}
}

func isPCAPArtifactName(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".pcap", ".pcapng":
		return true
	default:
		return false
	}
}

func artifactInventoryContentType(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".pcap":
		return "application/vnd.tcpdump.pcap"
	case ".pcapng":
		return "application/x-pcapng"
	default:
		return "application/octet-stream"
	}
}

func artifactInventorySkipReason(err error) string {
	switch {
	case errors.Is(err, errPathOutsideAllowlist):
		return ErrorKindPathOutsideAllowlist
	case errors.Is(err, errArtifactNotRegular):
		return ErrorKindArtifactNotRegularFile
	case errors.Is(err, errArtifactNotFound):
		return ErrorKindArtifactNotFound
	case errors.Is(err, errPCAPTooLarge):
		return ErrorKindPCAPTooLarge
	default:
		return artifactInventorySkipInaccessible
	}
}

func addArtifactInventorySkip(skipCounts map[string]int, reason string) {
	skipCounts[reason]++
}

func sortedArtifactInventorySkips(skipCounts map[string]int) []artifactInventorySkip {
	if len(skipCounts) == 0 {
		return nil
	}
	reasons := make([]string, 0, len(skipCounts))
	for reason := range skipCounts {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)
	out := make([]artifactInventorySkip, 0, len(reasons))
	for _, reason := range reasons {
		out = append(out, artifactInventorySkip{Reason: reason, Count: skipCounts[reason]})
	}
	return out
}

func encodeArtifactInventoryCursor(cursor artifactInventoryCursor) (string, error) {
	raw, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeArtifactInventoryCursor(token string, rootCount int) (*artifactInventoryCursor, error) {
	if token == "" {
		return nil, nil
	}
	if strings.ContainsRune(token, '\x00') {
		return nil, validationError("cursor", ValidationReasonContainsNUL, "cursor must not contain NUL bytes")
	}
	if len(token) > maxArtifactInventoryCursorLen {
		return nil, validationError("cursor", ValidationReasonTooLong,
			fmt.Sprintf("cursor must be %d bytes or less", maxArtifactInventoryCursorLen))
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, validationError("cursor", ValidationReasonInvalidFormat, "cursor is not a valid list_pcap_artifacts cursor")
	}
	var cursor artifactInventoryCursor
	if err := json.Unmarshal(raw, &cursor); err != nil {
		return nil, validationError("cursor", ValidationReasonInvalidFormat, "cursor is not a valid list_pcap_artifacts cursor")
	}
	if cursor.Version != artifactInventoryCursorV1 {
		return nil, validationError("cursor", ValidationReasonInvalidFormat, "cursor version is not supported")
	}
	if cursor.RootIndex < 0 || cursor.RootIndex >= rootCount {
		return nil, validationError("cursor", ValidationReasonInvalidFormat, "cursor root_index is outside the configured allowlist")
	}
	if !validArtifactInventoryRelativePath(cursor.RelativePath) {
		return nil, validationError("cursor", ValidationReasonInvalidFormat, "cursor relative_path is invalid")
	}
	return &cursor, nil
}

func validArtifactInventoryRelativePath(path string) bool {
	if path == "" || strings.ContainsRune(path, '\x00') || strings.Contains(path, "\\") {
		return false
	}
	rel := filepath.FromSlash(path)
	if filepath.IsAbs(rel) {
		return false
	}
	clean := filepath.Clean(rel)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return false
	}
	return filepath.ToSlash(clean) == path
}
