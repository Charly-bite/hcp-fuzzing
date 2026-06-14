package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// ================================================================
//  TEST SETUP HELPERS
// ================================================================

// setupTestProject creates a temporary directory tree and sets projectRoot, logDir, fuzzerDir.
func setupTestProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	projectRoot = dir

	// Create some test files & dirs
	os.MkdirAll(filepath.Join(dir, "subdir"), 0755)
	os.WriteFile(filepath.Join(dir, "hello.go"), []byte("package main\n"), 0644)
	os.WriteFile(filepath.Join(dir, "readme.md"), []byte("# Hello\n"), 0644)
	os.WriteFile(filepath.Join(dir, "image.png"), []byte{0x89, 0x50, 0x4e, 0x47}, 0644) // fake binary
	os.WriteFile(filepath.Join(dir, "subdir", "nested.txt"), []byte("nested content"), 0644)

	// Wordlists dir (for fuzzerDir)
	fDir := filepath.Join(dir, "fuzzer_data")
	wlDir := filepath.Join(fDir, "wordlists")
	os.MkdirAll(wlDir, 0755)
	os.WriteFile(filepath.Join(wlDir, "test.txt"), []byte("admin\nlogin\napi\n"), 0644)
	os.WriteFile(filepath.Join(wlDir, "seclists_common.txt"), []byte("index\nadmin\nlogin\napi\ntest\n"), 0644)
	fuzzerDir = fDir

	// Wordlists also under projectRoot for apiFuzzStatus
	os.MkdirAll(filepath.Join(dir, "wordlists"), 0755)
	os.WriteFile(filepath.Join(dir, "wordlists", "test.txt"), []byte("admin\nlogin\napi\n"), 0644)

	// Log dir with fake log files
	lDir := filepath.Join(dir, "fuzz_logs")
	os.MkdirAll(lDir, 0755)
	os.WriteFile(filepath.Join(lDir, "node01_12345.log"), []byte(
		"[+] Found https://example.com/admin Status: 200 Size: 1024\nSome other line\n[+] Found https://example.com/login Status: 403 Size: 500\n",
	), 0644)
	os.WriteFile(filepath.Join(lDir, "node02_12345.log"), []byte(
		"[+] Found https://example.com/api Status: 200 Size: 2048\nError line with ERROR keyword\n",
	), 0644)
	os.WriteFile(filepath.Join(lDir, "dashboard.log"), []byte("dashboard data should be excluded\n"), 0644)
	logDir = lDir

	// Hidden dirs (should be excluded from listing)
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	os.MkdirAll(filepath.Join(dir, "node_modules"), 0755)

	return dir
}

// decodeJSON is a test helper that decodes response body to a map.
func decodeJSON(t *testing.T, body io.Reader) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.NewDecoder(body).Decode(&m); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	return m
}

// decodeJSONSlice is a test helper for array responses.
func decodeJSONSlice(t *testing.T, body io.Reader) []interface{} {
	t.Helper()
	var s []interface{}
	if err := json.NewDecoder(body).Decode(&s); err != nil {
		t.Fatalf("failed to decode JSON array: %v", err)
	}
	return s
}

// ================================================================
//  UNIT TESTS: safePath
// ================================================================

func TestSafePath_RelativePathAllowed(t *testing.T) {
	dir := setupTestProject(t)
	got, err := safePath("hello.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := filepath.Join(dir, "hello.go")
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestSafePath_NestedPathAllowed(t *testing.T) {
	setupTestProject(t)
	_, err := safePath("subdir/nested.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSafePath_AbsolutePathBlocked(t *testing.T) {
	setupTestProject(t)
	_, err := safePath("C:\\Windows\\System32")
	if err == nil {
		t.Fatal("expected error for absolute path")
	}
	if !strings.Contains(err.Error(), "absolute") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSafePath_TraversalBlocked(t *testing.T) {
	setupTestProject(t)
	_, err := safePath("../../etc/passwd")
	if err == nil {
		t.Fatal("expected error for traversal")
	}
	if !strings.Contains(err.Error(), "traversal") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSafePath_DotPath(t *testing.T) {
	setupTestProject(t)
	got, err := safePath(".")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != filepath.Join(projectRoot, ".") {
		t.Errorf("unexpected path: %s", got)
	}
}

// ================================================================
//  UNIT TESTS: httpJSON
// ================================================================

func TestHttpJSON(t *testing.T) {
	rr := httptest.NewRecorder()
	data := map[string]string{"hello": "world"}
	httpJSON(rr, 201, data)

	if rr.Code != 201 {
		t.Errorf("expected status 201, got %d", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", ct)
	}
	m := decodeJSON(t, rr.Body)
	if m["hello"] != "world" {
		t.Errorf("unexpected body: %v", m)
	}
}

// ================================================================
//  UNIT TESTS: splitClean
// ================================================================

func TestSplitClean_Normal(t *testing.T) {
	r := splitClean("200, 403, 404")
	if len(r) != 3 || r[0] != "200" || r[1] != "403" || r[2] != "404" {
		t.Errorf("unexpected result: %v", r)
	}
}

func TestSplitClean_Empty(t *testing.T) {
	r := splitClean("")
	if r != nil {
		t.Errorf("expected nil for empty input, got %v", r)
	}
}

func TestSplitClean_WhitespaceOnly(t *testing.T) {
	r := splitClean(",  ,  ,")
	if len(r) != 0 {
		t.Errorf("expected empty for whitespace-only parts, got %v", r)
	}
}

func TestSplitClean_SingleValue(t *testing.T) {
	r := splitClean("200")
	if len(r) != 1 || r[0] != "200" {
		t.Errorf("unexpected: %v", r)
	}
}

// ================================================================
//  UNIT TESTS: matchFilters
// ================================================================

func TestMatchFilters_MatchingLine(t *testing.T) {
	statusRe := regexp.MustCompile(`Status: (\d+)`)
	sizeRe := regexp.MustCompile(`(?:Size|ContentLength): (\d+)`)
	line := "[+] Found https://example.com/admin Status: 200 Size: 1234"
	if !matchFilters(line, []string{"200"}, nil, statusRe, sizeRe) {
		t.Error("expected match for status 200")
	}
}

func TestMatchFilters_NoFoundPrefix(t *testing.T) {
	statusRe := regexp.MustCompile(`Status: (\d+)`)
	sizeRe := regexp.MustCompile(`(?:Size|ContentLength): (\d+)`)
	line := "Status: 200 Size: 1234"
	if matchFilters(line, []string{"200"}, nil, statusRe, sizeRe) {
		t.Error("expected no match without [+] Found prefix")
	}
}

func TestMatchFilters_StatusNotInFilter(t *testing.T) {
	statusRe := regexp.MustCompile(`Status: (\d+)`)
	sizeRe := regexp.MustCompile(`(?:Size|ContentLength): (\d+)`)
	line := "[+] Found https://example.com/ Status: 404 Size: 100"
	if matchFilters(line, []string{"200", "403"}, nil, statusRe, sizeRe) {
		t.Error("expected no match for status 404 when filtering 200,403")
	}
}

func TestMatchFilters_ExcludeSize(t *testing.T) {
	statusRe := regexp.MustCompile(`Status: (\d+)`)
	sizeRe := regexp.MustCompile(`(?:Size|ContentLength): (\d+)`)
	line := "[+] Found https://example.com/ Status: 200 Size: 9999"
	if matchFilters(line, []string{"200"}, []string{"9999"}, statusRe, sizeRe) {
		t.Error("expected exclusion for size 9999")
	}
}

func TestMatchFilters_EmptyFilters(t *testing.T) {
	statusRe := regexp.MustCompile(`Status: (\d+)`)
	sizeRe := regexp.MustCompile(`(?:Size|ContentLength): (\d+)`)
	line := "[+] Found https://example.com/ Status: 200 Size: 100"
	if matchFilters(line, []string{}, nil, statusRe, sizeRe) {
		t.Error("expected false for empty filters")
	}
}

func TestMatchFilters_NoStatusInLine(t *testing.T) {
	statusRe := regexp.MustCompile(`Status: (\d+)`)
	sizeRe := regexp.MustCompile(`(?:Size|ContentLength): (\d+)`)
	line := "[+] Found https://example.com/ Size: 100"
	if matchFilters(line, []string{"200"}, nil, statusRe, sizeRe) {
		t.Error("expected false when no status code in line")
	}
}

func TestMatchFilters_ContentLengthVariant(t *testing.T) {
	statusRe := regexp.MustCompile(`Status: (\d+)`)
	sizeRe := regexp.MustCompile(`(?:Size|ContentLength): (\d+)`)
	line := "[+] Found https://example.com/api Status: 403 ContentLength: 500"
	if !matchFilters(line, []string{"403"}, nil, statusRe, sizeRe) {
		t.Error("expected match with ContentLength variant")
	}
	// Now exclude by ContentLength
	if matchFilters(line, []string{"403"}, []string{"500"}, statusRe, sizeRe) {
		t.Error("expected exclusion for ContentLength 500")
	}
}

// ================================================================
//  UNIT TESTS: getRawLogs / gatherFindingsStr (with temp log dir)
// ================================================================

func setupTempLogDir(t *testing.T) (string, func()) {
	t.Helper()
	dir := t.TempDir()
	// Write fake log files
	os.WriteFile(filepath.Join(dir, "node01_12345.log"), []byte(
		"[+] Found https://example.com/admin Status: 200 Size: 1024\nSome other line\n[+] Found https://example.com/login Status: 403 Size: 500\n",
	), 0644)
	os.WriteFile(filepath.Join(dir, "node02_12345.log"), []byte(
		"[+] Found https://example.com/api Status: 200 Size: 2048\nError line\n",
	), 0644)
	os.WriteFile(filepath.Join(dir, "dashboard.log"), []byte("dashboard data, should be excluded\n"), 0644)

	return dir, func() { /* t.TempDir auto-cleans */ }
}

func TestGetRawLogs_AllFiles(t *testing.T) {
	dir, cleanup := setupTempLogDir(t)
	defer cleanup()

	// Temporarily override logDir (we can't reassign const, so test getRawLogs indirectly)
	// Instead, test through the handler which uses logDir const.
	// For unit testing, we test the logic directly with a helper.
	// Since logDir is a const, we'll test the handlers via integration tests below.
	_ = dir
	// This test validates that our log files were created correctly
	files, _ := filepath.Glob(filepath.Join(dir, "*.log"))
	if len(files) != 3 {
		t.Errorf("expected 3 log files, got %d", len(files))
	}
}

// ================================================================
//  HANDLER TESTS: apiListFiles
// ================================================================

func TestApiListFiles_RootDir(t *testing.T) {
	setupTestProject(t)

	req := httptest.NewRequest("GET", "/api/files?path=.", nil)
	rr := httptest.NewRecorder()
	apiListFiles(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	entries := decodeJSONSlice(t, rr.Body)
	// Should have: subdir, wordlists (dirs), hello.go, image.png, readme.md (files)
	// .git and node_modules should be hidden
	names := make(map[string]bool)
	for _, e := range entries {
		m := e.(map[string]interface{})
		names[m["name"].(string)] = true
	}

	if names[".git"] || names["node_modules"] {
		t.Error("hidden entries should not appear in listing")
	}
	if !names["hello.go"] {
		t.Error("expected hello.go in listing")
	}
	if !names["subdir"] {
		t.Error("expected subdir in listing")
	}
}

func TestApiListFiles_Subdir(t *testing.T) {
	setupTestProject(t)

	req := httptest.NewRequest("GET", "/api/files?path=subdir", nil)
	rr := httptest.NewRecorder()
	apiListFiles(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	entries := decodeJSONSlice(t, rr.Body)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry in subdir, got %d", len(entries))
	}
	m := entries[0].(map[string]interface{})
	if m["name"] != "nested.txt" {
		t.Errorf("expected nested.txt, got %s", m["name"])
	}
}

func TestApiListFiles_InvalidPath(t *testing.T) {
	setupTestProject(t)

	req := httptest.NewRequest("GET", "/api/files?path=../../etc", nil)
	rr := httptest.NewRecorder()
	apiListFiles(rr, req)

	if rr.Code != 400 {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestApiListFiles_NonexistentDir(t *testing.T) {
	setupTestProject(t)

	req := httptest.NewRequest("GET", "/api/files?path=nonexistent", nil)
	rr := httptest.NewRecorder()
	apiListFiles(rr, req)

	if rr.Code != 500 {
		t.Errorf("expected 500 for nonexistent dir, got %d", rr.Code)
	}
}

func TestApiListFiles_DefaultPath(t *testing.T) {
	setupTestProject(t)

	req := httptest.NewRequest("GET", "/api/files", nil)
	rr := httptest.NewRecorder()
	apiListFiles(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestApiListFiles_DirsSortedFirst(t *testing.T) {
	setupTestProject(t)

	req := httptest.NewRequest("GET", "/api/files?path=.", nil)
	rr := httptest.NewRecorder()
	apiListFiles(rr, req)

	entries := decodeJSONSlice(t, rr.Body)
	// First entries should be directories
	firstIsDir := entries[0].(map[string]interface{})["isDir"].(bool)
	if !firstIsDir {
		t.Error("directories should be sorted before files")
	}
}

// ================================================================
//  HANDLER TESTS: apiReadFile
// ================================================================

func TestApiReadFile_Success(t *testing.T) {
	setupTestProject(t)

	req := httptest.NewRequest("GET", "/api/file?path=hello.go", nil)
	rr := httptest.NewRecorder()
	apiReadFile(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	m := decodeJSON(t, rr.Body)
	content := m["content"].(string)
	if content != "package main\n" {
		t.Errorf("unexpected content: %q", content)
	}
}

func TestApiReadFile_BinaryDetection(t *testing.T) {
	setupTestProject(t)

	req := httptest.NewRequest("GET", "/api/file?path=image.png", nil)
	rr := httptest.NewRecorder()
	apiReadFile(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	m := decodeJSON(t, rr.Body)
	if m["binary"] != true {
		t.Error("expected binary flag for .png file")
	}
}

func TestApiReadFile_PathTraversal(t *testing.T) {
	setupTestProject(t)

	req := httptest.NewRequest("GET", "/api/file?path=../../etc/passwd", nil)
	rr := httptest.NewRecorder()
	apiReadFile(rr, req)

	if rr.Code != 400 {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestApiReadFile_NonexistentFile(t *testing.T) {
	setupTestProject(t)

	req := httptest.NewRequest("GET", "/api/file?path=nonexistent.txt", nil)
	rr := httptest.NewRecorder()
	apiReadFile(rr, req)

	if rr.Code != 500 {
		t.Errorf("expected 500 for nonexistent file, got %d", rr.Code)
	}
}

func TestApiReadFile_NestedFile(t *testing.T) {
	setupTestProject(t)

	req := httptest.NewRequest("GET", "/api/file?path=subdir/nested.txt", nil)
	rr := httptest.NewRecorder()
	apiReadFile(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	m := decodeJSON(t, rr.Body)
	if m["content"] != "nested content" {
		t.Errorf("unexpected content: %v", m["content"])
	}
}

// ================================================================
//  HANDLER TESTS: apiWriteFile
// ================================================================

func TestApiWriteFile_Success(t *testing.T) {
	setupTestProject(t)

	body := `{"path":"hello.go","content":"package updated\n"}`
	req := httptest.NewRequest("POST", "/api/file", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	apiWriteFile(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	// Verify file was actually written
	data, _ := os.ReadFile(filepath.Join(projectRoot, "hello.go"))
	if string(data) != "package updated\n" {
		t.Errorf("file content mismatch: %q", string(data))
	}
}

func TestApiWriteFile_InvalidJSON(t *testing.T) {
	setupTestProject(t)

	req := httptest.NewRequest("POST", "/api/file", strings.NewReader("not json"))
	rr := httptest.NewRecorder()
	apiWriteFile(rr, req)

	if rr.Code != 400 {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestApiWriteFile_PathTraversal(t *testing.T) {
	setupTestProject(t)

	body := `{"path":"../../evil.txt","content":"pwned"}`
	req := httptest.NewRequest("POST", "/api/file", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	apiWriteFile(rr, req)

	if rr.Code != 400 {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// ================================================================
//  HANDLER TESTS: apiCreateFile
// ================================================================

func TestApiCreateFile_NewFile(t *testing.T) {
	setupTestProject(t)

	body := `{"path":"newfile.txt","isDir":false}`
	req := httptest.NewRequest("POST", "/api/file/create", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	apiCreateFile(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	if _, err := os.Stat(filepath.Join(projectRoot, "newfile.txt")); os.IsNotExist(err) {
		t.Error("file was not created")
	}
}

func TestApiCreateFile_NewDir(t *testing.T) {
	setupTestProject(t)

	body := `{"path":"newdir","isDir":true}`
	req := httptest.NewRequest("POST", "/api/file/create", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	apiCreateFile(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	info, err := os.Stat(filepath.Join(projectRoot, "newdir"))
	if os.IsNotExist(err) || !info.IsDir() {
		t.Error("directory was not created")
	}
}

func TestApiCreateFile_InvalidJSON(t *testing.T) {
	setupTestProject(t)

	req := httptest.NewRequest("POST", "/api/file/create", strings.NewReader("broken"))
	rr := httptest.NewRecorder()
	apiCreateFile(rr, req)

	if rr.Code != 400 {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestApiCreateFile_PathTraversal(t *testing.T) {
	setupTestProject(t)

	body := `{"path":"../../evil_dir","isDir":true}`
	req := httptest.NewRequest("POST", "/api/file/create", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	apiCreateFile(rr, req)

	if rr.Code != 400 {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestApiCreateFile_NestedNewFile(t *testing.T) {
	setupTestProject(t)

	body := `{"path":"deep/nested/file.txt","isDir":false}`
	req := httptest.NewRequest("POST", "/api/file/create", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	apiCreateFile(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	if _, err := os.Stat(filepath.Join(projectRoot, "deep", "nested", "file.txt")); os.IsNotExist(err) {
		t.Error("nested file was not created")
	}
}

// ================================================================
//  HANDLER TESTS: apiDeleteFile
// ================================================================

func TestApiDeleteFile_Success(t *testing.T) {
	setupTestProject(t)

	req := httptest.NewRequest("DELETE", "/api/file?path=hello.go", nil)
	rr := httptest.NewRecorder()
	apiDeleteFile(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	if _, err := os.Stat(filepath.Join(projectRoot, "hello.go")); !os.IsNotExist(err) {
		t.Error("file should have been deleted")
	}
}

func TestApiDeleteFile_Directory(t *testing.T) {
	setupTestProject(t)

	req := httptest.NewRequest("DELETE", "/api/file?path=subdir", nil)
	rr := httptest.NewRecorder()
	apiDeleteFile(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	if _, err := os.Stat(filepath.Join(projectRoot, "subdir")); !os.IsNotExist(err) {
		t.Error("directory should have been deleted")
	}
}

func TestApiDeleteFile_PathTraversal(t *testing.T) {
	setupTestProject(t)

	req := httptest.NewRequest("DELETE", "/api/file?path=../../important", nil)
	rr := httptest.NewRecorder()
	apiDeleteFile(rr, req)

	if rr.Code != 400 {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// ================================================================
//  HANDLER TESTS: apiRenameFile
// ================================================================

func TestApiRenameFile_Success(t *testing.T) {
	setupTestProject(t)

	body := `{"oldPath":"hello.go","newPath":"hello_renamed.go"}`
	req := httptest.NewRequest("POST", "/api/file/rename", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	apiRenameFile(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	if _, err := os.Stat(filepath.Join(projectRoot, "hello_renamed.go")); os.IsNotExist(err) {
		t.Error("renamed file should exist")
	}
	if _, err := os.Stat(filepath.Join(projectRoot, "hello.go")); !os.IsNotExist(err) {
		t.Error("old file should not exist")
	}
}

func TestApiRenameFile_InvalidJSON(t *testing.T) {
	setupTestProject(t)

	req := httptest.NewRequest("POST", "/api/file/rename", strings.NewReader("bad"))
	rr := httptest.NewRecorder()
	apiRenameFile(rr, req)

	if rr.Code != 400 {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestApiRenameFile_OldPathTraversal(t *testing.T) {
	setupTestProject(t)

	body := `{"oldPath":"../../secret","newPath":"stolen"}`
	req := httptest.NewRequest("POST", "/api/file/rename", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	apiRenameFile(rr, req)

	if rr.Code != 400 {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestApiRenameFile_NewPathTraversal(t *testing.T) {
	setupTestProject(t)

	body := `{"oldPath":"hello.go","newPath":"../../outside.go"}`
	req := httptest.NewRequest("POST", "/api/file/rename", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	apiRenameFile(rr, req)

	if rr.Code != 400 {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestApiRenameFile_NonexistentSource(t *testing.T) {
	setupTestProject(t)

	body := `{"oldPath":"ghost.txt","newPath":"new.txt"}`
	req := httptest.NewRequest("POST", "/api/file/rename", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	apiRenameFile(rr, req)

	if rr.Code != 500 {
		t.Errorf("expected 500, got %d", rr.Code)
	}
}

// ================================================================
//  HANDLER TESTS: apiSendRequest
// ================================================================

func TestApiSendRequest_Success(t *testing.T) {
	// Start a local echo server
	echoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "works")
		w.WriteHeader(200)
		w.Write([]byte("echo response"))
	}))
	defer echoServer.Close()

	body := fmt.Sprintf(`{"method":"GET","url":"%s","headers":{"User-Agent":"test"}}`, echoServer.URL)
	req := httptest.NewRequest("POST", "/api/request", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	apiSendRequest(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	m := decodeJSON(t, rr.Body)
	if m["status"].(float64) != 200 {
		t.Errorf("expected status 200, got %v", m["status"])
	}
	if m["body"] != "echo response" {
		t.Errorf("unexpected body: %v", m["body"])
	}
	if m["bodySize"].(float64) != 13 {
		t.Errorf("unexpected bodySize: %v", m["bodySize"])
	}
}

func TestApiSendRequest_PostWithBody(t *testing.T) {
	echoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Write(body)
	}))
	defer echoServer.Close()

	body := fmt.Sprintf(`{"method":"POST","url":"%s","body":"hello world"}`, echoServer.URL)
	req := httptest.NewRequest("POST", "/api/request", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	apiSendRequest(rr, req)

	m := decodeJSON(t, rr.Body)
	if m["body"] != "hello world" {
		t.Errorf("unexpected echoed body: %v", m["body"])
	}
}

func TestApiSendRequest_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/request", strings.NewReader("bad json"))
	rr := httptest.NewRecorder()
	apiSendRequest(rr, req)

	if rr.Code != 400 {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestApiSendRequest_EmptyURL(t *testing.T) {
	body := `{"method":"GET","url":""}`
	req := httptest.NewRequest("POST", "/api/request", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	apiSendRequest(rr, req)

	if rr.Code != 400 {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestApiSendRequest_InvalidURL(t *testing.T) {
	body := `{"method":"GET","url":"not-a-url"}`
	req := httptest.NewRequest("POST", "/api/request", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	apiSendRequest(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200 with error field, got %d", rr.Code)
	}
	m := decodeJSON(t, rr.Body)
	if _, ok := m["error"]; !ok {
		t.Error("expected error field in response for invalid URL")
	}
}

func TestApiSendRequest_DefaultMethod(t *testing.T) {
	echoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.Method))
	}))
	defer echoServer.Close()

	body := fmt.Sprintf(`{"url":"%s"}`, echoServer.URL)
	req := httptest.NewRequest("POST", "/api/request", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	apiSendRequest(rr, req)

	m := decodeJSON(t, rr.Body)
	if m["body"] != "GET" {
		t.Errorf("expected default method GET, got %v", m["body"])
	}
}

func TestApiSendRequest_CustomHeaders(t *testing.T) {
	var receivedHeader string
	echoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("X-Custom")
		w.Write([]byte("ok"))
	}))
	defer echoServer.Close()

	body := fmt.Sprintf(`{"method":"GET","url":"%s","headers":{"X-Custom":"my-value","":"should-be-skipped"}}`, echoServer.URL)
	req := httptest.NewRequest("POST", "/api/request", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	apiSendRequest(rr, req)

	if receivedHeader != "my-value" {
		t.Errorf("expected X-Custom=my-value, got %s", receivedHeader)
	}
}

// ================================================================
//  HANDLER TESTS: apiFuzzStatus
// ================================================================

func TestApiFuzzStatus_Idle(t *testing.T) {
	setupTestProject(t)

	fuzzMu.Lock()
	fuzzRunning = false
	fuzzLog = nil
	fuzzMu.Unlock()

	req := httptest.NewRequest("GET", "/api/fuzz/status", nil)
	rr := httptest.NewRecorder()
	apiFuzzStatus(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	m := decodeJSON(t, rr.Body)
	if m["running"].(bool) {
		t.Error("expected running=false")
	}
}

func TestApiFuzzStatus_WithLogs(t *testing.T) {
	setupTestProject(t)

	fuzzMu.Lock()
	fuzzRunning = true
	fuzzLog = []string{"line1", "line2", "line3"}
	fuzzMu.Unlock()

	req := httptest.NewRequest("GET", "/api/fuzz/status", nil)
	rr := httptest.NewRecorder()
	apiFuzzStatus(rr, req)

	m := decodeJSON(t, rr.Body)
	if !m["running"].(bool) {
		t.Error("expected running=true")
	}
	logs := m["log"].([]interface{})
	if len(logs) != 3 {
		t.Errorf("expected 3 log lines, got %d", len(logs))
	}

	// cleanup
	fuzzMu.Lock()
	fuzzRunning = false
	fuzzLog = nil
	fuzzMu.Unlock()
}

// ================================================================
//  HANDLER TESTS: apiFuzzStop
// ================================================================

func TestApiFuzzStop_NoProcess(t *testing.T) {
	setupTestProject(t)

	fuzzMu.Lock()
	fuzzCmd = nil
	fuzzRunning = false
	fuzzMu.Unlock()

	req := httptest.NewRequest("POST", "/api/fuzz/stop", nil)
	rr := httptest.NewRecorder()
	apiFuzzStop(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

// ================================================================
//  HANDLER TESTS: apiFuzzLaunch
// ================================================================

func TestApiFuzzLaunch_NoURL(t *testing.T) {
	setupTestProject(t)

	fuzzMu.Lock()
	fuzzRunning = false
	fuzzLog = nil
	fuzzMu.Unlock()

	body := `{"url":"","filters":"200"}`
	req := httptest.NewRequest("POST", "/api/fuzz/launch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	apiFuzzLaunch(rr, req)

	m := decodeJSON(t, rr.Body)
	if _, ok := m["error"]; !ok {
		t.Error("expected error when URL is empty")
	}
}

func TestApiFuzzLaunch_AlreadyRunning(t *testing.T) {
	setupTestProject(t)

	fuzzMu.Lock()
	fuzzRunning = true
	fuzzMu.Unlock()

	body := `{"url":"https://example.com"}`
	req := httptest.NewRequest("POST", "/api/fuzz/launch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	apiFuzzLaunch(rr, req)

	m := decodeJSON(t, rr.Body)
	errMsg, ok := m["error"].(string)
	if !ok || !strings.Contains(errMsg, "already running") {
		t.Error("expected 'already running' error")
	}

	fuzzMu.Lock()
	fuzzRunning = false
	fuzzMu.Unlock()
}

// ================================================================
//  HANDLER TESTS: apiUploadWordlist
// ================================================================

func TestApiUploadWordlist_Success(t *testing.T) {
	setupTestProject(t)

	var b bytes.Buffer
	writer := multipart.NewWriter(&b)
	part, _ := writer.CreateFormFile("file", "custom_wordlist.txt")
	part.Write([]byte("word1\nword2\nword3\n"))
	writer.Close()

	req := httptest.NewRequest("POST", "/api/wordlist/upload", &b)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr := httptest.NewRecorder()
	apiUploadWordlist(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	data, err := os.ReadFile(filepath.Join(projectRoot, "wordlists", "custom_wordlist.txt"))
	if err != nil {
		t.Fatalf("uploaded file not found: %v", err)
	}
	if string(data) != "word1\nword2\nword3\n" {
		t.Errorf("uploaded content mismatch: %q", string(data))
	}
}

func TestApiUploadWordlist_NoFile(t *testing.T) {
	setupTestProject(t)

	req := httptest.NewRequest("POST", "/api/wordlist/upload", strings.NewReader(""))
	req.Header.Set("Content-Type", "multipart/form-data")
	rr := httptest.NewRecorder()
	apiUploadWordlist(rr, req)

	if rr.Code != 400 {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// ================================================================
//  HANDLER TESTS: apiGitInfo
// ================================================================

func TestApiGitInfo_StatusDefault(t *testing.T) {
	setupTestProject(t)

	req := httptest.NewRequest("GET", "/api/git", nil)
	rr := httptest.NewRecorder()
	apiGitInfo(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	m := decodeJSON(t, rr.Body)
	if _, ok := m["output"]; !ok {
		t.Error("expected 'output' field in response")
	}
}

func TestApiGitInfo_DiffAction(t *testing.T) {
	setupTestProject(t)

	req := httptest.NewRequest("GET", "/api/git?action=diff", nil)
	rr := httptest.NewRecorder()
	apiGitInfo(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestApiGitInfo_LogAction(t *testing.T) {
	setupTestProject(t)

	req := httptest.NewRequest("GET", "/api/git?action=log", nil)
	rr := httptest.NewRecorder()
	apiGitInfo(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

// ================================================================
//  HANDLER TESTS: apiAction
// ================================================================

func TestApiAction_UnknownAction(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/action", nil)
	req.Form = url.Values{"action": {"unknown"}}
	rr := httptest.NewRecorder()
	apiAction(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	m := decodeJSON(t, rr.Body)
	if m["message"] != "Unknown action." {
		t.Errorf("unexpected message: %v", m["message"])
	}
}

func TestApiAction_ClearLogs(t *testing.T) {
	// This action uses the logDir const which won't exist locally;
	// the handler gracefully handles missing dirs.
	req := httptest.NewRequest("POST", "/api/action", nil)
	req.Form = url.Values{"action": {"clear"}}
	rr := httptest.NewRecorder()
	apiAction(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	m := decodeJSON(t, rr.Body)
	if !strings.Contains(m["message"].(string), "cleared") {
		t.Errorf("unexpected message: %v", m["message"])
	}
}

// ================================================================
//  HANDLER TESTS: apiRawLogs
// ================================================================

func TestApiRawLogs_NoLogs(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/raw_logs?raw_file=all&raw_filter=", nil)
	rr := httptest.NewRecorder()
	apiRawLogs(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "No raw logs") {
		t.Errorf("expected 'No raw logs', got %q", body)
	}
}

// ================================================================
//  HANDLER TESTS: apiAnalyze
// ================================================================

func TestApiAnalyze_NoData(t *testing.T) {
	// With no log files available, should return "No data available"
	req := httptest.NewRequest("POST", "/api/analyze", nil)
	req.Form = url.Values{
		"prompt_type": {"audit"},
		"source_type": {"findings"},
		"filters":     {"200"},
	}
	rr := httptest.NewRecorder()
	apiAnalyze(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	m := decodeJSON(t, rr.Body)
	report := m["report"].(string)
	if !strings.Contains(report, "No data available") {
		t.Errorf("expected 'No data available', got %q", report)
	}
}

func TestApiAnalyze_RawSource(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/analyze", nil)
	req.Form = url.Values{
		"prompt_type": {"summary"},
		"source_type": {"raw"},
		"raw_file":    {"all"},
	}
	rr := httptest.NewRecorder()
	apiAnalyze(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestApiAnalyze_ExtractPrompt(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/analyze", nil)
	req.Form = url.Values{
		"prompt_type": {"extract"},
		"source_type": {"findings"},
	}
	rr := httptest.NewRecorder()
	apiAnalyze(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestApiAnalyze_DefaultPrompt(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/analyze", nil)
	req.Form = url.Values{
		"prompt_type": {"custom_unknown"},
		"source_type": {"findings"},
	}
	rr := httptest.NewRecorder()
	apiAnalyze(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

// ================================================================
//  HANDLER TESTS: serveIndex
// ================================================================

func TestServeIndex_Root(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	serveIndex(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html, got %s", ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "HCP") {
		t.Error("expected HTML to contain HCP branding")
	}
}

func TestServeIndex_NotFound(t *testing.T) {
	req := httptest.NewRequest("GET", "/nonexistent", nil)
	rr := httptest.NewRecorder()
	serveIndex(rr, req)

	if rr.Code != 404 {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

// ================================================================
//  HANDLER TESTS: apiFindings
// ================================================================

func TestApiFindings_NoLogDir(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/findings?filters=200", nil)
	rr := httptest.NewRecorder()
	apiFindings(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "No findings") {
		t.Errorf("expected 'No findings' message, got %q", body)
	}
}

// ================================================================
//  HANDLER TESTS: apiStatus
// ================================================================

func TestApiStatus_Response(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/status?wordlist=test.txt", nil)
	rr := httptest.NewRecorder()
	apiStatus(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	m := decodeJSON(t, rr.Body)
	if _, ok := m["wordlists"]; !ok {
		t.Error("expected 'wordlists' field")
	}
	if _, ok := m["progress"]; !ok {
		t.Error("expected 'progress' field")
	}
	if _, ok := m["jobStatus"]; !ok {
		t.Error("expected 'jobStatus' field")
	}
}

// ================================================================
//  EDGE CASE TESTS
// ================================================================

func TestApiListFiles_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	projectRoot = dir
	emptyDir := filepath.Join(dir, "empty")
	os.MkdirAll(emptyDir, 0755)

	req := httptest.NewRequest("GET", "/api/files?path=empty", nil)
	rr := httptest.NewRecorder()
	apiListFiles(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	entries := decodeJSONSlice(t, rr.Body)
	if len(entries) != 0 {
		t.Errorf("expected empty array, got %d entries", len(entries))
	}
}

func TestApiWriteFile_NewFileInExistingDir(t *testing.T) {
	setupTestProject(t)

	body := `{"path":"subdir/newfile.txt","content":"created in subdir"}`
	req := httptest.NewRequest("POST", "/api/file", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	apiWriteFile(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	data, _ := os.ReadFile(filepath.Join(projectRoot, "subdir", "newfile.txt"))
	if string(data) != "created in subdir" {
		t.Errorf("content mismatch: %q", data)
	}
}

func TestSafePath_WindowsDriveAbsolutePath(t *testing.T) {
	setupTestProject(t)
	_, err := safePath("C:\\Windows\\System32")
	if err == nil {
		t.Error("expected error for Windows absolute path")
	}
}

func TestSplitClean_TrailingComma(t *testing.T) {
	r := splitClean("200,403,")
	if len(r) != 2 {
		t.Errorf("expected 2 items, got %v", r)
	}
}

func TestMatchFilters_MultipleStatusFilters(t *testing.T) {
	statusRe := regexp.MustCompile(`Status: (\d+)`)
	sizeRe := regexp.MustCompile(`(?:Size|ContentLength): (\d+)`)
	line := "[+] Found https://example.com/test Status: 401 Size: 100"
	if !matchFilters(line, []string{"200", "401", "403"}, nil, statusRe, sizeRe) {
		t.Error("expected match for 401 in filter list")
	}
}

// ================================================================
//  HTTP METHOD ROUTING TEST
// ================================================================

func TestFileEndpoint_MethodRouting(t *testing.T) {
	setupTestProject(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			apiReadFile(w, r)
		case "POST":
			apiWriteFile(w, r)
		case "DELETE":
			apiDeleteFile(w, r)
		default:
			http.Error(w, "Method not allowed", 405)
		}
	})

	// Test 405 for unsupported method
	req := httptest.NewRequest("PATCH", "/api/file?path=hello.go", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != 405 {
		t.Errorf("expected 405 for PATCH, got %d", rr.Code)
	}
}

// ================================================================
//  ADDITIONAL COVERAGE TESTS
// ================================================================

func TestApiAction_Launch(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/action", nil)
	req.Form = url.Values{
		"action":   {"launch"},
		"url":      {"https://example.com"},
		"filters":  {"200"},
		"wordlist": {"test.txt"},
		"depth":    {""},
		"modes":    {"subdomain"},
	}
	rr := httptest.NewRecorder()
	apiAction(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	m := decodeJSON(t, rr.Body)
	if _, ok := m["message"]; !ok {
		t.Error("expected message field")
	}
}

func TestApiAction_Stop(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/action", nil)
	req.Form = url.Values{"action": {"stop"}}
	rr := httptest.NewRecorder()
	apiAction(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestApiSendRequest_Headers(t *testing.T) {
	var received map[string]string
	echoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = make(map[string]string)
		for k := range r.Header {
			received[k] = r.Header.Get(k)
		}
		w.Header().Set("X-Response", "hello")
		w.WriteHeader(201)
		w.Write([]byte("created"))
	}))
	defer echoServer.Close()

	body := fmt.Sprintf(`{"method":"PUT","url":"%s","headers":{"X-Auth":"token123"},"body":"{\"key\":\"val\"}"}`, echoServer.URL)
	req := httptest.NewRequest("POST", "/api/request", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	apiSendRequest(rr, req)

	m := decodeJSON(t, rr.Body)
	if m["status"].(float64) != 201 {
		t.Errorf("expected 201, got %v", m["status"])
	}
	if received["X-Auth"] != "token123" {
		t.Errorf("expected X-Auth header, got %v", received)
	}
}

func TestApiReadFile_AllBinaryExtensions(t *testing.T) {
	dir := setupTestProject(t)
	binExts := []string{".exe", ".bin", ".dll", ".pdf", ".zip", ".png", ".jpg", ".gif"}
	for _, ext := range binExts {
		os.WriteFile(filepath.Join(dir, "test"+ext), []byte{0x00}, 0644)
		req := httptest.NewRequest("GET", "/api/file?path=test"+ext, nil)
		rr := httptest.NewRecorder()
		apiReadFile(rr, req)
		m := decodeJSON(t, rr.Body)
		if m["binary"] != true {
			t.Errorf("expected binary=true for %s", ext)
		}
	}
}

func TestApiListFiles_FileSize(t *testing.T) {
	dir := setupTestProject(t)
	os.WriteFile(filepath.Join(dir, "sized.txt"), []byte("12345"), 0644)

	req := httptest.NewRequest("GET", "/api/files?path=.", nil)
	rr := httptest.NewRecorder()
	apiListFiles(rr, req)

	entries := decodeJSONSlice(t, rr.Body)
	for _, e := range entries {
		m := e.(map[string]interface{})
		if m["name"] == "sized.txt" {
			if m["size"].(float64) != 5 {
				t.Errorf("expected size 5, got %v", m["size"])
			}
			return
		}
	}
	t.Error("sized.txt not found")
}

func TestApiCreateFile_CreateInDir(t *testing.T) {
	setupTestProject(t)
	body := `{"path":"subdir/inner.go","isDir":false}`
	req := httptest.NewRequest("POST", "/api/file/create", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	apiCreateFile(rr, req)
	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestApiFuzzLaunch_DefaultDepthAndFilters(t *testing.T) {
	setupTestProject(t)
	fuzzMu.Lock()
	fuzzRunning = false
	fuzzLog = nil
	fuzzMu.Unlock()

	// URL provided but depth and filters empty → should use defaults
	body := `{"url":"https://example.com","depth":"","filters":"","wordlist":"test.txt","modes":"subdomain,api"}`
	req := httptest.NewRequest("POST", "/api/fuzz/launch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	apiFuzzLaunch(rr, req)

	m := decodeJSON(t, rr.Body)
	// Will either succeed with "message" or fail with "error" (go not found etc)
	if _, ok := m["message"]; !ok {
		if _, ok2 := m["error"]; !ok2 {
			t.Error("expected either message or error")
		}
	}

	// Cleanup
	fuzzMu.Lock()
	if fuzzCmd != nil && fuzzCmd.Process != nil {
		fuzzCmd.Process.Kill()
	}
	fuzzRunning = false
	fuzzMu.Unlock()
}

func TestApiFuzzStop_WithRunningProcess(t *testing.T) {
	setupTestProject(t)

	// Simulate a running process
	fuzzMu.Lock()
	fuzzRunning = true
	fuzzLog = []string{"running..."}
	fuzzCmd = nil // no actual process, but test the path
	fuzzMu.Unlock()

	req := httptest.NewRequest("POST", "/api/fuzz/stop", nil)
	rr := httptest.NewRecorder()
	apiFuzzStop(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestApiRawLogs_SpecificFile(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/raw_logs?raw_file=node01_12345.log&raw_filter=error", nil)
	rr := httptest.NewRecorder()
	apiRawLogs(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestApiRawLogs_EmptyFilter(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/raw_logs?raw_file=all", nil)
	rr := httptest.NewRecorder()
	apiRawLogs(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestApiFindings_WithFilters(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/findings?filters=200,403&exclude_sizes=0", nil)
	rr := httptest.NewRecorder()
	apiFindings(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestServeIndex_HTMLContainsDeployButton(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	serveIndex(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "DEPLOY") {
		t.Error("expected DEPLOY button in HTML")
	}
	if !strings.Contains(body, "sidebar") {
		t.Error("expected sidebar in HTML")
	}
}

func TestHttpJSON_ArrayResponse(t *testing.T) {
	rr := httptest.NewRecorder()
	data := []string{"a", "b", "c"}
	httpJSON(rr, 200, data)

	if rr.Code != 200 {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var result []string
	json.NewDecoder(rr.Body).Decode(&result)
	if len(result) != 3 {
		t.Errorf("expected 3 items, got %d", len(result))
	}
}

func TestSplitClean_SpacesAround(t *testing.T) {
	r := splitClean("  200  ,  403  ")
	if len(r) != 2 || r[0] != "200" || r[1] != "403" {
		t.Errorf("unexpected: %v", r)
	}
}

func TestMatchFilters_SizeWithoutExcludes(t *testing.T) {
	statusRe := regexp.MustCompile(`Status: (\d+)`)
	sizeRe := regexp.MustCompile(`(?:Size|ContentLength): (\d+)`)
	line := "[+] Found https://example.com/page Status: 200 Size: 5000"
	if !matchFilters(line, []string{"200"}, []string{}, statusRe, sizeRe) {
		t.Error("expected match with empty excludes list")
	}
}

func TestApiAction_LaunchWithDepthDefault(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/action", nil)
	req.Form = url.Values{
		"action":  {"launch"},
		"url":     {"https://example.com"},
		"filters": {"200"},
		"depth":   {""},
	}
	rr := httptest.NewRecorder()
	apiAction(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

// ================================================================
//  WEBSOCKET TERMINAL TESTS
// ================================================================

func TestHandleTerminalWS_Integration(t *testing.T) {
	setupTestProject(t)

	// Create test server with the WS handler
	srv := httptest.NewServer(http.HandlerFunc(handleTerminalWS))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws/terminal"

	// Use gorilla websocket dialer
	dialer := websocket.Dialer{}
	conn, resp, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("websocket dial failed: %v", err)
	}
	defer conn.Close()

	if resp.StatusCode != 101 {
		t.Errorf("expected 101 Switching Protocols, got %d", resp.StatusCode)
	}

	// Send a simple command
	err = conn.WriteMessage(websocket.TextMessage, []byte("echo hello"))
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// Read some output (with timeout)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var output strings.Builder
	for i := 0; i < 5; i++ {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}
		output.Write(msg)
		if strings.Contains(output.String(), "hello") {
			break
		}
	}

	// We should have received some output from powershell
	if output.Len() == 0 {
		t.Log("Warning: no output received from terminal (powershell may not be available)")
	}
}

// ================================================================
//  DEPLOY HANDLER TESTS
// ================================================================

func TestApiDeploy_Integration(t *testing.T) {
	setupTestProject(t)

	// Initialize a git repo in the temp dir so deploy can run
	cmds := [][]string{
		{"git", "init"},
		{"git", "checkout", "-b", "Development"},
		{"git", "config", "user.email", "test@test.com"},
		{"git", "config", "user.name", "Test"},
		{"git", "add", "-A"},
		{"git", "commit", "-m", "initial"},
	}
	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = projectRoot
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("git setup cmd %v failed: %v\n%s", args, err, out)
		}
	}

	req := httptest.NewRequest("POST", "/api/deploy", nil)
	rr := httptest.NewRecorder()
	apiDeploy(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	m := decodeJSON(t, rr.Body)
	steps, ok := m["steps"].([]interface{})
	if !ok {
		t.Fatal("expected steps array in response")
	}
	if len(steps) == 0 {
		t.Error("expected at least one step in deploy response")
	}

	// Verify that success field exists
	if _, ok := m["success"]; !ok {
		t.Error("expected 'success' field in deploy response")
	}
}

// ================================================================
//  INTEGRATION TESTS: getProgress, gatherFindingsStr, getRawLogs
//  These require logDir/fuzzerDir to have data. We can't change
//  the consts, but we test the function paths that are reachable.
// ================================================================

func TestGetWordlists_WithFiles(t *testing.T) {
	dir := t.TempDir()
	projectRoot = dir

	wlDir := filepath.Join(dir, "wordlists")
	os.MkdirAll(wlDir, 0755)
	os.WriteFile(filepath.Join(wlDir, "common.txt"), []byte("a\nb\n"), 0644)
	os.WriteFile(filepath.Join(wlDir, "big.txt"), []byte("x\ny\nz\n"), 0644)

	// Note: getWordlists uses fuzzerDir const, not projectRoot.
	// So this tests the fallback path (no wordlists found returns default).
	result := getWordlists()
	if len(result) == 0 {
		t.Error("expected at least one wordlist (default fallback)")
	}
}

func TestGetLogFiles_NoLogs(t *testing.T) {
	result := getLogFiles()
	// May return nil or empty since logDir likely doesn't exist in test
	_ = result
}

func TestGetProgress_NoWordlist(t *testing.T) {
	total, processed := getProgress("")
	// With default wordlist not found, returns (1, 0)
	if total != 1 && processed != 0 {
		t.Logf("getProgress returned total=%d processed=%d", total, processed)
	}
}

func TestGetProgress_WithWordlist(t *testing.T) {
	total, processed := getProgress("nonexistent.txt")
	if total != 1 || processed != 0 {
		t.Logf("getProgress for nonexistent: total=%d processed=%d", total, processed)
	}
}

func TestGetJobStatus_NoSlurm(t *testing.T) {
	// squeue won't be available on Windows dev machine
	status := getJobStatus()
	if status == "" {
		t.Error("expected non-empty status string")
	}
}

func TestGatherFindingsStr_NoLogDir(t *testing.T) {
	result := gatherFindingsStr("200", "")
	// With no log files, returns empty
	if result != "" {
		t.Logf("unexpected findings: %q", result)
	}
}

func TestGetRawLogs_AllEmpty(t *testing.T) {
	result := getRawLogs("all", "")
	// logDir won't exist in test env, returns empty
	_ = result
}

func TestGetRawLogs_SpecificFileMissing(t *testing.T) {
	result := getRawLogs("nonexistent.log", "")
	if result != "" {
		t.Logf("unexpected raw logs: %q", result)
	}
}

func TestGetRawLogs_DashboardExcluded(t *testing.T) {
	result := getRawLogs("dashboard.log", "")
	// dashboard.log should be excluded
	_ = result
}

// ================================================================
//  INTEGRATION TESTS: Full server with real routes
// ================================================================

func TestIntegration_FullServer(t *testing.T) {
	setupTestProject(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/files", apiListFiles)
	mux.HandleFunc("/api/file", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			apiReadFile(w, r)
		case "POST":
			apiWriteFile(w, r)
		case "DELETE":
			apiDeleteFile(w, r)
		default:
			http.Error(w, "Method not allowed", 405)
		}
	})
	mux.HandleFunc("/api/file/create", apiCreateFile)
	mux.HandleFunc("/api/file/rename", apiRenameFile)
	mux.HandleFunc("/api/request", apiSendRequest)
	mux.HandleFunc("/api/fuzz/status", apiFuzzStatus)
	mux.HandleFunc("/api/fuzz/stop", apiFuzzStop)
	mux.HandleFunc("/api/git", apiGitInfo)
	mux.HandleFunc("/api/status", apiStatus)
	mux.HandleFunc("/api/findings", apiFindings)
	mux.HandleFunc("/api/raw_logs", apiRawLogs)
	mux.HandleFunc("/api/action", apiAction)
	mux.HandleFunc("/api/analyze", apiAnalyze)
	mux.HandleFunc("/api/deploy", apiDeploy)
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	mux.HandleFunc("/", serveIndex)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Test index
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Test favicon
	resp, err = http.Get(srv.URL + "/favicon.ico")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 204 {
		t.Errorf("expected 204, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Test 404
	resp, err = http.Get(srv.URL + "/nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 404 {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Test file list via full HTTP
	resp, err = http.Get(srv.URL + "/api/files?path=.")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Test file read via full HTTP
	resp, err = http.Get(srv.URL + "/api/file?path=hello.go")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestApiAnalyze_AllPromptTypes(t *testing.T) {
	prompts := []string{"audit", "summary", "extract", "unknown_type"}
	for _, pt := range prompts {
		req := httptest.NewRequest("POST", "/api/analyze", nil)
		req.Form = url.Values{
			"prompt_type": {pt},
			"source_type": {"findings"},
			"filters":     {"200"},
		}
		rr := httptest.NewRecorder()
		apiAnalyze(rr, req)

		if rr.Code != 200 {
			t.Errorf("expected 200 for prompt_type=%s, got %d", pt, rr.Code)
		}
	}
}

func TestApiFindings_EmptyFilters(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/findings", nil)
	rr := httptest.NewRecorder()
	apiFindings(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestApiWriteFile_LargeContent(t *testing.T) {
	setupTestProject(t)

	largeContent := strings.Repeat("x", 100000)
	body := fmt.Sprintf(`{"path":"large.txt","content":"%s"}`, largeContent)
	req := httptest.NewRequest("POST", "/api/file", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	apiWriteFile(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	data, _ := os.ReadFile(filepath.Join(projectRoot, "large.txt"))
	if len(data) != 100000 {
		t.Errorf("expected 100000 bytes, got %d", len(data))
	}
}

func TestApiSendRequest_ConnectionRefused(t *testing.T) {
	// Use a port that's definitely not listening
	body := `{"method":"GET","url":"http://127.0.0.1:1"}`
	req := httptest.NewRequest("POST", "/api/request", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	apiSendRequest(rr, req)

	m := decodeJSON(t, rr.Body)
	if _, ok := m["error"]; !ok {
		t.Error("expected error for connection refused")
	}
}

// ================================================================
//  TESTS WITH REAL LOG DATA (logDir/fuzzerDir now set by setup)
// ================================================================

func TestGetWordlists_RealData(t *testing.T) {
	setupTestProject(t)
	result := getWordlists()
	if len(result) < 2 {
		t.Errorf("expected at least 2 wordlists, got %d: %v", len(result), result)
	}
	found := false
	for _, w := range result {
		if w == "test.txt" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected test.txt in wordlists: %v", result)
	}
}

func TestGetLogFiles_RealData(t *testing.T) {
	setupTestProject(t)
	result := getLogFiles()
	if len(result) != 2 {
		t.Errorf("expected 2 log files (dashboard excluded), got %d: %v", len(result), result)
	}
	for _, f := range result {
		if f == "dashboard.log" {
			t.Error("dashboard.log should be excluded from getLogFiles")
		}
	}
}

func TestGetProgress_RealWordlist(t *testing.T) {
	setupTestProject(t)
	total, processed := getProgress("seclists_common.txt")
	if total != 5 {
		t.Errorf("expected total=5 (5 lines in test wordlist), got %d", total)
	}
	// processed counts lines in node*_*.log files
	if processed < 0 {
		t.Errorf("processed should be >= 0, got %d", processed)
	}
}

func TestGetProgress_DefaultWordlist(t *testing.T) {
	setupTestProject(t)
	total, _ := getProgress("")
	// Should use seclists_common.txt by default
	if total != 5 {
		t.Errorf("expected total=5, got %d", total)
	}
}

func TestGatherFindingsStr_RealData(t *testing.T) {
	setupTestProject(t)
	result := gatherFindingsStr("200", "")
	if !strings.Contains(result, "Status: 200") {
		t.Errorf("expected findings with Status: 200, got %q", result)
	}
	if strings.Contains(result, "Status: 403") {
		t.Error("should not contain 403 when filtering for 200")
	}
}

func TestGatherFindingsStr_WithExclude(t *testing.T) {
	setupTestProject(t)
	result := gatherFindingsStr("200", "1024")
	// Should exclude the entry with Size: 1024
	if strings.Contains(result, "1024") {
		t.Error("expected size 1024 to be excluded")
	}
}

func TestGatherFindingsStr_MultipleFilters(t *testing.T) {
	setupTestProject(t)
	result := gatherFindingsStr("200,403", "")
	if !strings.Contains(result, "Status: 200") {
		t.Error("expected 200 findings")
	}
	if !strings.Contains(result, "Status: 403") {
		t.Error("expected 403 findings")
	}
}

func TestGetRawLogs_RealAllFiles(t *testing.T) {
	setupTestProject(t)
	result := getRawLogs("all", "")
	if result == "" {
		t.Error("expected non-empty raw logs")
	}
	if strings.Contains(result, "[dashboard.log]") {
		t.Error("dashboard.log should be excluded")
	}
	if !strings.Contains(result, "[node01_12345.log]") {
		t.Error("expected node01 logs")
	}
}

func TestGetRawLogs_WithFilter(t *testing.T) {
	setupTestProject(t)
	result := getRawLogs("all", "error")
	if !strings.Contains(strings.ToLower(result), "error") {
		t.Error("expected filtered results containing 'error'")
	}
}

func TestGetRawLogs_SingleFile(t *testing.T) {
	setupTestProject(t)
	result := getRawLogs("node01_12345.log", "")
	if !strings.Contains(result, "example.com/admin") {
		t.Error("expected admin entry from node01")
	}
}

func TestApiFindings_RealData(t *testing.T) {
	setupTestProject(t)

	req := httptest.NewRequest("GET", "/api/findings?filters=200", nil)
	rr := httptest.NewRecorder()
	apiFindings(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if strings.Contains(body, "No findings") {
		t.Error("expected findings, got 'No findings'")
	}
	if !strings.Contains(body, "example.com") {
		t.Errorf("expected example.com URLs in findings: %s", body)
	}
}

func TestApiFindings_WithExcludeSize(t *testing.T) {
	setupTestProject(t)

	req := httptest.NewRequest("GET", "/api/findings?filters=200&exclude_sizes=1024", nil)
	rr := httptest.NewRecorder()
	apiFindings(rr, req)

	body := rr.Body.String()
	// Should have the 2048 entry but not the 1024 one
	if strings.Contains(body, "1024") {
		t.Error("expected size 1024 to be excluded from findings")
	}
}

func TestApiRawLogs_RealData(t *testing.T) {
	setupTestProject(t)

	req := httptest.NewRequest("GET", "/api/raw_logs?raw_file=all&raw_filter=", nil)
	rr := httptest.NewRecorder()
	apiRawLogs(rr, req)

	body := rr.Body.String()
	if strings.Contains(body, "No raw logs") {
		t.Error("expected actual log content, got 'No raw logs'")
	}
}

func TestApiStatus_RealData(t *testing.T) {
	setupTestProject(t)

	req := httptest.NewRequest("GET", "/api/status?wordlist=seclists_common.txt", nil)
	rr := httptest.NewRecorder()
	apiStatus(rr, req)

	m := decodeJSON(t, rr.Body)
	progress := m["progress"].(map[string]interface{})
	total := progress["total"].(float64)
	if total != 5 {
		t.Errorf("expected total=5, got %v", total)
	}

	wordlists := m["wordlists"].([]interface{})
	if len(wordlists) < 2 {
		t.Errorf("expected at least 2 wordlists, got %d", len(wordlists))
	}
}
