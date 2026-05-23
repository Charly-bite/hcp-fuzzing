package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// --- Configuration ---
const (
	fuzzerDir  = "/cluster_data/fuzzer"
	logDir     = "/cluster_data/fuzz_logs"
	runScript  = "/cluster_data/fuzzer/run_fuzz.sh"
	llmBinary  = "/cluster_data/llama.cpp/build/bin/llama-cli"
	llmModel   = "/cluster_data/models/Meta-Llama-3-8B-Instruct-Q4_K_M.gguf"
	listenAddr = "192.168.2.172:5006"
)

var projectRoot string

// --- Global State ---
var upgrader = websocket.Upgrader{
	CheckOrigin:     func(r *http.Request) bool { return true },
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
}

var (
	fuzzCmd     *exec.Cmd
	fuzzMu      sync.Mutex
	fuzzLog     []string
	fuzzRunning bool
)

var hiddenEntries = map[string]bool{
	".git": true, ".idea": true, ".vscode": true, ".gemini": true,
	"node_modules": true, "__pycache__": true,
}

var binaryExts = map[string]bool{
	".exe": true, ".bin": true, ".dll": true, ".so": true, ".dylib": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".ico": true, ".webp": true,
	".pdf": true, ".zip": true, ".tar": true, ".gz": true, ".7z": true, ".rar": true,
	".gguf": true, ".o": true, ".a": true, ".wasm": true,
}

// ================================================================
//   PATH SAFETY (DEV CENTER)
// ================================================================

func safePath(reqPath string) (string, error) {
	cleaned := filepath.Clean(reqPath)
	if filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("absolute paths not allowed")
	}
	if strings.HasPrefix(cleaned, "..") {
		return "", fmt.Errorf("path traversal not allowed")
	}
	fullPath := filepath.Join(projectRoot, cleaned)
	absRoot, _ := filepath.Abs(projectRoot)
	absPath, _ := filepath.Abs(fullPath)
	if !strings.HasPrefix(strings.ToLower(absPath), strings.ToLower(absRoot)) {
		return "", fmt.Errorf("path escapes project root")
	}
	return fullPath, nil
}

func httpJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// ================================================================
//   RESULTS SERVER HELPERS
// ================================================================

func getWordlists() []string {
	files, _ := filepath.Glob(filepath.Join(fuzzerDir, "wordlists", "*.txt"))
	var names []string
	for _, f := range files {
		names = append(names, filepath.Base(f))
	}
	if len(names) == 0 {
		names = append(names, "seclists_common.txt")
	}
	return names
}

func getLogFiles() []string {
	files, _ := filepath.Glob(filepath.Join(logDir, "*.log"))
	var names []string
	for _, f := range files {
		name := filepath.Base(f)
		if name != "dashboard.log" {
			names = append(names, name)
		}
	}
	return names
}

func getJobStatus() string {
	cmd := exec.Command("squeue", "--name=stealth_fuzz", "--format=%.10i %.8j %.8u %.2t %.10M %.6D %R")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "Slurm cluster not responding or squeue not found."
	}
	return string(out)
}

func getProgress(wordlistName string) (int, int) {
	if wordlistName == "" {
		wordlistName = "seclists_common.txt"
	}
	wordlistPath := filepath.Join(fuzzerDir, "wordlists", wordlistName)
	f, err := os.Open(wordlistPath)
	if err != nil {
		return 1, 0
	}
	scanner := bufio.NewScanner(f)
	total := 0
	for scanner.Scan() {
		total++
	}
	f.Close()

	files, _ := filepath.Glob(filepath.Join(logDir, "node*_*.log"))
	processed := 0
	for _, file := range files {
		f, _ := os.Open(file)
		s := bufio.NewScanner(f)
		for s.Scan() {
			processed++
		}
		f.Close()
	}
	return total, processed
}

func splitClean(s string) []string {
	if s == "" { return nil }
	parts := strings.Split(s, ",")
	var cleaned []string
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			cleaned = append(cleaned, trimmed)
		}
	}
	return cleaned
}

func matchFilters(line string, filters, excludes []string, statusRe, sizeRe *regexp.Regexp) bool {
	if len(filters) == 0 { return false }
	if !strings.Contains(line, "[+] Found") {
		return false
	}

	statusMatches := statusRe.FindStringSubmatch(line)
	if len(statusMatches) < 2 { return false }
	
	status := statusMatches[1]
	statusOk := false
	for _, f := range filters {
		if status == f { statusOk = true; break }
	}
	if !statusOk { return false }
	
	sizeMatches := sizeRe.FindStringSubmatch(line)
	if len(sizeMatches) >= 2 {
		size := sizeMatches[1]
		for _, e := range excludes {
			if size == e { return false }
		}
	}
	return true
}

func gatherFindingsStr(filters, excludeSizes string) string {
	statusRegex := regexp.MustCompile(`Status: (\d+)`)
	sizeRegex := regexp.MustCompile(`(?:Size|ContentLength): (\d+)`)
	
	filterList := splitClean(filters)
	excludeList := splitClean(excludeSizes)
	
	files, _ := filepath.Glob(filepath.Join(logDir, "*.log"))
	var sb strings.Builder
	count := 0
	
	for _, file := range files {
		if filepath.Base(file) == "dashboard.log" { continue }
		f, _ := os.Open(file)
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if matchFilters(line, filterList, excludeList, statusRegex, sizeRegex) {
				sb.WriteString(line + "\n")
				count++
				if count > 100 { break } 
			}
		}
		f.Close()
		if count > 100 { break }
	}
	return sb.String()
}

func getRawLogs(fileName, filterText string) string {
	var files []string
	if fileName == "all" || fileName == "" {
		files, _ = filepath.Glob(filepath.Join(logDir, "*.log"))
	} else {
		files = []string{filepath.Join(logDir, fileName)}
	}

	var matchedLines []string
	filterText = strings.ToLower(filterText)

	for _, file := range files {
		if filepath.Base(file) == "dashboard.log" { continue }
		f, err := os.Open(file)
		if err != nil { continue }
		
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if filterText == "" || strings.Contains(strings.ToLower(line), filterText) {
				matchedLines = append(matchedLines, fmt.Sprintf("[%s] %s", filepath.Base(file), line))
			}
		}
		f.Close()
	}

	if len(matchedLines) > 300 {
		matchedLines = matchedLines[len(matchedLines)-300:]
	}
	return strings.Join(matchedLines, "\n")
}

// ================================================================
//   RESULTS SERVER APIS
// ================================================================

func apiStatus(w http.ResponseWriter, r *http.Request) {
	wordlist := r.URL.Query().Get("wordlist")
	total, processed := getProgress(wordlist)
	
	data := map[string]interface{}{
		"wordlists": getWordlists(),
		"logFiles":  getLogFiles(),
		"jobStatus": getJobStatus(),
		"progress": map[string]int{
			"total":     total,
			"processed": processed,
		},
	}
	httpJSON(w, 200, data)
}

func apiFindings(w http.ResponseWriter, r *http.Request) {
	filters := r.URL.Query().Get("filters")
	excludeSizes := r.URL.Query().Get("exclude_sizes")
	
	statusRegex := regexp.MustCompile(`Status: (\d+)`)
	sizeRegex := regexp.MustCompile(`(?:Size|ContentLength): (\d+)`)
	urlRegex := regexp.MustCompile(`(https?://[^\s]+)`)
	
	filterList := splitClean(filters)
	excludeList := splitClean(excludeSizes)
	
	files, _ := filepath.Glob(filepath.Join(logDir, "*.log"))
	w.Header().Set("Content-Type", "text/html")
	
	count := 0
	for _, file := range files {
		if filepath.Base(file) == "dashboard.log" { continue }
		f, _ := os.Open(file)
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if matchFilters(line, filterList, excludeList, statusRegex, sizeRegex) {
				urlMatch := urlRegex.FindString(line)
				statusMatch := statusRegex.FindStringSubmatch(line)
				sizeMatch := sizeRegex.FindStringSubmatch(line)
				
				status := ""
				if len(statusMatch) > 1 { status = statusMatch[1] }
				size := ""
				if len(sizeMatch) > 1 { size = sizeMatch[1] }

				if urlMatch != "" {
					fmt.Fprintf(w, "[%s] <a href='%s' target='_blank' class='finding-link'>%s</a> (Size: %s)\n", status, urlMatch, urlMatch, size)
				} else {
					fmt.Fprintf(w, "%s\n", line)
				}
				count++
			}
		}
		f.Close()
	}
	if count == 0 {
		fmt.Fprintf(w, "<i style='color:var(--text-muted);'>No findings match the current filters.</i>")
	}
}

func apiRawLogs(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("raw_file")
	filterText := strings.ToLower(r.URL.Query().Get("raw_filter"))
	
	rawStr := getRawLogs(fileName, filterText)
	w.Header().Set("Content-Type", "text/plain")
	
	if rawStr == "" {
		fmt.Fprintf(w, "No raw logs found.")
	} else {
		fmt.Fprintf(w, rawStr)
	}
}

func apiAction(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	action := r.FormValue("action")
	msg := ""
	
	switch action {
	case "launch":
		targetUrl := r.FormValue("url")
		filters := r.FormValue("filters")
		wordlist := r.FormValue("wordlist")
		depth := r.FormValue("depth")
		if depth == "" { depth = "2" }
		modes := r.FormValue("modes")
		
		cmd := exec.Command(runScript, targetUrl, filters, wordlist, depth, modes)
		if err := cmd.Start(); err != nil {
			msg = fmt.Sprintf("Error launching: %v", err)
		} else {
			msg = "Campaign launched successfully!"
		}
	case "stop":
		cmd := exec.Command("scancel", "--jobname=stealth_fuzz")
		if err := cmd.Run(); err != nil {
			msg = fmt.Sprintf("Error stopping job: %v", err)
		} else {
			msg = "Stop command issued to cluster."
		}
	case "clear":
		files, _ := filepath.Glob(filepath.Join(logDir, "*.log"))
		for _, f := range files {
			if filepath.Base(f) != "dashboard.log" {
				os.Remove(f)
			}
		}
		msg = "Fuzzing logs cleared."
	default:
		msg = "Unknown action."
	}
	
	httpJSON(w, 200, map[string]string{"message": msg})
}

func apiAnalyze(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	promptType := r.FormValue("prompt_type")
	sourceType := r.FormValue("source_type")
	
	var dataToAnalyze string
	
	if sourceType == "findings" {
		filters := r.FormValue("filters")
		excludeSizes := r.FormValue("exclude_sizes")
		dataToAnalyze = gatherFindingsStr(filters, excludeSizes)
	} else {
		fileName := r.FormValue("raw_file")
		filterText := r.FormValue("raw_filter")
		rawStr := getRawLogs(fileName, filterText)
		lines := strings.Split(rawStr, "\n")
		if len(lines) > 200 {
			lines = lines[len(lines)-200:]
		}
		dataToAnalyze = strings.Join(lines, "\n")
	}
	
	if dataToAnalyze == "" {
		httpJSON(w, 200, map[string]string{"report": "No data available to analyze based on current filters."})
		return
	}

	systemPrompt := ""
	switch promptType {
	case "audit":
		systemPrompt = "Analyze the following web fuzzing results. Identify any potentially sensitive exposed files, directories, or critical security vulnerabilities based on the paths and status codes. Keep the analysis concise and professional."
	case "summary":
		systemPrompt = "Provide a high-level summary of the most frequent errors, unusual status codes, and failed access attempts found in these logs."
	case "extract":
		systemPrompt = "Extract any unique IPs, email addresses, suspected credentials, or API keys visible in these logs. Present them as a simple list."
	default:
		systemPrompt = "Analyze the following logs for security relevance."
	}
	
	fullPrompt := fmt.Sprintf("%s\n\n%s", systemPrompt, dataToAnalyze)
	
	cmd := exec.Command("mpirun", 
		"--mca", "btl_tcp_if_include", "192.168.1.0/24",
		"--mca", "btl", "tcp,self",
		"--host", "node01:12,node02:4,node03:16,node04:16,node06:12",
		"--oversubscribe",
		llmBinary,
		"-m", llmModel,
		"-p", fullPrompt,
		"-n", "256",
	)
	
	out, err := cmd.CombinedOutput()
	report := ""
	if err != nil {
		report = fmt.Sprintf("AI Analysis failed: %v\nOutput: %s", err, string(out))
	} else {
		res := string(out)
		if strings.Contains(res, fullPrompt) {
			parts := strings.Split(res, fullPrompt)
			report = strings.TrimSpace(parts[len(parts)-1])
		} else {
			report = res
		}
	}
	
	httpJSON(w, 200, map[string]string{"report": report})
}


// ================================================================
//   DEV CENTER APIS (FILE MANAGER, TERMINAL, HTTP, LOCAL FUZZ)
// ================================================================

type FileEntry struct {
	Name  string `json:"name"`
	IsDir bool   `json:"isDir"`
	Size  int64  `json:"size,omitempty"`
}

func apiListFiles(w http.ResponseWriter, r *http.Request) {
	reqPath := r.URL.Query().Get("path")
	if reqPath == "" { reqPath = "." }
	dirPath, err := safePath(reqPath)
	if err != nil {
		httpJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		httpJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	var dirs, files []FileEntry
	for _, e := range entries {
		name := e.Name()
		if hiddenEntries[name] { continue }
		fe := FileEntry{Name: name, IsDir: e.IsDir()}
		if !e.IsDir() {
			if info, err := e.Info(); err == nil {
				fe.Size = info.Size()
			}
		}
		if e.IsDir() { dirs = append(dirs, fe) } else { files = append(files, fe) }
	}
	sort.Slice(dirs, func(i, j int) bool { return strings.ToLower(dirs[i].Name) < strings.ToLower(dirs[j].Name) })
	sort.Slice(files, func(i, j int) bool { return strings.ToLower(files[i].Name) < strings.ToLower(files[j].Name) })
	result := append(dirs, files...)
	if result == nil { result = []FileEntry{} }
	httpJSON(w, 200, result)
}

func apiReadFile(w http.ResponseWriter, r *http.Request) {
	reqPath := r.URL.Query().Get("path")
	filePath, err := safePath(reqPath)
	if err != nil {
		httpJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	ext := strings.ToLower(filepath.Ext(filePath))
	if binaryExts[ext] {
		httpJSON(w, 200, map[string]interface{}{"binary": true, "error": "Binary file cannot be displayed"})
		return
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		httpJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	httpJSON(w, 200, map[string]interface{}{"content": string(data), "path": reqPath})
}

func apiWriteFile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	filePath, err := safePath(req.Path)
	if err != nil {
		httpJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if err := os.WriteFile(filePath, []byte(req.Content), 0644); err != nil {
		httpJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	httpJSON(w, 200, map[string]string{"message": "Saved: " + req.Path})
}

func apiCreateFile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path  string `json:"path"`
		IsDir bool   `json:"isDir"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	filePath, err := safePath(req.Path)
	if err != nil {
		httpJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if req.IsDir {
		err = os.MkdirAll(filePath, 0755)
	} else {
		os.MkdirAll(filepath.Dir(filePath), 0755)
		err = os.WriteFile(filePath, []byte(""), 0644)
	}
	if err != nil {
		httpJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	httpJSON(w, 200, map[string]string{"message": "Created: " + req.Path})
}

func apiDeleteFile(w http.ResponseWriter, r *http.Request) {
	reqPath := r.URL.Query().Get("path")
	filePath, err := safePath(reqPath)
	if err != nil {
		httpJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if err := os.RemoveAll(filePath); err != nil {
		httpJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	httpJSON(w, 200, map[string]string{"message": "Deleted: " + reqPath})
}

func apiRenameFile(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OldPath string `json:"oldPath"`
		NewPath string `json:"newPath"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	oldFull, err := safePath(req.OldPath)
	if err != nil {
		httpJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	newFull, err := safePath(req.NewPath)
	if err != nil {
		httpJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if err := os.Rename(oldFull, newFull); err != nil {
		httpJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	httpJSON(w, 200, map[string]string{"message": "Renamed successfully"})
}

func handleTerminalWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[TERM] Upgrade error: %v", err)
		return
	}
	var wsMu sync.Mutex
	safeWrite := func(data []byte) error {
		wsMu.Lock()
		defer wsMu.Unlock()
		return conn.WriteMessage(websocket.TextMessage, data)
	}

	cmd := exec.Command("powershell.exe", "-NoLogo", "-NoProfile")
	cmd.Dir = projectRoot

	stdin, err := cmd.StdinPipe()
	if err != nil {
		safeWrite([]byte("Error: " + err.Error() + "\r\n"))
		conn.Close()
		return
	}

	pr, pw, err := os.Pipe()
	if err != nil {
		safeWrite([]byte("Error: " + err.Error() + "\r\n"))
		conn.Close()
		return
	}
	cmd.Stdout = pw
	cmd.Stderr = pw

	if err := cmd.Start(); err != nil {
		safeWrite([]byte("Error starting shell: " + err.Error() + "\r\n"))
		conn.Close()
		return
	}

	pw.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, err := pr.Read(buf)
			if n > 0 {
				if writeErr := safeWrite(buf[:n]); writeErr != nil {
					break
				}
			}
			if err != nil { break }
		}
	}()

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil { break }
		stdin.Write(msg)
		stdin.Write([]byte("\r\n"))
	}

	stdin.Close()
	cmd.Process.Kill()
	cmd.Wait()
	pr.Close()
	conn.Close()
	<-done
}

func apiSendRequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Method  string            `json:"method"`
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if req.URL == "" {
		httpJSON(w, 400, map[string]string{"error": "URL is required"})
		return
	}
	if req.Method == "" { req.Method = "GET" }

	var bodyReader io.Reader
	if req.Body != "" { bodyReader = strings.NewReader(req.Body) }

	httpReq, err := http.NewRequest(req.Method, req.URL, bodyReader)
	if err != nil {
		httpJSON(w, 200, map[string]interface{}{"error": err.Error()})
		return
	}
	for k, v := range req.Headers {
		if strings.TrimSpace(k) != "" { httpReq.Header.Set(k, v) }
	}

	client := &http.Client{Timeout: 30 * time.Second}
	start := time.Now()
	resp, err := client.Do(httpReq)
	elapsed := time.Since(start)

	if err != nil {
		httpJSON(w, 200, map[string]interface{}{"error": err.Error(), "elapsedMs": elapsed.Milliseconds()})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	respHeaders := make(map[string]string)
	for k, v := range resp.Header { respHeaders[k] = strings.Join(v, ", ") }

	httpJSON(w, 200, map[string]interface{}{
		"status":     resp.StatusCode,
		"statusText": resp.Status,
		"headers":    respHeaders,
		"body":       string(body),
		"elapsedMs":  elapsed.Milliseconds(),
		"bodySize":   len(body),
	})
}

func apiFuzzLaunch(w http.ResponseWriter, r *http.Request) {
	fuzzMu.Lock()
	defer fuzzMu.Unlock()

	if fuzzRunning {
		httpJSON(w, 200, map[string]string{"error": "Fuzzer is already running"})
		return
	}

	var req struct {
		URL      string `json:"url"`
		Filters  string `json:"filters"`
		Wordlist string `json:"wordlist"`
		Depth    string `json:"depth"`
		Modes    string `json:"modes"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.URL == "" {
		httpJSON(w, 200, map[string]string{"error": "Target URL is required"})
		return
	}
	if req.Depth == "" { req.Depth = "2" }
	if req.Filters == "" { req.Filters = "200" }

	args := []string{"run", "main.go", "-url", req.URL, "-filters", req.Filters, "-depth", req.Depth}
	if req.Wordlist != "" {
		args = append(args, "-wordlist", filepath.Join("wordlists", req.Wordlist))
	}
	if req.Modes != "" {
		args = append(args, "-modes", req.Modes)
	}

	fuzzLog = []string{"[SYSTEM] Launching local dev fuzzer: go " + strings.Join(args, " ")}
	fuzzCmd = exec.Command("go", args...)
	fuzzCmd.Dir = projectRoot

	stdout, err := fuzzCmd.StdoutPipe()
	if err != nil {
		httpJSON(w, 200, map[string]string{"error": err.Error()})
		return
	}
	fuzzCmd.Stderr = fuzzCmd.Stdout

	if err := fuzzCmd.Start(); err != nil {
		httpJSON(w, 200, map[string]string{"error": err.Error()})
		return
	}

	fuzzRunning = true

	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 64*1024), 64*1024)
		for scanner.Scan() {
			fuzzMu.Lock()
			fuzzLog = append(fuzzLog, scanner.Text())
			if len(fuzzLog) > 500 { fuzzLog = fuzzLog[len(fuzzLog)-500:] }
			fuzzMu.Unlock()
		}
		fuzzCmd.Wait()
		fuzzMu.Lock()
		fuzzRunning = false
		fuzzLog = append(fuzzLog, "[SYSTEM] Local fuzzer process exited.")
		fuzzMu.Unlock()
	}()

	httpJSON(w, 200, map[string]string{"message": "Local Fuzzer launched!"})
}

func apiFuzzStop(w http.ResponseWriter, r *http.Request) {
	fuzzMu.Lock()
	defer fuzzMu.Unlock()

	if fuzzCmd != nil && fuzzCmd.Process != nil {
		fuzzCmd.Process.Kill()
		fuzzRunning = false
		fuzzLog = append(fuzzLog, "[SYSTEM] Local Fuzzer stopped by user.")
	}
	httpJSON(w, 200, map[string]string{"message": "Local Fuzzer stopped."})
}

func apiFuzzStatus(w http.ResponseWriter, r *http.Request) {
	fuzzMu.Lock()
	defer fuzzMu.Unlock()

	wlFiles, _ := filepath.Glob(filepath.Join(projectRoot, "wordlists", "*.txt"))
	var wordlists []string
	for _, f := range wlFiles { wordlists = append(wordlists, filepath.Base(f)) }
	logCopy := make([]string, len(fuzzLog))
	copy(logCopy, fuzzLog)

	httpJSON(w, 200, map[string]interface{}{
		"running":   fuzzRunning,
		"log":       logCopy,
		"wordlists": wordlists,
	})
}

func apiUploadWordlist(w http.ResponseWriter, r *http.Request) {
	r.ParseMultipartForm(32 << 20)
	file, header, err := r.FormFile("file")
	if err != nil {
		httpJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	defer file.Close()

	dstPath := filepath.Join(projectRoot, "wordlists", filepath.Base(header.Filename))
	os.MkdirAll(filepath.Dir(dstPath), 0755)
	dst, err := os.Create(dstPath)
	if err != nil {
		httpJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer dst.Close()
	io.Copy(dst, file)

	httpJSON(w, 200, map[string]string{"message": "Uploaded: " + header.Filename})
}

func apiGitInfo(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	var cmd *exec.Cmd
	switch action {
	case "diff": cmd = exec.Command("git", "diff", "--stat")
	case "log": cmd = exec.Command("git", "log", "--oneline", "-20")
	default: cmd = exec.Command("git", "status", "--short", "--branch")
	}
	cmd.Dir = projectRoot

	out, err := cmd.CombinedOutput()
	result := string(out)
	if err != nil { result = "Git: " + err.Error() + "\n" + result }
	httpJSON(w, 200, map[string]string{"output": result})
}


// ================================================================
//   MAIN
// ================================================================

func serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(unifiedHTML))
}

func main() {
	var err error
	projectRoot, err = os.Getwd()
	if err != nil {
		log.Fatal("Failed to get working directory: ", err)
	}

	// Dev Server Files & IDE
	http.HandleFunc("/api/files", apiListFiles)
	http.HandleFunc("/api/file", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET": apiReadFile(w, r)
		case "POST": apiWriteFile(w, r)
		case "DELETE": apiDeleteFile(w, r)
		default: http.Error(w, "Method not allowed", 405)
		}
	})
	http.HandleFunc("/api/file/create", apiCreateFile)
	http.HandleFunc("/api/file/rename", apiRenameFile)
	http.HandleFunc("/ws/terminal", handleTerminalWS)
	http.HandleFunc("/api/request", apiSendRequest)
	
	// Local Dev Fuzzer
	http.HandleFunc("/api/fuzz/launch", apiFuzzLaunch)
	http.HandleFunc("/api/fuzz/stop", apiFuzzStop)
	http.HandleFunc("/api/fuzz/status", apiFuzzStatus)
	http.HandleFunc("/api/wordlist/upload", apiUploadWordlist)
	http.HandleFunc("/api/git", apiGitInfo)

	// Results/Slurm Server endpoints
	http.HandleFunc("/api/status", apiStatus)
	http.HandleFunc("/api/findings", apiFindings)
	http.HandleFunc("/api/raw_logs", apiRawLogs)
	http.HandleFunc("/api/action", apiAction)
	http.HandleFunc("/api/analyze", apiAnalyze)

	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	http.HandleFunc("/", serveIndex)

	log.Printf("HCP Unified Command Center live on http://%s", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}

// ================================================================
//   UNIFIED UI HTML
// ================================================================

var unifiedHTML = `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>HCP Unified Command Center</title>
	<link rel="preconnect" href="https://fonts.googleapis.com">
	<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
	<!-- CodeMirror for IDE -->
	<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.18/codemirror.min.css">
	<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.18/theme/material-darker.min.css">
	<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.18/addon/dialog/dialog.min.css">
	<style>
		:root {
			--primary: #00ffff;
			--primary-alpha: rgba(0,255,255,0.12);
			--success: #39ff14;
			--danger: #ff003c;
			--warning: #ffb000;
			--purple: #bf00ff;
			--bg: #05080f;
			--bg-alt: #0a0e17;
			--bg-raised: #0f1520;
			--surface: #141c2b;
			--surface-hover: #1a2438;
			--border: #1e293b;
			--border-active: #334155;
			--text: #e2e8f0;
			--text-secondary: #94a3b8;
			--text-dim: #64748b;
			--font-ui: 'Inter', -apple-system, sans-serif;
			--font-mono: 'JetBrains Mono', 'Consolas', monospace;
			--radius: 4px;
		}

		* { margin: 0; padding: 0; box-sizing: border-box; }
		body { font-family: var(--font-ui); background: var(--bg); color: var(--text); height: 100vh; overflow: hidden; display: flex; flex-direction: column; }
		::-webkit-scrollbar { width: 6px; height: 6px; }
		::-webkit-scrollbar-track { background: transparent; }
		::-webkit-scrollbar-thumb { background: var(--border-active); border-radius: 3px; }
		::-webkit-scrollbar-thumb:hover { background: var(--text-dim); }

		/* MAIN NAV TABS */
		#main-nav {
			height: 44px; flex-shrink: 0;
			background: linear-gradient(90deg, var(--bg-alt), var(--bg-raised));
			border-bottom: 2px solid rgba(0,255,255,0.4);
			display: flex; align-items: center; padding: 0 16px;
			box-shadow: 0 2px 10px rgba(0,0,0,0.5); gap: 15px;
			z-index: 10;
		}
		.nav-brand { font-size: 14px; font-weight: 800; color: #fff; letter-spacing: 2px; }
		.nav-brand span { color: var(--primary); text-shadow: 0 0 10px rgba(0,255,255,0.5); }
		.nav-tab {
			background: transparent; border: 1px solid transparent; color: var(--text-secondary);
			padding: 6px 14px; font-size: 12px; font-weight: 600; text-transform: uppercase;
			border-radius: var(--radius); cursor: pointer; transition: 0.2s;
		}
		.nav-tab:hover { color: var(--text); background: rgba(255,255,255,0.05); }
		.nav-tab.active { background: var(--primary-alpha); color: var(--primary); border: 1px solid var(--primary); box-shadow: 0 0 8px rgba(0,255,255,0.2); }

		.tab-view { flex: 1; display: none; overflow: hidden; }
		.tab-view.active { display: flex; flex-direction: column; }

		/* =========================================
		   TAB 1: SLURM DASHBOARD
		   ========================================= */
		#dashboard-view { padding: 10px; background: var(--bg); }
		.dash-grid { display: grid; grid-template-columns: 350px 1fr; gap: 10px; height: 100%; overflow: hidden; }
		.dash-col { display: flex; flex-direction: column; gap: 10px; overflow-y: auto; height: 100%; }
		.dash-card { background: var(--bg-alt); border: 1px solid var(--border); padding: 15px; box-shadow: inset 0 0 10px rgba(0,0,0,0.5); display: flex; flex-direction: column; }
		.dash-card h3 { margin-bottom: 10px; color: var(--primary); border-bottom: 1px dashed var(--border); padding-bottom: 5px; font-size: 12px; text-transform: uppercase; }
		
		.dash-label { display: block; margin: 8px 0 4px; font-weight: 600; font-size: 11px; color: var(--text-dim); text-transform: uppercase; }
		.dash-input, .dash-select { width: 100%; padding: 8px; border: 1px solid var(--border-active); background: var(--surface); color: var(--text); font-family: var(--font-mono); font-size: 12px; outline: none; }
		.dash-input:focus, .dash-select:focus { border-color: var(--primary); }
		
		.dash-btn-group { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 15px; }
		.dash-btn { padding: 8px 12px; border: 1px solid transparent; cursor: pointer; font-weight: bold; font-size: 11px; text-transform: uppercase; flex: 1; text-align: center; color: #000; transition: 0.2s; }
		.dash-btn:hover:not(:disabled) { filter: brightness(1.2); }
		.dash-btn-launch { background: var(--success); }
		.dash-btn-stop { background: var(--danger); color: #fff; }
		.dash-btn-clear { background: transparent; color: var(--text-secondary); border-color: var(--border-active); }
		.dash-btn-clear:hover { background: var(--border-active); color: #fff; }
		.dash-btn-ai { background: var(--purple); color: #fff; flex-basis: 100%; }
		.dash-btn-ai-raw { background: transparent; color: var(--purple); border-color: var(--purple); }
		
		.dash-checkbox-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 5px; margin-bottom: 10px; }
		.dash-checkbox { display: flex; align-items: center; gap: 5px; cursor: pointer; font-size: 11px; background: var(--surface); padding: 5px; border: 1px solid var(--border); color: var(--text-dim); }
		.dash-checkbox:hover { border-color: var(--primary); }
		.dash-checkbox input:checked + span { color: var(--primary); font-weight: bold; }
		
		.dash-pre { background: #000; color: var(--success); padding: 10px; border: 1px solid var(--border); font-family: var(--font-mono); font-size: 11px; overflow-y: auto; margin: 0; flex: 1; }
		.dash-findings { flex: 1; overflow-y: auto; background: var(--bg-alt); padding: 10px; border: 1px solid var(--border); font-family: var(--font-mono); font-size: 11px; }
		
		.finding-link { color: var(--primary); text-decoration: none; }
		.finding-link:hover { background: var(--primary); color: #000; }
		
		.progress-bar-wrap { width: 100%; background: var(--surface); border: 1px solid var(--border); height: 16px; position: relative; margin: 5px 0; }
		.progress-bar-fill { height: 100%; background: var(--primary); width: 0%; transition: width 0.3s; }
		.progress-bar-text { position: absolute; width: 100%; top: 1px; text-align: center; font-size: 10px; font-weight: bold; color: #fff; text-shadow: 0 1px 1px #000; }
		
		.status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; background-color: var(--text-dim); }
		.status-dot.live { background-color: var(--success); box-shadow: 0 0 6px var(--success); }
		.status-dot.error { background-color: var(--danger); box-shadow: 0 0 6px var(--danger); }
		
		.ai-report { background: rgba(191,0,255,0.05); border-left: 3px solid var(--purple); padding: 10px; font-family: var(--font-mono); font-size: 11px; margin-bottom: 10px; display: none; }

		/* =========================================
		   TAB 2: IDE / DEV CENTER
		   ========================================= */
		#ide-view { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
		#ide-top {
			height: 30px; background: var(--bg-alt); border-bottom: 1px solid var(--border);
			display: flex; justify-content: space-between; align-items: center; padding: 0 10px;
		}
		.git-badge { font-family: var(--font-mono); font-size: 10px; color: var(--primary); background: var(--primary-alpha); padding: 2px 8px; border-radius: 3px; border: 1px solid rgba(0,255,255,0.15); }
		.ide-layout { flex: 1; display: flex; overflow: hidden; }
		
		#sidebar { width: 220px; background: var(--bg-alt); border-right: 1px solid var(--border); display: flex; flex-direction: column; flex-shrink: 0; }
		.sidebar-hdr { padding: 6px 10px; font-size: 10px; font-weight: 700; color: var(--text-secondary); text-transform: uppercase; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; }
		.sidebar-hdr button { background: transparent; border: none; color: var(--text-dim); cursor: pointer; padding: 0 4px; }
		.sidebar-hdr button:hover { color: var(--primary); }
		#file-tree { flex: 1; overflow-y: auto; padding: 4px 0; }
		.tree-node { padding: 3px 8px; cursor: pointer; display: flex; align-items: center; gap: 4px; font-size: 12px; color: var(--text-secondary); white-space: nowrap; user-select: none; }
		.tree-node:hover { background: var(--surface-hover); color: var(--text); }
		.tree-node.active { background: var(--primary-alpha); color: var(--primary); }
		.tree-icon { font-size: 9px; width: 12px; text-align: center; color: var(--text-dim); }
		.tree-icon-type { font-size: 12px; }
		
		#center { flex: 1; display: flex; flex-direction: column; min-width: 0; }
		#editor-section { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
		.tabs-bar { height: 34px; background: var(--bg-alt); display: flex; overflow-x: auto; border-bottom: 1px solid var(--border); }
		.editor-tab { padding: 0 12px; display: flex; align-items: center; gap: 6px; font-size: 12px; color: var(--text-dim); cursor: pointer; border-right: 1px solid var(--border); }
		.editor-tab:hover { background: var(--surface-hover); }
		.editor-tab.active { color: var(--text); background: var(--bg); border-bottom: 2px solid var(--primary); }
		.tab-close { font-size: 14px; padding: 0 4px; } .tab-close:hover { background: var(--danger); color: #fff; }
		#editor-container { flex: 1; position: relative; }
		#editor-container .CodeMirror { height: 100%; font-family: var(--font-mono); font-size: 13px; background: var(--bg) !important; }
		
		#bottom-section { height: 220px; display: flex; border-top: 1px solid var(--border); }
		.panel-hdr { padding: 4px 10px; font-size: 10px; font-weight: 700; color: var(--text-secondary); background: var(--bg-alt); border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; }
		#term-panel { flex: 1; display: flex; flex-direction: column; background: #000; border-right: 1px solid var(--border); }
		#termOutput { flex: 1; padding: 6px; font-family: var(--font-mono); font-size: 12px; color: var(--success); overflow-y: auto; white-space: pre-wrap; margin: 0; }
		.term-in-row { display: flex; padding: 4px; background: #0a0a0a; border-top: 1px solid #1a1a1a; }
		#termInput { flex: 1; background: transparent; border: none; color: var(--success); font-family: var(--font-mono); font-size: 12px; outline: none; }
		
		#fuzz-panel { flex: 1; display: flex; flex-direction: column; background: var(--bg-alt); }
		.fuzz-ctrls { padding: 6px; display: flex; flex-direction: column; gap: 4px; border-bottom: 1px solid var(--border); }
		.fuzz-ctrls input, .fuzz-ctrls select { padding: 4px; font-size: 11px; background: var(--bg); border: 1px solid var(--border); color: var(--text); }
		#localFuzzOutput { flex: 1; padding: 6px; font-family: var(--font-mono); font-size: 11px; overflow-y: auto; margin: 0; color: var(--text-dim); }

		#right-panel { width: 340px; background: var(--bg-alt); border-left: 1px solid var(--border); display: flex; flex-direction: column; flex-shrink: 0; }
		.req-builder { flex: 1; display: flex; flex-direction: column; overflow-y: auto; }
		.req-row { display: flex; gap: 4px; padding: 6px; border-bottom: 1px solid var(--border); }
		.req-row select, .req-row input { padding: 4px; font-size: 11px; background: var(--bg); border: 1px solid var(--border); color: var(--text); }
		.btn-send { background: var(--primary); color: #000; border: none; padding: 4px 10px; font-weight: bold; cursor: pointer; }
		#reqBody { width: 100%; min-height: 60px; background: var(--bg); color: var(--text); border: none; font-family: var(--font-mono); padding: 5px; outline:none; border-bottom: 1px solid var(--border); }
		#respBody { flex: 1; margin: 0; padding: 5px; font-family: var(--font-mono); font-size: 11px; color: var(--text-secondary); overflow-y: auto; }

		/* Toasts */
		#toastArea { position: fixed; top: 10px; right: 10px; z-index: 9999; }
		.toast { padding: 8px 16px; margin-bottom: 5px; font-size: 11px; font-weight: bold; border-radius: var(--radius); text-transform: uppercase; animation: slideIn 0.2s; }
		.toast.success { background: var(--success); color: #000; }
		.toast.error { background: var(--danger); color: #fff; }
		@keyframes slideIn { from{transform:translateX(100%);} to{transform:translateX(0);} }
	</style>
</head>
<body>
	<div id="toastArea"></div>

	<!-- TOP NAV -->
	<div id="main-nav">
		<div class="nav-brand">HCP<span> UNIFIED</span></div>
		<button class="nav-tab active" onclick="switchMainTab('dashboard-view', this)">Command Center (Slurm)</button>
		<button class="nav-tab" onclick="switchMainTab('ide-view', this)">IDE / Local Dev</button>
	</div>

	<!-- ==============================================
	     TAB 1: SLURM DASHBOARD
	     ============================================== -->
	<div id="dashboard-view" class="tab-view active">
		<div class="dash-grid">
			<!-- LEFT COL -->
			<div class="dash-col">
				<div class="dash-card">
					<h3>Fuzzing Campaign (Cluster)</h3>
					<label class="dash-label">Target URL:</label>
					<input type="text" id="dashUrl" class="dash-input" placeholder="https://example.com">
					<label class="dash-label">Status Search (e.g. 200,403):</label>
					<input type="text" id="dashFilters" class="dash-input" value="200">
					<label class="dash-label">Exclude Sizes (e.g. 474):</label>
					<input type="text" id="dashExcludes" class="dash-input" placeholder="Optional">
					<label class="dash-label">Wordlist:</label>
					<select id="dashWordlist" class="dash-select"><option value="">Loading...</option></select>
					<div class="dash-btn-group">
						<button class="dash-btn dash-btn-launch" onclick="dashAction('launch', this)">Launch</button>
						<button class="dash-btn dash-btn-stop" onclick="dashAction('stop', this)">Stop</button>
						<button class="dash-btn dash-btn-clear" onclick="dashAction('clear', this)">Clear Logs</button>
					</div>
				</div>

				<div class="dash-card">
					<h3>Advanced Modes</h3>
					<div class="dash-checkbox-grid">
						<label class="dash-checkbox"><input type="checkbox" id="mod_sub"><span>Subdomain</span></label>
						<label class="dash-checkbox"><input type="checkbox" id="mod_api"><span>API</span></label>
						<label class="dash-checkbox"><input type="checkbox" id="mod_par"><span>Parameter</span></label>
						<label class="dash-checkbox"><input type="checkbox" id="mod_met"><span>Method</span></label>
						<label class="dash-checkbox" style="grid-column: span 2;"><input type="checkbox" id="mod_hdr"><span>Header</span></label>
					</div>
					<label class="dash-label">Recursion Depth:</label>
					<input type="number" id="dashDepth" class="dash-input" value="2" min="0" max="5">
				</div>

				<div class="dash-card">
					<h3 style="display:flex; justify-content:space-between;">
						<span><span id="dashStatusDot" class="status-dot"></span> Live Terminal</span>
						<label style="font-size:10px; cursor:pointer;"><input type="checkbox" id="dashAutoScroll" checked> Scroll</label>
					</h3>
					<pre id="dashTerminal" class="dash-pre"></pre>
					<div class="progress-bar-wrap">
						<div id="dashProgFill" class="progress-bar-fill"></div>
						<div id="dashProgText" class="progress-bar-text">Waiting...</div>
					</div>
					<div id="dashJobStatus" style="font-size:10px; color:var(--text-dim); margin-top:5px;"></div>
				</div>

				<div class="dash-card">
					<h3>AI Analysis</h3>
					<select id="aiPromptType" class="dash-select" style="margin-bottom:5px;">
						<option value="audit">Security Audit</option>
						<option value="summary">Error Summary</option>
						<option value="extract">Extract IPs/Creds</option>
					</select>
					<div class="dash-btn-group">
						<button class="dash-btn dash-btn-ai" onclick="runAI('findings', this)">Analyze Findings</button>
						<button class="dash-btn dash-btn-ai dash-btn-ai-raw" onclick="runAI('raw', this)">Analyze Logs</button>
					</div>
				</div>
			</div>

			<!-- RIGHT COL -->
			<div class="dash-col">
				<div id="aiReportBox" class="ai-report">
					<div style="font-weight:bold; color:var(--purple); margin-bottom:5px;" id="aiStatusTitle">AI REPORT</div>
					<div id="aiReportContent"></div>
				</div>
				<div class="dash-card" style="flex:1;">
					<h3>Active Findings</h3>
					<div id="dashFindings" class="dash-findings"></div>
				</div>
				<div class="dash-card" style="flex:1;">
					<h3>Raw Log Explorer</h3>
					<div style="display:flex; gap:5px; margin-bottom:5px;">
						<select id="dashRawFile" class="dash-select" style="flex:1;"><option value="all">All Logs</option></select>
						<input type="text" id="dashRawFilter" class="dash-input" placeholder="GREP SEARCH" style="flex:2;">
					</div>
					<div id="dashRawLogs" class="dash-findings" style="background:#000; color:var(--success);"></div>
				</div>
			</div>
		</div>
	</div>

	<!-- ==============================================
	     TAB 2: IDE / DEV CENTER
	     ============================================== -->
	<div id="ide-view" class="tab-view">
		<div id="ide-top">
			<span id="gitBranch" class="git-badge">git N/A</span>
			<div>
				<button style="background:transparent; color:#fff; border:1px solid #334; padding:2px 8px; font-size:10px; cursor:pointer;" onclick="togglePanel('right-panel')">REQ BUILDER</button>
				<button style="background:transparent; color:#fff; border:1px solid #334; padding:2px 8px; font-size:10px; cursor:pointer;" onclick="togglePanel('bottom-section')">TERMINAL</button>
			</div>
		</div>
		<div class="ide-layout">
			<!-- SIDEBAR -->
			<div id="sidebar">
				<div class="sidebar-hdr">Explorer <div><button onclick="newFile()">+</button><button onclick="newDir()">D</button><button onclick="refreshTree()">R</button></div></div>
				<div id="file-tree"></div>
			</div>

			<!-- CENTER EDITOR -->
			<div id="center">
				<div id="editor-section">
					<div id="tabs-bar" class="tabs-bar"><div style="padding:10px; font-size:12px; color:var(--text-dim); font-style:italic;">Open a file to edit</div></div>
					<div id="editor-container"><textarea id="code-editor"></textarea></div>
				</div>

				<!-- BOTTOM PANELS -->
				<div id="bottom-section">
					<div id="term-panel">
						<div class="panel-hdr">Terminal <button onclick="document.getElementById('termOutput').textContent=''" style="background:transparent; border:none; color:var(--text-dim); cursor:pointer;">Clear</button></div>
						<pre id="termOutput"></pre>
						<div class="term-in-row"><span style="color:var(--primary); font-family:var(--font-mono); font-size:12px; margin-right:5px;">PS&gt;</span><input type="text" id="termInput" autocomplete="off"></div>
					</div>
					<div id="fuzz-panel">
						<div class="panel-hdr">Local Fuzzer <span id="locFuzzStatus" style="color:var(--text-dim);">IDLE</span></div>
						<div class="fuzz-ctrls">
							<input type="text" id="locUrl" placeholder="Target URL">
							<div style="display:flex; gap:4px;">
								<input type="text" id="locFilters" value="200" placeholder="Filters" style="width:60px;">
								<select id="locWordlist" style="flex:1;"><option value="">No wordlist</option></select>
								<input type="number" id="locDepth" value="2" style="width:40px;">
							</div>
							<div style="display:flex; gap:4px;">
								<button onclick="localFuzz('launch')" style="flex:1; background:var(--success); border:none; padding:4px; font-weight:bold; cursor:pointer;">LAUNCH</button>
								<button onclick="localFuzz('stop')" style="flex:1; background:var(--danger); border:none; padding:4px; font-weight:bold; cursor:pointer; color:#fff;">STOP</button>
							</div>
						</div>
						<pre id="localFuzzOutput"></pre>
					</div>
				</div>
			</div>

			<!-- RIGHT PANEL: REQ BUILDER -->
			<div id="right-panel">
				<div class="panel-hdr">Request Builder</div>
				<div class="req-builder">
					<div class="req-row">
						<select id="reqMethod"><option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option></select>
						<input type="text" id="reqUrl" placeholder="URL" style="flex:1;">
						<button class="btn-send" onclick="sendHttpReq()">SEND</button>
					</div>
					<div style="padding:6px; font-size:10px; font-weight:bold; color:var(--text-dim);">HEADERS <button onclick="addHdr()" style="float:right;">+</button></div>
					<div id="reqHeaders"></div>
					<div style="padding:6px; font-size:10px; font-weight:bold; color:var(--text-dim);">BODY</div>
					<textarea id="reqBody" placeholder="Request body..."></textarea>
					<div style="padding:6px; font-size:10px; font-weight:bold; color:var(--text-dim);">RESPONSE <span id="respStatus" style="float:right;"></span></div>
					<pre id="respBody"></pre>
				</div>
			</div>
		</div>
	</div>

	<!-- SCRIPTS -->
	<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.18/codemirror.min.js"></script>
	<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.18/mode/go/go.min.js"></script>
	<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.18/mode/javascript/javascript.min.js"></script>
	<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.18/mode/shell/shell.min.js"></script>
	<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.18/mode/markdown/markdown.min.js"></script>
	<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.18/mode/yaml/yaml.min.js"></script>
	<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.18/mode/css/css.min.js"></script>
	<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.18/addon/edit/closebrackets.min.js"></script>
	<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.18/addon/selection/active-line.min.js"></script>
	<script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.18/addon/dialog/dialog.min.js"></script>

	<script>
		function showToast(msg, isErr=false) {
			const a = document.getElementById('toastArea');
			const t = document.createElement('div');
			t.className = 'toast ' + (isErr?'error':'success');
			t.textContent = msg;
			a.appendChild(t);
			setTimeout(()=>t.remove(), 3000);
		}

		function switchMainTab(id, btn) {
			document.querySelectorAll('.nav-tab').forEach(b => b.classList.remove('active'));
			btn.classList.add('active');
			document.querySelectorAll('.tab-view').forEach(v => v.classList.remove('active'));
			document.getElementById(id).classList.add('active');
			if(id === 'ide-view' && window.editor) setTimeout(()=>editor.refresh(), 10);
		}

		/* ====================================================
		   SLURM DASHBOARD JS
		   ==================================================== */
		let lastFilters = "";
		function linkify(t) { return t.replace(/(https?:\/\/[^\s]+)/g, '<a href="$1" target="_blank" class="finding-link">$1</a>'); }
		
		async function updateDash() {
			const wordlist = document.getElementById('dashWordlist').value;
			const filters = document.getElementById('dashFilters').value;
			const ex = document.getElementById('dashExcludes').value;
			const rFile = document.getElementById('dashRawFile').value;
			const rFilt = document.getElementById('dashRawFilter').value;
			const state = filters+"|"+ex+"|"+wordlist+"|"+rFile+"|"+rFilt;
			
			try {
				const sRes = await fetch('/api/status?wordlist='+encodeURIComponent(wordlist));
				if(sRes.ok) {
					const d = await sRes.json();
					document.getElementById('dashJobStatus').innerText = d.jobStatus;
					updateSelect('dashWordlist', d.wordlists, wordlist);
					updateSelect('locWordlist', d.wordlists, document.getElementById('locWordlist').value);
					updateSelect('dashRawFile', d.logFiles, rFile, true);
					
					let p=0, tot=d.progress.total, pr=d.progress.processed;
					if(tot>0) p = Math.floor(pr*100/tot);
					document.getElementById('dashProgFill').style.width = Math.min(p,100)+'%';
					document.getElementById('dashProgText').innerText = p>=100 ? 'Crawling ('+pr+')' : p+'% ('+pr+'/'+tot+')';
					document.getElementById('dashStatusDot').className = 'status-dot live';

					if(state !== lastFilters) {
						lastFilters = state;
						fetch('/api/findings?filters='+encodeURIComponent(filters)+'&exclude_sizes='+encodeURIComponent(ex))
							.then(r=>r.text()).then(t=>document.getElementById('dashFindings').innerHTML=t);
						fetch('/api/raw_logs?raw_file='+encodeURIComponent(rFile)+'&raw_filter='+encodeURIComponent(rFilt))
							.then(r=>r.text()).then(t=>document.getElementById('dashRawLogs').innerHTML=linkify(t));
					}
					
					fetch('/api/raw_logs?raw_file=all&raw_filter=')
						.then(r=>r.text()).then(t=>{
							const term = document.getElementById('dashTerminal');
							const atBot = term.scrollHeight - term.scrollTop <= term.clientHeight + 10;
							term.innerHTML = linkify(t);
							if(document.getElementById('dashAutoScroll').checked && atBot) term.scrollTop = term.scrollHeight;
						});
				}
			} catch(e) { document.getElementById('dashStatusDot').className = 'status-dot error'; }
		}

		function updateSelect(id, opts, cur, addAll=false) {
			const s = document.getElementById(id);
			let h = addAll ? '<option value="all">All Logs</option>' : (id.includes('Word')?'<option value="">No wordlist</option>':'');
			opts.forEach(o => h+='<option value="'+o+'">'+o+'</option>');
			s.innerHTML = h;
			if(cur && Array.from(s.options).some(o=>o.value===cur)) s.value = cur;
		}

		async function dashAction(act, btn) {
			btn.disabled = true;
			const f = new URLSearchParams();
			f.append('action', act);
			f.append('url', document.getElementById('dashUrl').value);
			f.append('filters', document.getElementById('dashFilters').value);
			f.append('wordlist', document.getElementById('dashWordlist').value);
			f.append('depth', document.getElementById('dashDepth').value);
			let m=[];
			if(document.getElementById('mod_sub').checked) m.push('subdomain');
			if(document.getElementById('mod_api').checked) m.push('api');
			if(document.getElementById('mod_par').checked) m.push('parameter');
			if(document.getElementById('mod_met').checked) m.push('method');
			if(document.getElementById('mod_hdr').checked) m.push('header');
			f.append('modes', m.join(','));
			
			if(act==='clear') document.getElementById('dashTerminal').innerHTML='';
			
			try {
				const r = await fetch('/api/action', {method:'POST', body:f});
				const d = await r.json();
				showToast(d.message, d.message.toLowerCase().includes('error'));
				updateDash();
			} catch(e) { showToast('Action failed', true); }
			btn.disabled = false;
		}

		async function runAI(src, btn) {
			btn.disabled = true;
			document.getElementById('aiReportBox').style.display = 'block';
			document.getElementById('aiStatusTitle').innerText = "AI IS ANALYZING...";
			document.getElementById('aiReportContent').innerText = "";
			
			const f = new URLSearchParams();
			f.append('prompt_type', document.getElementById('aiPromptType').value);
			f.append('source_type', src);
			if(src==='findings') {
				f.append('filters', document.getElementById('dashFilters').value);
				f.append('exclude_sizes', document.getElementById('dashExcludes').value);
			} else {
				f.append('raw_file', document.getElementById('dashRawFile').value);
				f.append('raw_filter', document.getElementById('dashRawFilter').value);
			}
			try {
				const r = await fetch('/api/analyze', {method:'POST', body:f});
				const d = await r.json();
				document.getElementById('aiStatusTitle').innerText = "AI REPORT";
				document.getElementById('aiReportContent').innerText = d.report;
			} catch(e) {
				document.getElementById('aiStatusTitle').innerText = "AI FAILED";
				document.getElementById('aiReportContent').innerText = e.message;
			}
			btn.disabled = false;
		}

		/* ====================================================
		   IDE / DEV CENTER JS
		   ==================================================== */
		let openTabs={}, activeTab=null;
		let termWs=null, termHist=[], termIdx=-1;

		window.editor = CodeMirror.fromTextArea(document.getElementById('code-editor'), {
			theme: 'material-darker', lineNumbers: true, autoCloseBrackets: true,
			tabSize: 4, indentWithTabs: true, styleActiveLine: true,
			extraKeys: {'Ctrl-S': saveFile, 'Cmd-S': saveFile}
		});

		function refreshTree() { loadDir('.', document.getElementById('file-tree'), 0); }
		function loadDir(path, cont, lvl) {
			fetch('/api/files?path='+encodeURIComponent(path)).then(r=>r.json()).then(ents=>{
				cont.innerHTML='';
				if(!ents.length) { cont.innerHTML='<div class="tree-node" style="padding-left:'+(lvl*16+24)+'px; font-style:italic;">(empty)</div>'; return; }
				ents.forEach(e => {
					let d = document.createElement('div'); d.className='tree-node'; d.style.paddingLeft=(lvl*16+8)+'px';
					let cp = path==='.' ? e.name : path+'/'+e.name;
					if(e.isDir) {
						d.innerHTML='<span class="tree-icon">&#9654;</span><span class="tree-icon-type">&#128193;</span> '+e.name;
						let cb = document.createElement('div'); cb.style.display='none';
						d.onclick = ev => {
							ev.stopPropagation();
							if(cb.style.display==='none') { cb.style.display='block'; d.querySelector('.tree-icon').innerHTML='&#9660;'; if(!cb.children.length) loadDir(cp,cb,lvl+1); }
							else { cb.style.display='none'; d.querySelector('.tree-icon').innerHTML='&#9654;'; }
						};
						cont.appendChild(d); cont.appendChild(cb);
					} else {
						d.innerHTML='<span class="tree-icon"></span><span class="tree-icon-type">&#128196;</span> '+e.name;
						d.onclick = ev => { ev.stopPropagation(); openFile(cp); document.querySelectorAll('.tree-node.active').forEach(x=>x.classList.remove('active')); d.classList.add('active'); };
						cont.appendChild(d);
					}
				});
			});
		}

		function openFile(p) {
			if(openTabs[p]) return actTab(p);
			fetch('/api/file?path='+encodeURIComponent(p)).then(r=>r.json()).then(d=>{
				if(d.binary) return showToast('Binary file', true);
				if(d.error) return showToast(d.error, true);
				let mode = 'text/plain';
				if(p.endsWith('.go')) mode='text/x-go'; else if(p.endsWith('.js')) mode='text/javascript'; else if(p.endsWith('.html')) mode='text/html';
				let doc = CodeMirror.Doc(d.content||'', mode);
				openTabs[p] = {doc:doc, mod:false};
				actTab(p);
			});
		}
		function actTab(p) {
			activeTab=p; editor.swapDoc(openTabs[p].doc);
			if(!openTabs[p].trk) { openTabs[p].doc.on('change', ()=>{ if(!openTabs[p].mod){ openTabs[p].mod=true; renTabs(); } }); openTabs[p].trk=true; }
			renTabs(); setTimeout(()=>editor.refresh(), 10);
		}
		function renTabs() {
			let b = document.getElementById('tabs-bar'); b.innerHTML='';
			let ks = Object.keys(openTabs);
			if(!ks.length) { b.innerHTML='<div style="padding:10px; font-size:12px; color:var(--text-dim);">No file open</div>'; return; }
			ks.forEach(k => {
				let d = document.createElement('div'); d.className = 'editor-tab'+(k===activeTab?' active':'');
				d.innerHTML = k.split('/').pop() + (openTabs[k].mod?' <span style="color:var(--warning);font-size:10px;">&#9679;</span>':'') + ' <span class="tab-close" onclick="clsTab(event,\''+k+'\')">&times;</span>';
				d.onclick = ()=>actTab(k);
				b.appendChild(d);
			});
		}
		function clsTab(e, p) {
			e.stopPropagation();
			if(openTabs[p].mod && !confirm('Discard changes in '+p+'?')) return;
			delete openTabs[p];
			let ks = Object.keys(openTabs);
			if(activeTab===p) { if(ks.length) actTab(ks[ks.length-1]); else { activeTab=null; editor.setValue(''); renTabs(); } }
			else renTabs();
		}
		function saveFile() {
			if(!activeTab) return;
			fetch('/api/file', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({path:activeTab, content:editor.getValue()})})
			.then(r=>r.json()).then(d=>{ if(d.message) { openTabs[activeTab].mod=false; renTabs(); showToast('Saved'); } else showToast(d.error,true); });
		}
		function newFile() { let n=prompt('File name:'); if(n) fetch('/api/file/create', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({path:n, isDir:false})}).then(()=>refreshTree()); }
		function newDir() { let n=prompt('Folder name:'); if(n) fetch('/api/file/create', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({path:n, isDir:true})}).then(()=>refreshTree()); }
		
		function initTerm() {
			termWs = new WebSocket((location.protocol==='https:'?'wss:':'ws:')+'//'+location.host+'/ws/terminal');
			termWs.onmessage = e => { let o=document.getElementById('termOutput'); o.textContent+=e.data; o.scrollTop=o.scrollHeight; };
			termWs.onclose = () => setTimeout(initTerm, 3000);
		}
		document.getElementById('termInput').onkeydown = function(e) {
			if(e.key==='Enter' && this.value && termWs.readyState===1) {
				termHist.push(this.value); termIdx=termHist.length;
				termWs.send(this.value); this.value='';
			} else if(e.key==='ArrowUp' && termIdx>0) { termIdx--; this.value=termHist[termIdx]; }
			else if(e.key==='ArrowDown' && termIdx<termHist.length-1) { termIdx++; this.value=termHist[termIdx]; }
		};

		function addHdr() {
			let d = document.createElement('div'); d.className='req-row';
			d.innerHTML='<input type="text" placeholder="Key" style="width:100px;"><input type="text" placeholder="Value" style="flex:1;"><button onclick="this.parentElement.remove()" style="background:transparent;border:none;color:var(--danger);cursor:pointer;">X</button>';
			document.getElementById('reqHeaders').appendChild(d);
		}
		async function sendHttpReq() {
			let h={}; document.querySelectorAll('#reqHeaders .req-row').forEach(r=>{ let inps=r.querySelectorAll('input'); if(inps[0].value) h[inps[0].value]=inps[1].value; });
			try {
				const r = await fetch('/api/request', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({
					method:document.getElementById('reqMethod').value, url:document.getElementById('reqUrl').value,
					body:document.getElementById('reqBody').value, headers:h
				})});
				const d = await r.json();
				if(d.error) { document.getElementById('respStatus').innerText='ERROR'; document.getElementById('respBody').innerText=d.error; return; }
				document.getElementById('respStatus').innerText = d.statusText+' | '+d.elapsedMs+'ms';
				document.getElementById('respBody').innerText = JSON.stringify(d.headers,null,2)+'\n\n'+d.body;
			} catch(e) { document.getElementById('respBody').innerText=e.message; }
		}

		async function updateLocFuzz() {
			try {
				const r = await fetch('/api/fuzz/status');
				if(r.ok) {
					const d = await r.json();
					document.getElementById('locFuzzStatus').innerText = d.running ? 'RUNNING' : 'IDLE';
					document.getElementById('locFuzzStatus').style.color = d.running ? 'var(--success)' : 'var(--text-dim)';
					if(d.log) { let o=document.getElementById('localFuzzOutput'); o.textContent=d.log.join('\n'); o.scrollTop=o.scrollHeight; }
				}
			} catch(e) {}
		}
		async function localFuzz(act) {
			if(act==='stop') return fetch('/api/fuzz/stop',{method:'POST'}).then(updateLocFuzz);
			fetch('/api/fuzz/launch', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({
				url:document.getElementById('locUrl').value, filters:document.getElementById('locFilters').value,
				wordlist:document.getElementById('locWordlist').value, depth:document.getElementById('locDepth').value
			})}).then(r=>r.json()).then(d=>{ showToast(d.message||d.error, !!d.error); updateLocFuzz(); });
		}

		function togglePanel(id) { let p=document.getElementById(id); p.style.display = p.style.display==='none' ? 'flex' : 'none'; }

		// Startup
		window.onload = function() {
			refreshTree();
			initTerm();
			updateDash();
			updateLocFuzz();
			setInterval(updateDash, 3000);
			setInterval(updateLocFuzz, 3000);
			fetch('/api/git').then(r=>r.json()).then(d=>{ document.getElementById('gitBranch').innerText=(d.output||'').split('\n')[0]||'unknown'; });
		};
	</script>
</body>
</html>`