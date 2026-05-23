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
//   DEPLOY PIPELINE
// ================================================================

func apiDeploy(w http.ResponseWriter, r *http.Request) {
	type stepResult struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Output string `json:"output"`
	}

	pipeline := []struct {
		name      string
		args      []string
		allowFail bool
	}{
		{"Stage Changes", []string{"git", "add", "-A"}, false},
		{"Commit", []string{"git", "commit", "-m", "deploy: " + time.Now().Format("2006-01-02T15:04:05")}, true},
		{"Push Development", []string{"git", "push", "origin", "Development"}, false},
		{"Checkout Production", []string{"git", "checkout", "Production"}, false},
		{"Pull Production", []string{"git", "pull", "origin", "Production"}, true},
		{"Merge Development", []string{"git", "merge", "Development", "-m", "merge: Development -> Production"}, false},
		{"Push Production", []string{"git", "push", "origin", "Production"}, false},
		{"Checkout Development", []string{"git", "checkout", "Development"}, false},
	}

	var steps []stepResult
	success := true

	for _, p := range pipeline {
		cmd := exec.Command(p.args[0], p.args[1:]...)
		cmd.Dir = projectRoot
		out, err := cmd.CombinedOutput()
		outStr := strings.TrimSpace(string(out))

		if err != nil {
			if p.allowFail {
				steps = append(steps, stepResult{p.name, "skip", outStr})
				continue
			}
			steps = append(steps, stepResult{p.name, "error", outStr + " â€” " + err.Error()})
			success = false
			break
		}
		steps = append(steps, stepResult{p.name, "ok", outStr})
	}

	if !success {
		cmd := exec.Command("git", "checkout", "Development")
		cmd.Dir = projectRoot
		cmd.Run()
	}

	httpJSON(w, 200, map[string]interface{}{"steps": steps, "success": success})
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
	http.HandleFunc("/api/deploy", apiDeploy)

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
<title>HCP Command Center</title>
<meta name="description" content="HCP Stealth Fuzzer - Unified Command Center">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.18/codemirror.min.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.18/theme/material-darker.min.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.18/addon/dialog/dialog.min.css">
<style>
:root{--bg:#05080f;--bg2:#0a0e17;--bg3:#0f1520;--surface:#141c2b;--surfH:#1a2438;--bdr:#1e293b;--bdr2:#334155;--pri:#00ffff;--priA:rgba(0,255,255,.12);--ok:#39ff14;--err:#ff003c;--warn:#ffb000;--purp:#bf00ff;--txt:#e2e8f0;--txt2:#94a3b8;--dim:#64748b;--ui:'Inter',sans-serif;--mono:'JetBrains Mono','Consolas',monospace;--r:6px}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:var(--ui);background:var(--bg);color:var(--txt);height:100vh;overflow:hidden;display:flex;flex-direction:column;font-size:13px}
::-webkit-scrollbar{width:5px;height:5px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--bdr2);border-radius:3px}

/* TOPBAR */
#topbar{height:46px;flex-shrink:0;background:linear-gradient(90deg,var(--bg2),var(--bg3));border-bottom:1px solid rgba(0,255,255,.2);display:flex;align-items:center;padding:0 16px;gap:14px;z-index:20;box-shadow:0 2px 20px rgba(0,0,0,.5)}
.brand{font-size:15px;font-weight:800;color:#fff;letter-spacing:3px;white-space:nowrap}.brand span{color:var(--pri);text-shadow:0 0 12px rgba(0,255,255,.5)}
.deploy-btn{background:linear-gradient(135deg,#39ff14,#00e676);color:#000;font-weight:800;padding:7px 18px;border:none;border-radius:var(--r);cursor:pointer;font-size:11px;text-transform:uppercase;letter-spacing:1px;box-shadow:0 0 16px rgba(57,255,20,.25);transition:all .3s;font-family:var(--ui);display:flex;align-items:center;gap:6px}
.deploy-btn:hover{box-shadow:0 0 28px rgba(57,255,20,.5);transform:translateY(-1px)}
.deploy-btn:active{transform:scale(.97)}
.deploy-btn.running{background:var(--warn);pointer-events:none;animation:dpulse 1.5s infinite}
@keyframes dpulse{0%,100%{opacity:1}50%{opacity:.6}}
.git-badge{font-family:var(--mono);font-size:10px;color:var(--pri);background:var(--priA);padding:3px 10px;border-radius:4px;border:1px solid rgba(0,255,255,.15);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.topbar-r{margin-left:auto;display:flex;align-items:center;gap:8px}
.conn-dot{width:8px;height:8px;border-radius:50%;background:var(--dim);transition:.3s}.conn-dot.live{background:var(--ok);box-shadow:0 0 8px var(--ok)}

/* BODY */
#appBody{flex:1;display:flex;overflow:hidden}

/* SIDEBAR */
#sidebar{width:48px;background:var(--bg2);border-right:1px solid var(--bdr);display:flex;flex-direction:column;align-items:center;padding:10px 0;gap:4px;flex-shrink:0}
.nav-i{width:38px;height:38px;display:flex;align-items:center;justify-content:center;background:transparent;border:none;color:var(--dim);cursor:pointer;border-radius:8px;transition:.2s;position:relative}
.nav-i:hover{color:var(--txt2);background:rgba(255,255,255,.04)}
.nav-i.active{color:var(--pri);background:var(--priA)}
.nav-i.active::before{content:'';position:absolute;left:-4px;top:8px;bottom:8px;width:3px;background:var(--pri);border-radius:2px;box-shadow:0 0 8px var(--pri)}
.nav-i svg{width:20px;height:20px}

/* WORKSPACE */
#workspace{flex:1;display:flex;flex-direction:column;overflow:hidden;position:relative}
.view{display:none;flex:1;overflow:hidden;flex-direction:column}.view.active{display:flex}

/* CARDS */
.card{background:rgba(10,14,23,.75);backdrop-filter:blur(10px);border:1px solid rgba(0,255,255,.07);border-radius:var(--r);box-shadow:0 4px 20px rgba(0,0,0,.3);padding:16px;display:flex;flex-direction:column}
.card h3{font-size:11px;text-transform:uppercase;letter-spacing:1.5px;color:var(--pri);margin-bottom:12px;font-weight:700;display:flex;align-items:center;justify-content:space-between}

/* MISSION CONTROL */
.cmd-strip{padding:12px 16px;background:var(--bg2);border-bottom:1px solid var(--bdr);display:flex;flex-wrap:wrap;gap:8px;align-items:center;flex-shrink:0}
.cmd-strip label{font-size:10px;color:var(--dim);text-transform:uppercase;font-weight:600;margin-right:2px}
.cmd-strip input,.cmd-strip select{padding:6px 8px;background:var(--surface);border:1px solid var(--bdr);color:var(--txt);font-family:var(--mono);font-size:11px;border-radius:var(--r);outline:none;transition:border .2s}
.cmd-strip input:focus,.cmd-strip select:focus{border-color:var(--pri)}
.cmd-strip .url-in{flex:1;min-width:200px}
.btn-launch{background:var(--ok);color:#000;border:none;padding:6px 14px;font-weight:800;font-size:11px;text-transform:uppercase;cursor:pointer;border-radius:var(--r);transition:.2s;font-family:var(--ui)}
.btn-launch:hover{box-shadow:0 0 14px rgba(57,255,20,.4)}
.btn-stop{background:var(--err);color:#fff;border:none;padding:6px 10px;font-weight:700;font-size:11px;cursor:pointer;border-radius:var(--r);transition:.2s}
.btn-clear{background:transparent;color:var(--dim);border:1px solid var(--bdr);padding:6px 10px;font-size:11px;cursor:pointer;border-radius:var(--r);transition:.2s}
.btn-clear:hover{border-color:var(--txt2);color:var(--txt2)}
.mode-pill{display:inline-flex;align-items:center;gap:3px;font-size:10px;color:var(--dim);cursor:pointer;padding:3px 6px;background:var(--surface);border:1px solid var(--bdr);border-radius:3px;transition:.2s}
.mode-pill:hover{border-color:var(--pri)}.mode-pill input:checked+span{color:var(--pri);font-weight:600}

.mission-grid{flex:1;display:grid;grid-template-columns:340px 1fr;gap:12px;padding:12px 16px;overflow:hidden}
.mission-left{display:flex;flex-direction:column;gap:12px;overflow-y:auto}
.mission-right{display:flex;flex-direction:column;gap:12px;overflow:hidden}

/* PROGRESS RING */
.ring-wrap{display:flex;align-items:center;gap:16px;margin-bottom:8px}
.ring-wrap svg text{font-family:var(--ui)}
.ring-info{display:flex;flex-direction:column;gap:4px}
.ring-stat{font-size:12px;color:var(--txt2)}.ring-stat strong{color:var(--txt)}

/* FINDINGS */
.findings-list{flex:1;overflow-y:auto;font-family:var(--mono);font-size:11px;line-height:1.6}
.finding-row{padding:3px 0;display:flex;gap:8px;align-items:baseline;border-bottom:1px solid rgba(255,255,255,.02)}
.status-badge{display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700;letter-spacing:.5px}
.s2xx{background:rgba(57,255,20,.12);color:var(--ok)}.s3xx{background:rgba(255,176,0,.12);color:var(--warn)}.s4xx{background:rgba(255,0,60,.12);color:var(--err)}.s5xx{background:rgba(191,0,255,.12);color:var(--purp)}
.finding-link{color:var(--pri);text-decoration:none;transition:.15s}.finding-link:hover{background:var(--pri);color:#000;padding:0 3px;border-radius:2px}

/* TERMINAL */
.term-sect{border-top:1px solid var(--bdr);flex-shrink:0;display:flex;flex-direction:column;background:#000}
.term-hdr{padding:4px 12px;font-size:10px;font-weight:700;color:var(--dim);text-transform:uppercase;cursor:pointer;display:flex;justify-content:space-between;align-items:center;background:var(--bg2);border-bottom:1px solid var(--bdr);user-select:none}
.term-hdr:hover{color:var(--txt2)}
#termBody{height:180px;display:flex;flex-direction:column;overflow:hidden;transition:height .2s}
#termBody.collapsed{height:0;overflow:hidden}
#termOutput{flex:1;padding:6px 10px;font-family:var(--mono);font-size:12px;color:var(--ok);overflow-y:auto;white-space:pre-wrap;word-break:break-all;margin:0}
.term-in{display:flex;padding:4px 10px;background:#0a0a0a;border-top:1px solid #1a1a1a}
.term-prompt{color:var(--pri);font-family:var(--mono);font-size:12px;margin-right:6px}
#termInput{flex:1;background:transparent;border:none;color:var(--ok);font-family:var(--mono);font-size:12px;outline:none}

/* AI VIEW */
.ai-layout{flex:1;padding:16px;display:flex;flex-direction:column;gap:12px;overflow-y:auto}
.ai-controls{display:flex;gap:8px;align-items:center}
.ai-controls select,.ai-controls button{padding:6px 12px;font-size:11px;border-radius:var(--r)}
.ai-controls select{background:var(--surface);border:1px solid var(--bdr);color:var(--txt);font-family:var(--mono)}
.btn-ai{background:var(--purp);color:#fff;border:none;font-weight:700;cursor:pointer;text-transform:uppercase;transition:.2s}
.btn-ai:hover{box-shadow:0 0 12px rgba(191,0,255,.4)}
.btn-ai:disabled{opacity:.5;pointer-events:none}
.ai-report{flex:1;background:var(--bg2);border:1px solid var(--bdr);border-left:3px solid var(--purp);border-radius:var(--r);padding:16px;font-family:var(--mono);font-size:12px;color:var(--txt2);overflow-y:auto;white-space:pre-wrap;line-height:1.5}

/* EDITOR VIEW */
.editor-layout{flex:1;display:flex;overflow:hidden}
#edSidebar{width:200px;background:var(--bg2);border-right:1px solid var(--bdr);display:flex;flex-direction:column;flex-shrink:0}
.ed-shdr{padding:6px 10px;font-size:10px;font-weight:700;color:var(--txt2);text-transform:uppercase;border-bottom:1px solid var(--bdr);display:flex;justify-content:space-between;align-items:center}
.ed-shdr button{background:transparent;border:none;color:var(--dim);cursor:pointer;padding:1px 4px;font-size:12px}.ed-shdr button:hover{color:var(--pri)}
#fileTree{flex:1;overflow-y:auto;padding:4px 0}
.tn{padding:3px 8px;cursor:pointer;display:flex;align-items:center;gap:4px;font-size:12px;color:var(--txt2);white-space:nowrap;user-select:none;transition:background .1s}
.tn:hover{background:var(--surfH);color:var(--txt)}.tn.active{background:var(--priA);color:var(--pri)}
.ti{font-size:9px;width:12px;text-align:center;color:var(--dim)}

#edCenter{flex:1;display:flex;flex-direction:column;min-width:0}
.ed-tabs{height:32px;background:var(--bg2);display:flex;overflow-x:auto;border-bottom:1px solid var(--bdr);flex-shrink:0}
.etab{padding:0 12px;display:flex;align-items:center;gap:6px;font-size:12px;color:var(--dim);cursor:pointer;border-right:1px solid var(--bdr);transition:.15s;white-space:nowrap}
.etab:hover{background:var(--surfH)}.etab.active{color:var(--txt);background:var(--bg);border-bottom:2px solid var(--pri)}
.etab-x{font-size:14px;padding:0 3px;border-radius:3px}.etab-x:hover{background:var(--err);color:#fff}
#editorWrap{flex:1;position:relative}
#editorWrap .CodeMirror{height:100%;font-family:var(--mono);font-size:13px;background:var(--bg)!important}
.CodeMirror-gutters{background:var(--bg2)!important;border-color:var(--bdr)!important}
.CodeMirror-linenumber{color:var(--dim)!important}.CodeMirror-cursor{border-left-color:var(--pri)!important}
.CodeMirror-selected{background:rgba(0,255,255,.08)!important}

#edRight{width:300px;background:var(--bg2);border-left:1px solid var(--bdr);display:flex;flex-direction:column;flex-shrink:0;overflow-y:auto}
.rq-hdr{padding:5px 10px;font-size:10px;font-weight:700;color:var(--dim);text-transform:uppercase;border-bottom:1px solid var(--bdr);display:flex;justify-content:space-between}
.rq-row{display:flex;gap:4px;padding:6px 8px;border-bottom:1px solid var(--bdr)}
.rq-row select,.rq-row input{padding:5px;font-size:11px;background:var(--surface);border:1px solid var(--bdr);color:var(--txt);font-family:var(--mono);border-radius:var(--r);outline:none}
.rq-row select:focus,.rq-row input:focus{border-color:var(--pri)}
.btn-send{background:var(--pri);color:#000;border:none;padding:5px 12px;font-weight:700;font-size:11px;cursor:pointer;border-radius:var(--r);transition:.2s}
.btn-send:hover{box-shadow:0 0 10px rgba(0,255,255,.4)}
#reqBody{width:100%;min-height:50px;background:var(--surface);color:var(--txt);border:none;font-family:var(--mono);font-size:11px;padding:6px;outline:none;border-bottom:1px solid var(--bdr);resize:vertical}
#respBody{flex:1;margin:0;padding:6px;font-family:var(--mono);font-size:11px;color:var(--txt2);overflow-y:auto;white-space:pre-wrap;word-break:break-all}

/* LOGS VIEW */
.logs-layout{flex:1;display:flex;flex-direction:column;padding:16px;gap:12px;overflow:hidden}
.logs-bar{display:flex;gap:8px;flex-shrink:0}
.logs-bar select,.logs-bar input{padding:6px 8px;font-size:11px;background:var(--surface);border:1px solid var(--bdr);color:var(--txt);font-family:var(--mono);border-radius:var(--r);outline:none}
.logs-bar select{width:200px}.logs-bar input{flex:1}
.logs-bar select:focus,.logs-bar input:focus{border-color:var(--pri)}
#logsContent{flex:1;background:#000;color:var(--ok);border:1px solid var(--bdr);border-radius:var(--r);padding:10px;font-family:var(--mono);font-size:11px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;margin:0}

/* LOCAL FUZZ VIEW */
.lfuzz-layout{flex:1;padding:16px;display:flex;gap:12px;overflow:hidden}
.lfuzz-ctrls{width:300px;display:flex;flex-direction:column;gap:8px;flex-shrink:0}
.lfuzz-ctrls input,.lfuzz-ctrls select{padding:6px 8px;font-size:11px;background:var(--surface);border:1px solid var(--bdr);color:var(--txt);font-family:var(--mono);border-radius:var(--r);outline:none}
.lfuzz-ctrls input:focus,.lfuzz-ctrls select:focus{border-color:var(--pri)}
.lf-badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:10px;font-weight:700;background:var(--bdr);color:var(--dim)}
.lf-badge.running{background:rgba(57,255,20,.15);color:var(--ok);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
#lfuzzOutput{flex:1;background:#000;color:var(--ok);border:1px solid var(--bdr);border-radius:var(--r);padding:10px;font-family:var(--mono);font-size:11px;overflow-y:auto;white-space:pre-wrap;margin:0}

/* DEPLOY MODAL */
.modal-bg{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);backdrop-filter:blur(4px);z-index:100;align-items:center;justify-content:center}
.modal-bg.show{display:flex}
.modal-card{background:var(--bg3);border:1px solid var(--bdr);border-radius:12px;padding:24px;width:480px;max-height:80vh;overflow-y:auto;box-shadow:0 20px 60px rgba(0,0,0,.5)}
.modal-title{font-size:16px;font-weight:800;color:var(--txt);margin-bottom:16px;display:flex;justify-content:space-between;align-items:center}
.modal-title button{background:transparent;border:none;color:var(--dim);font-size:20px;cursor:pointer}.modal-title button:hover{color:var(--txt)}
.pipe-step{display:flex;align-items:center;gap:12px;padding:10px 12px;border-radius:var(--r);background:rgba(255,255,255,.02);margin-bottom:6px;transition:background .3s}
.pipe-dot{width:12px;height:12px;border-radius:50%;background:var(--dim);flex-shrink:0;transition:.3s}
.pipe-step.ok .pipe-dot{background:var(--ok);box-shadow:0 0 8px var(--ok)}
.pipe-step.error .pipe-dot{background:var(--err);box-shadow:0 0 8px var(--err)}
.pipe-step.skip .pipe-dot{background:var(--warn)}
.pipe-step.running .pipe-dot{background:var(--pri);animation:pulse 1s infinite}
.pipe-name{flex:1;font-size:12px;font-weight:600;color:var(--txt2)}.pipe-step.ok .pipe-name{color:var(--txt)}
.pipe-stat{font-size:10px;color:var(--dim);font-family:var(--mono)}
.pipe-step.ok .pipe-stat{color:var(--ok)}.pipe-step.error .pipe-stat{color:var(--err)}
.deploy-done{margin-top:16px;padding:12px;border-radius:var(--r);text-align:center;font-weight:700;font-size:13px}
.deploy-done.success{background:rgba(57,255,20,.1);color:var(--ok);border:1px solid rgba(57,255,20,.2)}
.deploy-done.fail{background:rgba(255,0,60,.1);color:var(--err);border:1px solid rgba(255,0,60,.2)}

/* TOASTS */
#toasts{position:fixed;top:10px;right:10px;z-index:200}
.toast{padding:8px 16px;margin-bottom:4px;font-size:11px;font-weight:700;border-radius:var(--r);animation:slideIn .2s;text-transform:uppercase;letter-spacing:.5px}
.toast.success{background:var(--ok);color:#000}.toast.error{background:var(--err);color:#fff}
@keyframes slideIn{from{transform:translateX(100%);opacity:0}to{transform:translateX(0);opacity:1}}
</style>
</head>
<body>
<div id="toasts"></div>

<!-- DEPLOY MODAL -->
<div id="deployModal" class="modal-bg">
<div class="modal-card">
<div class="modal-title">Deploy Pipeline <button onclick="document.getElementById('deployModal').classList.remove('show')">&times;</button></div>
<div id="pipeSteps"></div>
<div id="deployDone" style="display:none"></div>
</div>
</div>

<!-- TOPBAR -->
<header id="topbar">
<div class="brand">HCP<span> COMMAND CENTER</span></div>
<button id="btnDeploy" class="deploy-btn" onclick="runDeploy()">
<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 19V5M5 12l7-7 7 7"/></svg>
DEPLOY
</button>
<span id="gitBadge" class="git-badge">loading...</span>
<div class="topbar-r">
<span id="connDot" class="conn-dot"></span>
</div>
</header>

<!-- BODY -->
<div id="appBody">
<!-- SIDEBAR -->
<nav id="sidebar">
<button class="nav-i active" onclick="switchView('mission',this)" title="Mission Control">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="3"/><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/></svg>
</button>
<button class="nav-i" onclick="switchView('ai',this)" title="AI Analysis">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l2.4 4.8L20 8l-4 3.9.9 5.1L12 14.4 7.1 17l.9-5.1L4 8l5.6-1.2z"/></svg>
</button>
<button class="nav-i" onclick="switchView('editor',this)" title="Code Editor">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="8 4 2 12 8 20"/><polyline points="16 4 22 12 16 20"/></svg>
</button>
<button class="nav-i" onclick="switchView('logs',this)" title="Raw Logs">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="4" y1="6" x2="20" y2="6"/><line x1="4" y1="12" x2="20" y2="12"/><line x1="4" y1="18" x2="14" y2="18"/></svg>
</button>
<button class="nav-i" onclick="switchView('localfuzz',this)" title="Local Fuzzer">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>
</button>
</nav>

<!-- WORKSPACE -->
<div id="workspace">

<!-- VIEW: MISSION CONTROL -->
<div id="v-mission" class="view active">
<div class="cmd-strip">
<label>TARGET</label>
<input type="text" id="mUrl" class="url-in" placeholder="https://target.com">
<label>CODES</label>
<input type="text" id="mFilters" value="200" style="width:70px">
<label>EXCLUDE</label>
<input type="text" id="mExclude" placeholder="sizes" style="width:70px">
<label>WORDLIST</label>
<select id="mWordlist" style="width:120px"><option>loading...</option></select>
<label>DEPTH</label>
<input type="number" id="mDepth" value="2" min="0" max="5" style="width:50px">
<label class="mode-pill"><input type="checkbox" value="subdomain"><span>Sub</span></label>
<label class="mode-pill"><input type="checkbox" value="api"><span>API</span></label>
<label class="mode-pill"><input type="checkbox" value="parameter"><span>Param</span></label>
<label class="mode-pill"><input type="checkbox" value="method"><span>Method</span></label>
<label class="mode-pill"><input type="checkbox" value="header"><span>Header</span></label>
<button class="btn-launch" onclick="launchCampaign()">&#9654; LAUNCH</button>
<button class="btn-stop" onclick="stopCampaign()">&#9632; STOP</button>
<button class="btn-clear" onclick="clearLogs()">CLEAR</button>
</div>
<div class="mission-grid">
<div class="mission-left">
<div class="card">
<h3><span><span id="statusDot" class="conn-dot"></span> Cluster Status</span></h3>
<div class="ring-wrap">
<svg width="100" height="100" viewBox="0 0 100 100">
<circle cx="50" cy="50" r="42" fill="none" stroke="rgba(0,255,255,.1)" stroke-width="7"/>
<circle id="progCircle" cx="50" cy="50" r="42" fill="none" stroke="var(--pri)" stroke-width="7" stroke-dasharray="264" stroke-dashoffset="264" stroke-linecap="round" transform="rotate(-90 50 50)" style="transition:stroke-dashoffset .5s"/>
<text id="progPct" x="50" y="48" text-anchor="middle" fill="var(--txt)" font-size="22" font-weight="800" font-family="var(--ui)">0%</text>
<text id="progSub" x="50" y="62" text-anchor="middle" fill="var(--dim)" font-size="8" font-family="var(--ui)">WAITING</text>
</svg>
<div class="ring-info">
<div class="ring-stat" id="rProcessed"><strong>0</strong> processed</div>
<div class="ring-stat" id="rTotal"><strong>0</strong> total</div>
</div>
</div>
<pre id="jobStatus" style="font-family:var(--mono);font-size:10px;color:var(--dim);white-space:pre-wrap;max-height:120px;overflow-y:auto;margin:0"></pre>
</div>
</div>
<div class="mission-right">
<div class="card" style="flex:1;overflow:hidden">
<h3>Live Findings <span id="findCount" style="font-size:10px;color:var(--dim);font-weight:400">0 results</span></h3>
<div id="findingsContent" class="findings-list">Waiting for data...</div>
</div>
</div>
</div>
</div>

<!-- VIEW: AI ANALYSIS -->
<div id="v-ai" class="view">
<div class="ai-layout">
<div class="card" style="flex-shrink:0">
<h3>AI Analysis Engine</h3>
<div class="ai-controls">
<select id="aiType"><option value="audit">Security Audit</option><option value="summary">Error Summary</option><option value="extract">Extract IPs/Creds</option></select>
<button class="btn-ai" onclick="runAI('findings',this)">Analyze Findings</button>
<button class="btn-ai" onclick="runAI('raw',this)" style="background:transparent;color:var(--purp);border:1px solid var(--purp)">Analyze Raw Logs</button>
</div>
</div>
<div id="aiReport" class="ai-report">Run an analysis to see results here.</div>
</div>
</div>

<!-- VIEW: CODE EDITOR -->
<div id="v-editor" class="view">
<div class="editor-layout">
<div id="edSidebar">
<div class="ed-shdr">Explorer <div><button onclick="newFile()">+</button><button onclick="newDir()">D</button><button onclick="refreshTree()">R</button></div></div>
<div id="fileTree"></div>
</div>
<div id="edCenter">
<div id="edTabs" class="ed-tabs"><div style="padding:8px 12px;color:var(--dim);font-size:11px">Open a file to edit</div></div>
<div id="editorWrap"><textarea id="codeTA"></textarea></div>
</div>
<div id="edRight">
<div class="rq-hdr">Request Builder</div>
<div class="rq-row">
<select id="reqMethod" style="width:80px"><option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option><option>PATCH</option></select>
<input type="text" id="reqUrl" placeholder="URL" style="flex:1">
<button class="btn-send" onclick="sendReq()">SEND</button>
</div>
<div class="rq-hdr">Headers <button onclick="addHdr()" style="background:transparent;border:none;color:var(--dim);cursor:pointer">+</button></div>
<div id="reqHeaders"></div>
<div class="rq-hdr">Body</div>
<textarea id="reqBody" placeholder="Request body..."></textarea>
<div class="rq-hdr">Response <span id="respMeta" style="font-weight:400"></span></div>
<pre id="respBody">Send a request to see response</pre>
</div>
</div>
</div>

<!-- VIEW: RAW LOGS -->
<div id="v-logs" class="view">
<div class="logs-layout">
<div class="logs-bar">
<select id="logFile"><option value="all">All Node Logs</option></select>
<input type="text" id="logFilter" placeholder="GREP filter (e.g. ERROR, 404)">
<button class="btn-clear" onclick="refreshLogs()">Search</button>
</div>
<pre id="logsContent">Loading logs...</pre>
</div>
</div>

<!-- VIEW: LOCAL FUZZER -->
<div id="v-localfuzz" class="view">
<div class="lfuzz-layout">
<div class="lfuzz-ctrls">
<div class="card">
<h3>Local Dev Fuzzer <span id="lfBadge" class="lf-badge">IDLE</span></h3>
<label class="dash-label" style="font-size:10px;color:var(--dim);margin-bottom:4px;display:block">Target URL</label>
<input type="text" id="lfUrl" placeholder="https://target.com">
<div style="display:flex;gap:4px;margin-top:6px">
<input type="text" id="lfFilters" value="200" placeholder="Codes" style="width:60px">
<select id="lfWordlist" style="flex:1"><option value="">No wordlist</option></select>
<input type="number" id="lfDepth" value="2" style="width:44px">
</div>
<div style="display:flex;gap:4px;margin-top:8px">
<button class="btn-launch" style="flex:1" onclick="lfLaunch()">&#9654; LAUNCH</button>
<button class="btn-stop" style="flex:1" onclick="lfStop()">&#9632; STOP</button>
</div>
</div>
</div>
<pre id="lfuzzOutput">Local fuzzer idle. Configure and launch.</pre>
</div>
</div>

<!-- BOTTOM TERMINAL -->
<div class="term-sect">
<div class="term-hdr" onclick="toggleTerm()"><span><span id="termDot" class="conn-dot" style="width:6px;height:6px;margin-right:4px"></span> TERMINAL</span><span id="termIcon">&#9660;</span></div>
<div id="termBody">
<pre id="termOutput"></pre>
<div class="term-in"><span class="term-prompt">PS&gt;</span><input type="text" id="termInput" autocomplete="off" placeholder="Type command..."></div>
</div>
</div>

</div><!-- workspace -->
</div><!-- appBody -->

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
/* === STATE === */
var openTabs={},activeTab=null,editor=null,termWs=null,termH=[],termHi=-1,lastDashState='';

/* === TOAST === */
function toast(m,e){var a=document.getElementById('toasts'),t=document.createElement('div');t.className='toast '+(e?'error':'success');t.textContent=m;a.appendChild(t);setTimeout(function(){t.remove()},3000)}

/* === VIEW SWITCHING === */
function switchView(id,btn){
document.querySelectorAll('.view').forEach(function(v){v.classList.remove('active')});
document.getElementById('v-'+id).classList.add('active');
document.querySelectorAll('.nav-i').forEach(function(b){b.classList.remove('active')});
if(btn)btn.classList.add('active');
if(id==='editor'&&editor)setTimeout(function(){editor.refresh()},20);
if(id==='logs')refreshLogs();
}

/* === DEPLOY PIPELINE === */
function runDeploy(){
var btn=document.getElementById('btnDeploy');
btn.classList.add('running');btn.textContent='DEPLOYING...';
var modal=document.getElementById('deployModal');
var steps=document.getElementById('pipeSteps');
var done=document.getElementById('deployDone');
done.style.display='none';
var names=['Stage Changes','Commit','Push Development','Checkout Production','Pull Production','Merge Development','Push Production','Checkout Development'];
steps.innerHTML='';
names.forEach(function(n){
steps.innerHTML+='<div class="pipe-step" id="ps-'+n.replace(/\s/g,'')+'"><div class="pipe-dot"></div><div class="pipe-name">'+n+'</div><div class="pipe-stat">waiting</div></div>';
});
modal.classList.add('show');
fetch('/api/deploy',{method:'POST'}).then(function(r){return r.json()}).then(function(data){
var i=0;
function showStep(){
if(i>=data.steps.length){
done.style.display='block';
done.className='deploy-done '+(data.success?'success':'fail');
done.textContent=data.success?'DEPLOYMENT SUCCESSFUL':'DEPLOYMENT FAILED';
btn.classList.remove('running');btn.textContent='DEPLOY';
loadGit();return;
}
var s=data.steps[i];
var el=document.getElementById('ps-'+s.name.replace(/\s/g,''));
if(el){el.className='pipe-step '+s.status;el.querySelector('.pipe-stat').textContent=s.status==='ok'?'done':s.status}
i++;setTimeout(showStep,400);
}
showStep();
}).catch(function(e){
btn.classList.remove('running');btn.textContent='DEPLOY';
toast('Deploy failed: '+e.message,true);
modal.classList.remove('show');
});
}

/* === DASHBOARD / MISSION CONTROL === */
function linkify(t){return t.replace(/(https?:\/\/[^\s]+)/g,'<a href="$1" target="_blank" class="finding-link">$1</a>')}

function updateDash(){
var wl=document.getElementById('mWordlist').value;
var f=document.getElementById('mFilters').value;
var ex=document.getElementById('mExclude').value;
var st=f+'|'+ex+'|'+wl;
fetch('/api/status?wordlist='+encodeURIComponent(wl)).then(function(r){return r.json()}).then(function(d){
document.getElementById('jobStatus').textContent=d.jobStatus;
updateSel('mWordlist',d.wordlists,wl);
updateSel('lfWordlist',d.wordlists,document.getElementById('lfWordlist').value);
updateSel('logFile',d.logFiles,document.getElementById('logFile').value,true);
var tot=d.progress.total,pr=d.progress.processed,p=0;
if(tot>0)p=Math.floor(pr*100/tot);
var ring=document.getElementById('progCircle');
ring.setAttribute('stroke-dashoffset',264*(1-Math.min(p,100)/100));
document.getElementById('progPct').textContent=Math.min(p,100)+'%';
document.getElementById('progSub').textContent=p>=100?'CRAWLING':'PROGRESS';
document.getElementById('rProcessed').innerHTML='<strong>'+pr+'</strong> processed';
document.getElementById('rTotal').innerHTML='<strong>'+tot+'</strong> total';
document.getElementById('statusDot').className='conn-dot live';
if(st!==lastDashState){
lastDashState=st;
fetch('/api/findings?filters='+encodeURIComponent(f)+'&exclude_sizes='+encodeURIComponent(ex)).then(function(r){return r.text()}).then(function(t){document.getElementById('findingsContent').innerHTML=t||'<span style="color:var(--dim)">No findings</span>';});
}
}).catch(function(){document.getElementById('statusDot').className='conn-dot'});
}
function updateSel(id,opts,cur,addAll){
if(!opts||!opts.length)return;
var s=document.getElementById(id);
var h=addAll?'<option value="all">All Logs</option>':'';
opts.forEach(function(o){h+='<option value="'+o+'">'+o+'</option>'});
s.innerHTML=h;if(cur)s.value=cur;
}

function launchCampaign(){
var f=new URLSearchParams();f.append('action','launch');
f.append('url',document.getElementById('mUrl').value);
f.append('filters',document.getElementById('mFilters').value);
f.append('wordlist',document.getElementById('mWordlist').value);
f.append('depth',document.getElementById('mDepth').value);
var m=[];document.querySelectorAll('.mode-pill input:checked').forEach(function(c){m.push(c.value)});
f.append('modes',m.join(','));
fetch('/api/action',{method:'POST',body:f}).then(function(r){return r.json()}).then(function(d){toast(d.message,d.message.toLowerCase().indexOf('error')>=0);updateDash()}).catch(function(){toast('Failed',true)});
}
function stopCampaign(){
var f=new URLSearchParams();f.append('action','stop');
fetch('/api/action',{method:'POST',body:f}).then(function(r){return r.json()}).then(function(d){toast(d.message);updateDash()}).catch(function(){toast('Failed',true)});
}
function clearLogs(){
var f=new URLSearchParams();f.append('action','clear');
fetch('/api/action',{method:'POST',body:f}).then(function(r){return r.json()}).then(function(d){toast(d.message);updateDash()}).catch(function(){toast('Failed',true)});
}

/* === AI === */
function runAI(src,btn){
btn.disabled=true;
document.getElementById('aiReport').textContent='Analyzing...';
var f=new URLSearchParams();f.append('prompt_type',document.getElementById('aiType').value);f.append('source_type',src);
if(src==='findings'){f.append('filters',document.getElementById('mFilters').value);f.append('exclude_sizes',document.getElementById('mExclude').value)}
else{f.append('raw_file',document.getElementById('logFile').value);f.append('raw_filter',document.getElementById('logFilter').value)}
fetch('/api/analyze',{method:'POST',body:f}).then(function(r){return r.json()}).then(function(d){document.getElementById('aiReport').textContent=d.report}).catch(function(e){document.getElementById('aiReport').textContent='Error: '+e.message}).finally(function(){btn.disabled=false});
}

/* === LOGS === */
function refreshLogs(){
var rf=document.getElementById('logFile').value;
var ft=document.getElementById('logFilter').value;
fetch('/api/raw_logs?raw_file='+encodeURIComponent(rf)+'&raw_filter='+encodeURIComponent(ft)).then(function(r){return r.text()}).then(function(t){document.getElementById('logsContent').innerHTML=linkify(t)}).catch(function(){});
}

/* === EDITOR === */
function initEditor(){
editor=CodeMirror.fromTextArea(document.getElementById('codeTA'),{theme:'material-darker',lineNumbers:true,autoCloseBrackets:true,tabSize:4,indentWithTabs:true,styleActiveLine:true,extraKeys:{'Ctrl-S':saveFile,'Cmd-S':saveFile}});
editor.setSize('100%','100%');
}
function refreshTree(){loadDir('.',document.getElementById('fileTree'),0)}
function loadDir(path,cont,lvl){
fetch('/api/files?path='+encodeURIComponent(path)).then(function(r){return r.json()}).then(function(ents){
cont.innerHTML='';if(!ents||!ents.length){cont.innerHTML='<div class="tn" style="padding-left:'+(lvl*14+20)+'px;color:var(--dim)">(empty)</div>';return}
ents.forEach(function(e){
var d=document.createElement('div');d.className='tn';d.style.paddingLeft=(lvl*14+8)+'px';
var cp=path==='.'?e.name:path+'/'+e.name;
if(e.isDir){
d.innerHTML='<span class="ti">&#9654;</span>&#128193; '+esc(e.name);
var cb=document.createElement('div');cb.style.display='none';
d.onclick=function(ev){ev.stopPropagation();if(cb.style.display==='none'){cb.style.display='block';d.querySelector('.ti').innerHTML='&#9660;';if(!cb.children.length)loadDir(cp,cb,lvl+1)}else{cb.style.display='none';d.querySelector('.ti').innerHTML='&#9654;'}};
cont.appendChild(d);cont.appendChild(cb);
}else{
d.innerHTML='<span class="ti"></span>&#128196; '+esc(e.name);
d.onclick=function(ev){ev.stopPropagation();openFile(cp);document.querySelectorAll('.tn.active').forEach(function(x){x.classList.remove('active')});d.classList.add('active')};
cont.appendChild(d);
}
});
});
}
function esc(s){var d=document.createElement('div');d.textContent=s;return d.innerHTML}
function openFile(p){
p=p.replace(/\\/g,'/');if(openTabs[p])return actTab(p);
fetch('/api/file?path='+encodeURIComponent(p)).then(function(r){return r.json()}).then(function(d){
if(d.binary){toast('Binary file',true);return}if(d.error&&!d.binary){toast(d.error,true);return}
var mode='text/plain';if(p.endsWith('.go'))mode='text/x-go';else if(p.endsWith('.js'))mode='text/javascript';else if(p.endsWith('.html'))mode='text/html';else if(p.endsWith('.css'))mode='text/css';else if(p.endsWith('.sh'))mode='text/x-sh';else if(p.endsWith('.md'))mode='text/x-markdown';else if(p.endsWith('.yaml')||p.endsWith('.yml'))mode='text/x-yaml';
var doc=CodeMirror.Doc(d.content||'',mode);
openTabs[p]={doc:doc,mod:false};actTab(p);renTabs();
});
}
function actTab(p){activeTab=p;editor.swapDoc(openTabs[p].doc);if(!openTabs[p].trk){openTabs[p].doc.on('change',function(){if(!openTabs[p].mod){openTabs[p].mod=true;renTabs()}});openTabs[p].trk=true}renTabs();setTimeout(function(){editor.refresh()},10)}
function renTabs(){
var b=document.getElementById('edTabs');var ks=Object.keys(openTabs);
if(!ks.length){b.innerHTML='<div style="padding:8px 12px;color:var(--dim);font-size:11px">Open a file to edit</div>';return}
var h='';ks.forEach(function(k){var nm=k.split('/').pop();var cls='etab'+(k===activeTab?' active':'');var dot=openTabs[k].mod?' <span style="color:var(--warn);font-size:8px">&#9679;</span>':'';h+='<div class="'+cls+'" data-p="'+k+'"><span>'+esc(nm)+'</span>'+dot+' <span class="etab-x" data-cp="'+k+'">&times;</span></div>'});
b.innerHTML=h;
b.querySelectorAll('.etab').forEach(function(t){t.addEventListener('click',function(e){if(!e.target.classList.contains('etab-x'))actTab(t.getAttribute('data-p'))})});
b.querySelectorAll('.etab-x').forEach(function(x){x.addEventListener('click',function(e){e.stopPropagation();clsTab(x.getAttribute('data-cp'))})});
}
function clsTab(p){if(openTabs[p]&&openTabs[p].mod&&!confirm('Discard changes?'))return;delete openTabs[p];var ks=Object.keys(openTabs);if(activeTab===p){if(ks.length)actTab(ks[ks.length-1]);else{activeTab=null;editor.setValue('');renTabs()}}else renTabs()}
function saveFile(){if(!activeTab)return;fetch('/api/file',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:activeTab,content:editor.getValue()})}).then(function(r){return r.json()}).then(function(d){if(d.message){openTabs[activeTab].mod=false;renTabs();toast('Saved')}else toast(d.error,true)})}
function newFile(){var n=prompt('File name:');if(n)fetch('/api/file/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:n,isDir:false})}).then(function(){refreshTree()})}
function newDir(){var n=prompt('Folder name:');if(n)fetch('/api/file/create',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:n,isDir:true})}).then(function(){refreshTree()})}

/* === REQUEST BUILDER === */
function addHdr(){var c=document.getElementById('reqHeaders');var d=document.createElement('div');d.className='rq-row';d.innerHTML='<input type="text" placeholder="Key" style="width:90px"><input type="text" placeholder="Value" style="flex:1"><button onclick="this.parentElement.remove()" style="background:transparent;border:none;color:var(--err);cursor:pointer">X</button>';c.appendChild(d)}
function sendReq(){
var h={};document.querySelectorAll('#reqHeaders .rq-row').forEach(function(r){var ins=r.querySelectorAll('input');if(ins[0]&&ins[0].value)h[ins[0].value]=ins[1].value});
document.getElementById('respMeta').textContent='...';document.getElementById('respBody').textContent='Sending...';
fetch('/api/request',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({method:document.getElementById('reqMethod').value,url:document.getElementById('reqUrl').value,body:document.getElementById('reqBody').value,headers:h})}).then(function(r){return r.json()}).then(function(d){
if(d.error){document.getElementById('respMeta').textContent='ERROR';document.getElementById('respBody').textContent=d.error;return}
var c=d.status<300?'var(--ok)':d.status<400?'var(--warn)':'var(--err)';
document.getElementById('respMeta').innerHTML='<span style="color:'+c+'">'+d.statusText+'</span> '+d.elapsedMs+'ms';
var txt='';if(d.headers){Object.keys(d.headers).forEach(function(k){txt+=k+': '+d.headers[k]+'\n'});txt+='\n'}txt+=d.body||'';
document.getElementById('respBody').textContent=txt;
}).catch(function(e){document.getElementById('respBody').textContent=e.message});
}

/* === TERMINAL === */
function initTerm(){
var proto=location.protocol==='https:'?'wss:':'ws:';
termWs=new WebSocket(proto+'//'+location.host+'/ws/terminal');
termWs.onopen=function(){document.getElementById('termDot').classList.add('live');document.getElementById('connDot').classList.add('live')};
termWs.onmessage=function(e){var o=document.getElementById('termOutput');o.textContent+=e.data;if(o.textContent.length>80000)o.textContent=o.textContent.substring(o.textContent.length-40000);o.scrollTop=o.scrollHeight};
termWs.onclose=function(){document.getElementById('termDot').classList.remove('live');document.getElementById('connDot').classList.remove('live');setTimeout(initTerm,3000)};
termWs.onerror=function(){document.getElementById('termDot').classList.remove('live')};
}
function toggleTerm(){var b=document.getElementById('termBody');var i=document.getElementById('termIcon');if(b.classList.contains('collapsed')){b.classList.remove('collapsed');i.innerHTML='&#9660;'}else{b.classList.add('collapsed');i.innerHTML='&#9654;'}}

/* === LOCAL FUZZER === */
function updateLF(){
fetch('/api/fuzz/status').then(function(r){return r.json()}).then(function(d){
var b=document.getElementById('lfBadge');b.textContent=d.running?'RUNNING':'IDLE';b.className='lf-badge'+(d.running?' running':'');
if(d.log&&d.log.length){var o=document.getElementById('lfuzzOutput');o.textContent=d.log.join('\n');o.scrollTop=o.scrollHeight}
}).catch(function(){});
}
function lfLaunch(){
var u=document.getElementById('lfUrl').value;if(!u){toast('Target URL required',true);return}
fetch('/api/fuzz/launch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:u,filters:document.getElementById('lfFilters').value,wordlist:document.getElementById('lfWordlist').value,depth:document.getElementById('lfDepth').value})}).then(function(r){return r.json()}).then(function(d){toast(d.message||d.error,!!d.error);updateLF()}).catch(function(e){toast(e.message,true)});
}
function lfStop(){fetch('/api/fuzz/stop',{method:'POST'}).then(function(){updateLF()})}

/* === GIT === */
function loadGit(){fetch('/api/git').then(function(r){return r.json()}).then(function(d){document.getElementById('gitBadge').textContent=(d.output||'').split('\n')[0]||'unknown'}).catch(function(){document.getElementById('gitBadge').textContent='git N/A'})}

/* === KEYBOARD === */
document.addEventListener('keydown',function(e){if((e.ctrlKey||e.metaKey)&&e.key==='s'){e.preventDefault();saveFile()}});

/* === INIT === */
window.addEventListener('load',function(){
initEditor();refreshTree();initTerm();updateDash();updateLF();loadGit();
setInterval(updateDash,3000);setInterval(updateLF,3000);
document.getElementById('termInput').addEventListener('keydown',function(e){
if(e.key==='Enter'&&this.value&&termWs&&termWs.readyState===1){termH.push(this.value);termHi=termH.length;termWs.send(this.value);this.value=''}
else if(e.key==='ArrowUp'&&termHi>0){termHi--;this.value=termH[termHi]}
else if(e.key==='ArrowDown'){if(termHi<termH.length-1){termHi++;this.value=termH[termHi]}else{termHi=termH.length;this.value=''}}
});
});
</script>
</body>
</html>`
