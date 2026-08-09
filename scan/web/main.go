package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"winscan/deps"
	"winscan/scanner"
)

//go:embed index.html style.css app.js
var webFS embed.FS

const (
	maxRunJobs   = 4             // 同时运行的最大扫描任务数
	maxLogLines  = 500           // 每个任务保留的最大日志行数
	jobRetention = 1 * time.Hour // 已完成任务保留时长
	maxKeepJobs  = 50            // 最多保留的历史任务数
)

type scanJob struct {
	mu         sync.Mutex
	ID         string
	Status     string
	Target     string
	Ports      string
	Progress   scanner.Progress
	Stage1N    int
	Stage2N    int
	FinalN     int
	Output     []string
	OutputPath string
	Error      string
	Created    time.Time
	Done       time.Time
	Logs       []string
}

type server struct {
	mu   sync.Mutex
	jobs map[string]*scanJob
	sem  chan struct{}
}

func newServer() *server {
	return &server{jobs: make(map[string]*scanJob), sem: make(chan struct{}, maxRunJobs)}
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		switch r.URL.Path {
		case "/style.css":
			s.serveStatic(w, "style.css", "text/css; charset=utf-8")
		case "/app.js":
			s.serveStatic(w, "app.js", "application/javascript; charset=utf-8")
		default:
			http.NotFound(w, r)
		}
		return
	}
	data, err := webFS.ReadFile("index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

func (s *server) serveStatic(w http.ResponseWriter, name, contentType string) {
	data, err := webFS.ReadFile(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Write(data)
}

type scanRequest struct {
	Target      string `json:"target"`
	Ports       string `json:"ports"`
	Domain      string `json:"domain"`
	Concurrency int    `json:"concurrency"`
}

func (s *server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var req scanRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "无效 JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Target == "" {
		http.Error(w, "target 不能为空", http.StatusBadRequest)
		return
	}
	if req.Ports == "" {
		req.Ports = "443"
	}

	job := &scanJob{
		ID:      fmt.Sprintf("%d", time.Now().UnixNano()),
		Status:  "running",
		Target:  req.Target,
		Ports:   req.Ports,
		Created: time.Now(),
	}

	select {
	case s.sem <- struct{}{}:
	default:
		http.Error(w, "同时运行的扫描任务已达上限（"+strconv.Itoa(maxRunJobs)+"），请等待当前任务完成", http.StatusTooManyRequests)
		return
	}

	s.mu.Lock()
	s.jobs[job.ID] = job
	s.mu.Unlock()

	cfg := scanner.Config{
		Concurrency:  req.Concurrency,
		CustomDomain: req.Domain,
		Validate:     true,
	}
	if cfg.CustomDomain == "" {
		cfg.CustomDomain = os.Getenv("CUSTOM_CF_DOMAIN")
	}

	go func() {
		defer func() { <-s.sem }()

		cfg.Logger = func(format string, args ...interface{}) {
			msg := fmt.Sprintf(format, args...)
			log.Printf("[scan %s] %s", job.ID, msg)
			job.mu.Lock()
			job.Logs = append(job.Logs, msg)
			if len(job.Logs) > maxLogLines {
				job.Logs = job.Logs[len(job.Logs)-maxLogLines:]
			}
			job.mu.Unlock()
		}
		onProgress := func(p scanner.Progress) {
			job.mu.Lock()
			job.Progress = p
			job.mu.Unlock()
			stageLabels := []string{"", "阶段一 TLS 探测", "阶段二 HTTP 校验", "阶段三自定义域名校验"}
			label := stageLabels[0]
			if p.Stage >= 1 && p.Stage <= 3 {
				label = stageLabels[p.Stage]
			}
			eta := ""
			if p.ETA != "" {
				eta = " | 预计剩余 " + p.ETA
			}
			msg := fmt.Sprintf("%s 进度 %d/%d (%.1f%%) | 当前通过 %d 个%s",
				label, p.Done, p.Total, float64(p.Done)/float64(p.Total)*100, p.Passed, eta)
			cfg.Logger("%s", msg)
		}
		res, err := scanner.Scan(context.Background(), req.Target, req.Ports, cfg, onProgress)
		job.mu.Lock()
		defer job.mu.Unlock()
		job.Done = time.Now()
		if err != nil {
			job.Status = "failed"
			job.Error = err.Error()
			return
		}
		job.Status = "done"
		job.Stage1N = res.Stage1N
		job.Stage2N = res.Stage2N
		job.FinalN = len(res.FinalItems)
		job.OutputPath = res.OutputPath
		if len(res.Validated) > 0 {
			job.Output = res.Validated
		} else {
			job.Output = make([]string, 0, len(res.FinalItems))
			for _, t := range res.FinalItems {
				job.Output = append(job.Output, t.String())
			}
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"id": job.ID})
}

func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	s.mu.Lock()
	job, ok := s.jobs[id]
	s.mu.Unlock()
	if !ok {
		http.Error(w, "job 不存在", http.StatusNotFound)
		return
	}

	job.mu.Lock()
	defer job.mu.Unlock()
	outputCount := job.FinalN
	if len(job.Output) > 0 {
		outputCount = len(job.Output)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":         job.ID,
		"status":     job.Status,
		"target":     job.Target,
		"ports":      job.Ports,
		"progress":   job.Progress,
		"stage1":     job.Stage1N,
		"stage2":     job.Stage2N,
		"final":      outputCount,
		"outputPath": job.OutputPath,
		"error":      job.Error,
	})
}

func (s *server) handleResult(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	s.mu.Lock()
	job, ok := s.jobs[id]
	s.mu.Unlock()
	if !ok {
		http.Error(w, "job 不存在", http.StatusNotFound)
		return
	}

	job.mu.Lock()
	defer job.mu.Unlock()
	if job.Status != "done" {
		http.Error(w, "扫描未完成", http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for _, line := range job.Output {
		fmt.Fprintln(w, line)
	}
}

func (s *server) handleLogs(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	s.mu.Lock()
	job, ok := s.jobs[id]
	s.mu.Unlock()
	if !ok {
		http.Error(w, "job 不存在", http.StatusNotFound)
		return
	}

	job.mu.Lock()
	defer job.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"logs": job.Logs,
	})
}

func (s *server) handleHistory(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	type item struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		Target string `json:"target"`
		Final  int    `json:"final"`
		Error  string `json:"error"`
	}
	var out []item
	for _, j := range s.jobs {
		j.mu.Lock()
		out = append(out, item{ID: j.ID, Status: j.Status, Target: j.Target, Final: j.FinalN, Error: j.Error})
		j.mu.Unlock()
	}
	if out == nil {
		out = []item{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (s *server) cleanupLoop() {
	for {
		time.Sleep(5 * time.Minute)
		s.mu.Lock()
		now := time.Now()
		for id, j := range s.jobs {
			j.mu.Lock()
			if j.Status == "running" && now.Sub(j.Created) > 2*jobRetention {
				j.mu.Unlock()
				delete(s.jobs, id)
				continue
			}
			if j.Status != "running" && now.Sub(j.Done) > jobRetention {
				j.mu.Unlock()
				delete(s.jobs, id)
				continue
			}
			j.mu.Unlock()
		}
		// 保留最近 maxKeepJobs 个已完成任务
		var doneJobs []struct {
			id   string
			done time.Time
		}
		for id, j := range s.jobs {
			j.mu.Lock()
			if j.Status != "running" {
				doneJobs = append(doneJobs, struct {
					id   string
					done time.Time
				}{id, j.Done})
			}
			j.mu.Unlock()
		}
		if len(doneJobs) > maxKeepJobs {
			sort.Slice(doneJobs, func(i, j int) bool {
				return doneJobs[i].done.After(doneJobs[j].done)
			})
			for _, dj := range doneJobs[maxKeepJobs:] {
				delete(s.jobs, dj.id)
			}
		}
		s.mu.Unlock()
	}
}

func main() {
	if _, err := deps.EnsureAssets(func(format string, args ...interface{}) {
		log.Printf(format, args...)
	}); err != nil {
		log.Printf("[!] 依赖文件自动下载未完全成功: %v", err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	if len(os.Args) > 1 {
		if n, err := strconv.Atoi(os.Args[1]); err == nil && n > 0 {
			port = os.Args[1]
		}
	}

	s := newServer()
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/result", s.handleResult)
	mux.HandleFunc("/api/logs", s.handleLogs)
	mux.HandleFunc("/api/history", s.handleHistory)

	go s.cleanupLoop()

	addr := "0.0.0.0:" + port
	log.Printf("[*] Web 界面已启动: http://localhost:%s", port)
	log.Printf("[*] 端口参数: 用法 ./win-web [端口] 或环境变量 PORT")
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("启动失败: %v", err)
	}
}
