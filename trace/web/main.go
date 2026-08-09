package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"trace/internal/deps"
	"trace/internal/engine"
	"trace/internal/tracer"
)

//go:embed static
var staticFS embed.FS

// Job 一次扫描任务
type Job struct {
	ID      string
	Targets []string
	Created time.Time
	Status  string // running / done
	mu      sync.Mutex
	Results []*engine.Result
	Logs    []string
	Done    bool
}

// Hub 管理多个任务与日志流
type Hub struct {
	mu   sync.Mutex
	jobs map[string]*Job
	subs map[chan string]bool
}

func NewHub() *Hub {
	return &Hub{
		jobs: make(map[string]*Job),
		subs: make(map[chan string]bool),
	}
}

var globalHub *Hub

func (h *Hub) addLog(msg string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- msg:
		default:
		}
	}
}

func (h *Hub) subscribe() chan string {
	ch := make(chan string, 200)
	h.mu.Lock()
	h.subs[ch] = true
	h.mu.Unlock()
	return ch
}

func (h *Hub) unsubscribe(ch chan string) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
}

func (h *Hub) getJob(id string) *Job {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.jobs[id]
}

func (h *Hub) listJobs() []*Job {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]*Job, 0, len(h.jobs))
	for _, j := range h.jobs {
		out = append(out, j)
	}
	return out
}

func (h *Hub) addJob(j *Job) {
	h.mu.Lock()
	h.jobs[j.ID] = j
	h.mu.Unlock()
}

func (j *Job) logf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	j.mu.Lock()
	j.Logs = append(j.Logs, msg)
	j.mu.Unlock()
	if globalHub != nil {
		globalHub.addLog(msg)
	}
}

// ---- HTTP handlers ----

type Server struct {
	hub    *Hub
	engine *engine.Engine
}

func (s *Server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Targets    string `json:"targets"`
		SkipTracer bool   `json:"skip_tracer"`
		Workers    int    `json:"workers"`
		MaxHops    int    `json:"max_hops"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}

	var targets []string
	for _, line := range strings.Split(req.Targets, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	if len(targets) == 0 {
		http.Error(w, "no valid targets", http.StatusBadRequest)
		return
	}

	id := fmt.Sprintf("job-%d", time.Now().UnixNano())
	job := &Job{
		ID:      id,
		Targets: targets,
		Created: time.Now(),
		Status:  "running",
	}
	s.hub.addJob(job)
	job.logf("[*] 任务 %s 已创建，目标数量 %d", id, len(targets))

	eng := s.engine
	eng.SkipTracert = req.SkipTracer
	eng.Workers = req.Workers
	if eng.Workers <= 0 {
		eng.Workers = 8
	}
	cfg := tracer.DefaultConfig()
	if req.MaxHops > 0 {
		cfg.MaxHops = req.MaxHops
	}
	eng.TracerCfg = cfg

	go func() {
		ctx := context.Background()
		eng.ConcurrentScan(ctx, targets, eng.Workers, func(res *engine.Result) {
			job.mu.Lock()
			job.Results = append(job.Results, res)
			job.mu.Unlock()
			job.logf("[结果] %s", res.RawLine)
		})
		job.mu.Lock()
		job.Done = true
		job.Status = "done"
		job.mu.Unlock()
		job.logf("[+] 任务 %s 完成，共 %d 个结果", id, len(job.Results))
	}()

	json.NewEncoder(w).Encode(map[string]string{"id": id})
}

func (s *Server) handleJob(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/job/")
	job := s.hub.getJob(id)
	if job == nil {
		http.Error(w, "job not found", http.StatusNotFound)
		return
	}
	job.mu.Lock()
	defer job.mu.Unlock()
	json.NewEncoder(w).Encode(job)
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(s.hub.listJobs())
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := s.hub.subscribe()
	defer s.hub.unsubscribe(ch)

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	// 先发送历史日志
	s.hub.mu.Lock()
	var history []string
	for _, j := range s.hub.jobs {
		j.mu.Lock()
		history = append(history, j.Logs...)
		j.mu.Unlock()
	}
	s.hub.mu.Unlock()
	for _, l := range history {
		fmt.Fprintf(w, "data: %s\n\n", l)
	}

	for {
		select {
		case <-r.Context().Done():
			return
		case msg := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

// hopDetail 单跳详情（含 ASN / 线路识别）
type hopDetail struct {
	TTL     int    `json:"ttl"`
	IP      string `json:"ip"`
	Latency string `json:"latency"`
	ASN     string `json:"asn"`
	Org     string `json:"org"`
	Line    string `json:"line"`
}

func (s *Server) handleHops(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "target required", http.StatusBadRequest)
		return
	}
	cfg := tracer.DefaultConfig()
	cfg.MaxHops = 12

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	hops, err := tracer.Trace(ctx, target, cfg)
	if err != nil {
		http.Error(w, "tracert failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	out := make([]hopDetail, 0, len(hops))
	for _, h := range hops {
		asn, org, line, _ := s.engine.Identify(h.IP)
		out = append(out, hopDetail{
			TTL:     h.TTL,
			IP:      h.IP,
			Latency: h.Latency,
			ASN:     asn,
			Org:     org,
			Line:    line,
		})
	}
	json.NewEncoder(w).Encode(out)
}

func main() {
	// 1. 依赖文件
	assets, err := deps.EnsureAssets(nil)
	if err != nil {
		fmt.Printf("[!] 依赖文件自动下载未完全成功: %v\n", err)
	}

	// 2. 引擎
	eng, err := engine.NewEngine(assets, func(format string, args ...interface{}) {
		fmt.Printf(format+"\n", args...)
	})
	if err != nil {
		fmt.Printf("[-] 初始化引擎失败: %v\n", err)
		os.Exit(1)
	}
	defer eng.Close()

	eng.Workers = 8
	eng.TracerCfg = tracer.DefaultConfig()

	hub := NewHub()
	globalHub = hub
	srv := &Server{hub: hub, engine: eng}

	// 3. 路由
	mux := http.NewServeMux()
	mux.HandleFunc("/api/submit", srv.handleSubmit)
	mux.HandleFunc("/api/job/", srv.handleJob)
	mux.HandleFunc("/api/jobs", srv.handleList)
	mux.HandleFunc("/api/stream", srv.handleStream)
	mux.HandleFunc("/api/hops", srv.handleHops)

	// 静态文件
	sub, _ := fs.Sub(staticFS, "static")
	mux.Handle("/", http.FileServer(http.FS(sub)))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := ":" + port
	fmt.Printf("[*] Web 界面已启动: http://localhost%s\n", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Printf("[-] 服务器启动失败: %v\n", err)
		os.Exit(1)
	}
}

