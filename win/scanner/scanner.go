package scanner

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	Stage1Timeout = 800 * time.Millisecond
	Stage2Timeout = 2 * time.Second
	Stage3Timeout = 2 * time.Second

	validateURL         = "https://api.090227.xyz/check?proxyip=%s:%s"
	validateConcurrency = 20
	validatePerTimeout  = 15 * time.Second
	validateUserAgent   = "curl/8.0"

	stage1BatchSize = 10000
)

var defaultHTTPClient = &http.Client{
	Timeout: validatePerTimeout,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: validateConcurrency,
		IdleConnTimeout:     90 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	},
}

type Config struct {
	Concurrency  int
	CustomDomain string
	CFHostTest   string
	CFSni1       string
	OutputDir    string
	Validate     bool
	Logger       func(format string, args ...interface{})
}

type Target struct {
	IP   netip.Addr
	Port int
}

func (t Target) String() string {
	return fmt.Sprintf("%s:%d", t.IP.String(), t.Port)
}

type Progress struct {
	Stage  int    `json:"stage"`
	Done   int64  `json:"done"`
	Total  int64  `json:"total"`
	Passed int    `json:"passed"`
	ETA    string `json:"eta"`
}

type Result struct {
	FinalItems []Target
	Validated  []string
	Stage1N    int
	Stage2N    int
	OutputPath string
}

type scannerImpl struct {
	cfg     Config
	portStr string
}

func (s *scannerImpl) log(format string, args ...interface{}) {
	if s.cfg.Logger != nil {
		s.cfg.Logger(format, args...)
	} else {
		fmt.Printf(format+"\n", args...)
	}
}

func (s *scannerImpl) getConcurrency() int {
	base := s.cfg.Concurrency
	if base <= 0 {
		base = 2000
	}
	if soft := raiseFdLimit(); soft > 0 {
		s.log("[*] 系统 Socket 文件描述符上限已提升至: %d", soft)
		if soft >= 128 {
			base = minInt(base, maxInt(64, soft/2))
		}
	}
	s.log("[*] 阶段一并发数调整为: %d", base)
	return base
}

func parsePorts(portStr string) []int {
	if strings.TrimSpace(portStr) == "" {
		return []int{443}
	}
	raw := regexp.MustCompile(`[\s,，]+`).Split(strings.TrimSpace(portStr), -1)
	seen := make(map[int]bool)
	var ports []int
	for _, p := range raw {
		if n, err := strconv.Atoi(p); err == nil && n >= 1 && n <= 65535 && !seen[n] {
			seen[n] = true
			ports = append(ports, n)
		}
	}
	if len(ports) == 0 {
		return []int{443}
	}
	return ports
}

func expandCIDR(cidr string) []string {
	var ips []string
	prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil {
		fmt.Printf("[!] 无效 CIDR: %s\n", cidr)
		return nil
	}
	prefix = prefix.Masked()
	if prefix.Addr().Is6() {
		fmt.Printf("[-] 跳过 IPv6 网段: %s\n", cidr)
		return nil
	}
	if prefix.Bits() >= 31 {
		for addr := prefix.Addr(); prefix.Contains(addr); addr = addr.Next() {
			ips = append(ips, addr.String())
		}
	} else {
		last := broadcastAddr(prefix)
		for addr := prefix.Addr().Next(); addr != last; addr = addr.Next() {
			ips = append(ips, addr.String())
		}
	}
	return ips
}

func broadcastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	hostBits := 32 - p.Bits()
	var mask uint32
	if hostBits >= 32 {
		mask = 0xffffffff
	} else {
		mask = (1 << hostBits) - 1
	}
	netUint := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	last := netUint | mask
	return netip.AddrFrom4([4]byte{byte(last >> 24), byte(last >> 16), byte(last >> 8), byte(last)})
}

func fetchJSON(url string, out interface{}) error {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

func fetchRIPE(asn string) []string {
	url := fmt.Sprintf("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS%s", asn)
	var data struct {
		Data struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	if err := fetchJSON(url, &data); err != nil {
		fmt.Printf("[!] RIPE API 获取失败: %v\n", err)
		return nil
	}
	var cidrs []string
	for _, p := range data.Data.Prefixes {
		if p.Prefix != "" && !strings.Contains(p.Prefix, ":") {
			cidrs = append(cidrs, p.Prefix)
		}
	}
	return cidrs
}

func fetchBGPView(asn string) []string {
	url := fmt.Sprintf("https://api.bgpview.io/asn/%s/prefixes", asn)
	var data struct {
		Data struct {
			IPv4Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"ipv4_prefixes"`
		} `json:"data"`
	}
	if err := fetchJSON(url, &data); err != nil {
		fmt.Printf("[!] BGPView API 获取失败: %v\n", err)
		return nil
	}
	var cidrs []string
	for _, p := range data.Data.IPv4Prefixes {
		if p.Prefix != "" {
			cidrs = append(cidrs, p.Prefix)
		}
	}
	return cidrs
}

func getIPsFromASN(asn string, log func(string, ...interface{})) []string {
	log("[*] 正在自动查询并拉取 AS%s 的网段信息...", asn)
	cidrs := fetchRIPE(asn)
	if len(cidrs) == 0 {
		cidrs = fetchBGPView(asn)
	}
	var ips []string
	for _, c := range cidrs {
		ips = append(ips, expandCIDR(c)...)
	}
	return ips
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func isAllDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

func parseTargetsRec(inputStr string, seenFiles map[string]bool, log func(string, ...interface{})) []netip.Addr {
	raw := regexp.MustCompile(`[\s,，]+`).Split(strings.TrimSpace(inputStr), -1)
	var allIPs []netip.Addr

	for _, item := range raw {
		if item == "" {
			continue
		}
		if strings.HasSuffix(item, ".txt") && fileExists(item) {
			if seenFiles[item] {
				continue
			}
			seenFiles[item] = true
			content, err := os.ReadFile(item)
			if err != nil {
				log("[-] 读取文件失败: %s: %v", item, err)
				continue
			}
			allIPs = append(allIPs, parseTargetsRec(string(content), seenFiles, log)...)
			log("[+] 从文件 [%s] 加载目标", item)
			continue
		}

		if addr, err := netip.ParseAddr(item); err == nil && addr.Is4() {
			allIPs = append(allIPs, addr)
			log("[+] 识别为 IP [%s]", item)
			continue
		}

		if prefix, err := netip.ParsePrefix(item); err == nil {
			if prefix.Addr().Is6() {
				log("[-] 跳过 IPv6 网段: %s", item)
				continue
			}
			expanded := expandCIDR(item)
			if len(expanded) > 0 {
				for _, s := range expanded {
					if a, err := netip.ParseAddr(s); err == nil {
						allIPs = append(allIPs, a)
					}
				}
				log("[+] 识别为 IP/网段 [%s]，展开出 %d 个地址", item, len(expanded))
			}
			continue
		}

		asn := strings.ToUpper(item)
		asn = strings.ReplaceAll(asn, "AS", "")
		if asn != "" && isAllDigits(asn) {
			ips := getIPsFromASN(asn, log)
			log("[+] AS%s 解析完成，提取出 %d 个待测 IPv4 地址。", asn, len(ips))
			for _, s := range ips {
				if a, err := netip.ParseAddr(s); err == nil {
					allIPs = append(allIPs, a)
				}
			}
		} else {
			log("[-] 无法识别的目标格式: %s", item)
		}
	}
	return allIPs
}

func parseTargets(inputStr string, log func(string, ...interface{})) []netip.Addr {
	seenFiles := make(map[string]bool)
	allIPs := parseTargetsRec(inputStr, seenFiles, log)
	unique := make(map[netip.Addr]bool)
	var ips []netip.Addr
	for _, ip := range allIPs {
		if !unique[ip] {
			unique[ip] = true
			ips = append(ips, ip)
		}
	}
	log("[+] 所有目标汇总去重后，共有 %d 个待测 IP 地址。", len(ips))
	return ips
}

func latin1ToString(raw []byte) string {
	var sb strings.Builder
	sb.Grow(len(raw))
	for _, b := range raw {
		sb.WriteRune(rune(b))
	}
	return strings.ToLower(sb.String())
}

func matchDomainInCert(sniDomain string, cert *x509.Certificate) bool {
	sniDomain = strings.ToLower(sniDomain)
	certStr := latin1ToString(cert.Raw)

	if strings.Contains(certStr, sniDomain) {
		return true
	}

	parts := strings.Split(sniDomain, ".")
	if len(parts) >= 2 {
		mainDomain := strings.Join(parts[len(parts)-2:], ".")
		wildcardDomain := "*." + mainDomain
		if strings.Contains(certStr, mainDomain) || strings.Contains(certStr, wildcardDomain) {
			return true
		}
	}

	if strings.Contains(sniDomain, "cloudflare") && strings.Contains(certStr, "cloudflare") {
		return true
	}

	return false
}

func dialWithRetry(ip string, port int, timeout time.Duration) (net.Conn, error) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	for attempt := 0; attempt < 2; attempt++ {
		dialer := net.Dialer{Timeout: timeout}
		conn, err := dialer.Dial("tcp", addr)
		if err == nil {
			return conn, nil
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() && attempt == 0 {
			continue
		}
		return nil, err
	}
	return nil, fmt.Errorf("dial %s timeout", addr)
}

func checkTLS(t Target, sni string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := dialWithRetry(t.IP.String(), t.Port, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	})
	tlsConn.SetDeadline(time.Now().Add(timeout))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return false
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return false
	}
	return matchDomainInCert(sni, state.PeerCertificates[0])
}

func checkHTTP(t Target, host string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := dialWithRetry(t.IP.String(), t.Port, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	})
	tlsConn.SetDeadline(time.Now().Add(timeout))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return false
	}

	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", host)
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return false
	}

	buf := make([]byte, 1024)
	n, err := tlsConn.Read(buf)
	if err != nil && err != io.EOF {
		return false
	}
	if n == 0 {
		return false
	}

	resp := strings.ToLower(string(buf[:n]))
	hasRedirect := strings.Contains(resp, "http/1.1 301") || strings.Contains(resp, "http/1.1 302")
	hasLocation := strings.Contains(resp, "location:")
	return hasRedirect && hasLocation
}

func filterByResult(items []Target, results []bool) []Target {
	var out []Target
	for i, ok := range results {
		if ok {
			out = append(out, items[i])
		}
	}
	return out
}

type validateProbe struct {
	OK   bool `json:"ok"`
	Exit *struct {
		Country        string `json:"country"`
		City           string `json:"city"`
		Asn            int    `json:"asn"`
		AsOrganization string `json:"asOrganization"`
	} `json:"exit"`
}

func validateProxy(t Target) string {
	url := fmt.Sprintf(validateURL, t.IP.String(), strconv.Itoa(t.Port))
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return t.String() + "#timeout"
	}
	req.Header.Set("User-Agent", validateUserAgent)
	resp, err := defaultHTTPClient.Do(req)
	if err != nil {
		return t.String() + "#timeout"
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return t.String() + "#timeout"
	}
	var data struct {
		Success      bool                     `json:"success"`
		ProbeResults map[string]validateProbe `json:"probe_results"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return t.String() + "#timeout"
	}
	if !data.Success {
		return t.String() + "#timeout"
	}
	for _, key := range []string{"ipv4", "ipv6"} {
		if pr, ok := data.ProbeResults[key]; ok && pr.OK && pr.Exit != nil {
			e := pr.Exit
			if e.Country != "" {
				return t.String() + "#" + e.Country
			}
			return t.String() + "#timeout"
		}
	}
	return t.String() + "#timeout"
}

func runValidate(items []Target, concurrency int) []string {
	results := make([]string, len(items))
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	for i, t := range items {
		wg.Add(1)
		go func(i int, t Target) {
			defer wg.Done()
			sem <- struct{}{}
			results[i] = validateProxy(t)
			<-sem
		}(i, t)
	}
	wg.Wait()
	var out []string
	for _, r := range results {
		if !strings.HasSuffix(r, "#timeout") {
			out = append(out, r)
		}
	}
	return out
}

func runBatched(items []Target, fn func(Target) bool, concurrency int, stage int, onProgress func(Progress)) []bool {
	results := make([]bool, len(items))
	var wg sync.WaitGroup
	var completed atomic.Int64
	var passed atomic.Int64
	total := int64(len(items))
	sem := make(chan struct{}, concurrency)

	step := total / 10
	if step < 1 {
		step = 1
	}
	var progressMu sync.Mutex
	var lastReported int64

	for i, t := range items {
		wg.Add(1)
		go func(i int, t Target) {
			defer wg.Done()
			sem <- struct{}{}
			ok := fn(t)
			results[i] = ok
			<-sem
			if ok {
				passed.Add(1)
			}
			done := completed.Add(1)
			if onProgress != nil {
				progressMu.Lock()
				if done%step == 0 || done == total {
					if done > lastReported {
						lastReported = done
						progressMu.Unlock()
						onProgress(Progress{Stage: stage, Done: done, Total: total, Passed: int(passed.Load())})
					} else {
						progressMu.Unlock()
					}
				} else {
					progressMu.Unlock()
				}
			}
		}(i, t)
	}
	wg.Wait()
	return results
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type addrTag struct {
	ip   netip.Addr
	port int
}

func parseAddrTag(line string) addrTag {
	hashIdx := strings.IndexByte(line, '#')
	addr := line
	if hashIdx >= 0 {
		addr = line[:hashIdx]
	}
	idx := strings.LastIndexByte(addr, ':')
	if idx < 0 {
		if ip, err := netip.ParseAddr(addr); err == nil {
			return addrTag{ip: ip, port: 443}
		}
		return addrTag{}
	}
	ip, err := netip.ParseAddr(addr[:idx])
	if err != nil {
		return addrTag{}
	}
	port := 443
	if n, err := strconv.Atoi(addr[idx+1:]); err == nil {
		port = n
	}
	return addrTag{ip: ip, port: port}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func filepathJoin(dir, name string) string {
	return strings.TrimRight(dir, `/\`) + string(os.PathSeparator) + name
}

func Scan(ctx context.Context, targetInput, portsInput string, cfg Config, onProgress func(Progress)) (*Result, error) {
	s := &scannerImpl{cfg: cfg}

	concurrency := s.getConcurrency()

	ports := parsePorts(portsInput)
	s.log("[*] 目标输入: %s | 端口列表: %v", targetInput, ports)

	ips := parseTargets(targetInput, s.log)
	if len(ips) == 0 {
		return nil, fmt.Errorf("未能获取到任何待测 IP")
	}
	if len(ips) > 50000 {
		s.log("[!] 待测 IP 超过 50000 个 (%d)，继续可能超时。建议使用更小的网段。", len(ips))
	}

	targets := make([]Target, 0, len(ips)*len(ports))
	for _, ip := range ips {
		for _, p := range ports {
			targets = append(targets, Target{IP: ip, Port: p})
		}
	}
	s.log("[*] 解析完成：%d 个 IP × %d 个端口 %v = 共有 %d 个连接目标。", len(ips), len(ports), ports, len(targets))

	cfSni1 := cfg.CFSni1
	if cfSni1 == "" {
		cfSni1 = "www.cloudflare.com"
	}
	cfHostTest := cfg.CFHostTest
	if cfHostTest == "" {
		cfHostTest = "crypto.cloudflare.com"
	}

	s.log("\n[1/3 第一阶段 TLS 探测] 开始测试，共 %d 个目标 (IP:端口组合)，分批调度每批 %d，并发 %d...", len(targets), stage1BatchSize, concurrency)
	pass1 := runStage1(ctx, targets, cfSni1, concurrency, onProgress)
	s.log("[+] 第一阶段完成！匹配 CF 证书保留目标: %d 个\n", len(pass1))

	if len(pass1) == 0 {
		return nil, fmt.Errorf("未发现匹配 Cloudflare 证书的 IP。请确认目标属于 Cloudflare IP 段（如 AS206300、AS209242、154.17.0.0/24 等）")
	}

	s.log("[2/3 第二阶段 HTTP 校验] 正在快速校验 %d 个候选目标...", len(pass1))
	res2 := runBatched(pass1, func(t Target) bool {
		return checkHTTP(t, cfHostTest, Stage2Timeout)
	}, concurrency, 2, onProgress)
	pass2 := filterByResult(pass1, res2)
	s.log("[+] 第二阶段完成！可用 301 重定向目标: %d 个\n", len(pass2))

	if len(pass2) == 0 {
		return nil, fmt.Errorf("候选 IP 均未返回 301 重定向，未能通过第二阶段校验")
	}

	finalItems := pass2
	if strings.TrimSpace(cfg.CustomDomain) != "" {
		domain := strings.TrimSpace(cfg.CustomDomain)
		s.log("[3/3 第三阶段自定义域名校验] 正在校验域名 %s...", domain)
		res3 := runBatched(pass2, func(t Target) bool {
			return checkTLS(t, domain, Stage3Timeout)
		}, concurrency, 3, onProgress)
		finalItems = filterByResult(pass2, res3)
		s.log("[+] 第三阶段完成！支持自定义托管域名的优选反代 IP: %d 个", len(finalItems))
	} else {
		s.log("[3/3] 未检测到 CUSTOM_CF_DOMAIN，自动跳过第三阶段。")
	}

	sort.Slice(finalItems, func(i, j int) bool {
		a, b := finalItems[i], finalItems[j]
		if c := a.IP.Compare(b.IP); c != 0 {
			return c < 0
		}
		return a.Port < b.Port
	})

	s.log("\n==================== 扫描结束 ====================")
	s.log("最终有效目标总数: %d", len(finalItems))

	res := &Result{FinalItems: finalItems, Stage1N: len(pass1), Stage2N: len(pass2)}

	if cfg.Validate && len(finalItems) > 0 {
		s.log("[+] 正在通过外部 API 校验目标并获取国家信息...")
		validated := runValidate(finalItems, validateConcurrency)
		sort.Slice(validated, func(i, j int) bool {
			a := parseAddrTag(validated[i])
			b := parseAddrTag(validated[j])
			if c := a.ip.Compare(b.ip); c != 0 {
				return c < 0
			}
			return a.port < b.port
		})
		res.Validated = validated
		s.log("[+] API 校验完成，有效 %d 个（已剔除超时）。", len(validated))
	}

	outputDir := cfg.OutputDir
	if outputDir == "" {
		outputDir = "check/history"
	}
	if !filepathIsAbs(outputDir) {
		exe, _ := os.Executable()
		if exe != "" {
			outputDir = filepathJoin(filepathBaseDir(exe), outputDir)
		}
	}
	cleanName := regexp.MustCompile(`[^\w\.-]`).ReplaceAllString(strings.Split(targetInput, ",")[0], "_")
	cleanName = strings.TrimSpace(cleanName)
	if strings.HasSuffix(strings.ToLower(cleanName), ".txt") {
		cleanName = strings.TrimSuffix(filepathBase(cleanName), ".txt")
	}
	if cleanName == "" {
		cleanName = "scan_result"
	}
	outputFilename := cleanName + ".txt"
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return res, err
	}
	outputPath := filepathJoin(outputDir, outputFilename)
	f, err := os.Create(outputPath)
	if err != nil {
		return res, err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, t := range finalItems {
		fmt.Fprintf(w, "%s:%d\n", t.IP.String(), t.Port)
	}
	w.Flush()
	res.OutputPath = outputPath
	s.log("[+] 最终结果已排序保存至：%s (格式为 IP:PORT)", outputPath)
	return res, nil
}

func filepathBase(p string) string {
	idx := strings.LastIndexAny(p, `/\`)
	if idx >= 0 {
		return p[idx+1:]
	}
	return p
}

func filepathBaseDir(p string) string {
	idx := strings.LastIndexAny(p, `/\`)
	if idx >= 0 {
		return p[:idx]
	}
	return "."
}

func filepathIsAbs(p string) bool {
	return strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\`) || len(p) >= 3 && p[1] == ':'
}

func runStage1(ctx context.Context, targets []Target, sni string, concurrency int, onProgress func(Progress)) []Target {
	total := len(targets)
	var completed, passed atomic.Int64
	var mu sync.Mutex
	var passedItems []Target

	step := total / 10
	if step < 1 {
		step = 1
	}
	var lastPrinted atomic.Int64

	startTime := time.Now()

	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(t Target) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			ok := checkTLS(t, sni, Stage1Timeout)
			<-sem
			done := completed.Add(1)
			if ok {
				mu.Lock()
				passedItems = append(passedItems, t)
				mu.Unlock()
				passed.Add(1)
			}
			curStep := done / int64(step)
			if curStep > lastPrinted.Load() || done == int64(total) {
				lastPrinted.Store(curStep)
				p := passed.Load()
				eta := formatETA(startTime, done, int64(total))
				if onProgress != nil {
					onProgress(Progress{Stage: 1, Done: done, Total: int64(total), Passed: int(p), ETA: eta})
				} else {
					fmt.Printf("[1/3 进度] %d/%d (%.1f%%) | 当前通过: %d 个 | 预计剩余: %s\n",
						done, total, float64(done)/float64(total)*100, p, eta)
				}
			}
		}(t)
	}
	wg.Wait()
	return passedItems
}

func formatETA(start time.Time, done, total int64) string {
	if done <= 0 {
		return "计算中..."
	}
	elapsed := time.Since(start)
	remaining := time.Duration(float64(elapsed) / float64(done) * float64(total-done))
	remaining = remaining.Round(time.Second)
	if remaining < time.Second {
		remaining = time.Second
	}
	if remaining > 24*time.Hour {
		return ">24h"
	}
	return remaining.String()
}
