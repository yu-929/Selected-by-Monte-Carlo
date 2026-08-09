package engine

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"

	"trace/internal/geo"
	"trace/internal/model"
	"trace/internal/tracer"
)

// Engine 串联 tracert、ASN 匹配与线路识别
type Engine struct {
	PrefixIndex *geo.PrefixIndex
	MMDB        *geo.MMDB
	Locations   *geo.Locations

	SkipTracert bool
	Workers     int
	TracerCfg   tracer.Config
	Log         func(format string, args ...interface{})
}

// Result 单目标扫描结果（含格式化行）
type Result struct {
	model.TargetResult
	RawLine string // CSV/输出行
}

// NewEngine 使用已就绪的依赖文件路径构建引擎
func NewEngine(assets map[string]string, log func(string, ...interface{})) (*Engine, error) {
	if log == nil {
		log = func(f string, a ...interface{}) { fmt.Printf(f+"\n", a...) }
	}
	e := &Engine{Log: log}

	// asn_prefixes.json
	if p := assets["asn_prefixes.json"]; p != "" {
		idx, err := geo.LoadPrefixes(p)
		if err != nil {
			log("[-] 加载 asn_prefixes.json 失败: %v", err)
		} else {
			e.PrefixIndex = idx
		}
	}
	// GeoLite2-ASN.mmdb
	if p := assets["GeoLite2-ASN.mmdb"]; p != "" {
		mmdb, err := geo.OpenMMDB(p)
		if err != nil {
			log("[-] 加载 GeoLite2-ASN.mmdb 失败: %v", err)
		} else {
			e.MMDB = mmdb
		}
	}
	// locations.json
	if p := assets["locations.json"]; p != "" {
		loc, err := geo.LoadLocations(p)
		if err != nil {
			log("[-] 加载 locations.json 失败: %v", err)
		} else {
			e.Locations = loc
		}
	}
	return e, nil
}

// Close 释放资源
func (e *Engine) Close() {
	if e.MMDB != nil {
		e.MMDB.Close()
	}
}

// ResolveTarget 将目标解析为 IPv4 地址与端口（支持 "IP"、"IP:port"、域名、域名:port）
// 返回 (ip, port, err)，port 为 0 表示未指定。
func (e *Engine) ResolveTarget(target string) (string, int, error) {
	target = strings.TrimSpace(target)
	port := 0

	// 分离 host 与端口
	host := target
	if h, p, err := net.SplitHostPort(target); err == nil {
		host = h
		if n, perr := strconv.Atoi(p); perr == nil && n > 0 && n < 65536 {
			port = n
		}
	}

	// 直接 IPv4
	if ip, err := netip.ParseAddr(host); err == nil && ip.Is4() {
		return ip.String(), port, nil
	}
	// 域名解析为 IPv4
	addrs, err := net.LookupIP(host)
	if err != nil {
		return "", 0, fmt.Errorf("无法解析目标 %s: %v", target, err)
	}
	for _, a := range addrs {
		if v4 := a.To4(); v4 != nil {
			return v4.String(), port, nil
		}
	}
	return "", 0, fmt.Errorf("目标 %s 无 IPv4 地址", target)
}

// Scan 对单个 IP 执行完整扫描。port 为目标端口（0 表示用引擎默认端口做延迟测速）。
func (e *Engine) Scan(ctx context.Context, ip string) *Result {
	res := &Result{}
	res.Target = ip
	res.IP = ip

	// 1. tracert（可跳过）
	if !e.SkipTracert {
		hops, err := tracer.Trace(ctx, ip, e.TracerCfg)
		if err != nil {
			e.Log("  [-] %s tracert 失败: %v", ip, err)
		} else {
			res.Hops = hops
		}
	}

	// 2. 逐跳 ASN 识别 + 路径特征线路检测
	targetASN, targetOrg, targetLine, targetISP := e.Identify(ip)
	res.DetectedASN = targetASN

	pathLine, pathISP := detectPathLine(res.Hops, e.Identify)

	// 线路优先级：目标自身命中特征 ASN > 路径检测 > 兜底 ISP 名
	switch {
	case targetLine != "":
		res.DetectedLine = targetLine
		res.DetectedISP = targetISP
	case pathLine != "":
		res.DetectedLine = pathLine
		res.DetectedISP = pathISP
	}

	// 3. 地区信息：优先本地 org 机场码匹配，失败后在线查询
	country, city, onlineISP, _, onlineASN := e.locationFor(ctx, ip, targetOrg)
	res.Country = country
	res.City = city
	// 在线查询能补充更准确的运营商（isp）与 ASN
	if res.DetectedISP == "" && onlineISP != "" {
		res.DetectedISP = onlineISP
	}
	if res.DetectedASN == "" && onlineASN != "" {
		res.DetectedASN = onlineASN
	}
	// 线路仅用于识别特征 ASN；非特征目标不显示线路
	if res.DetectedLine == "" {
		res.DetectedLine = "-"
	}

	// 组装输出行
	res.RawLine = e.formatLine(res)
	return res
}

// detectPathLine 在 tracert 路径中检测特征 ASN，返回命中线路与运营商。
// 同时把每跳的 ASN/组织/线路信息回填到 hops 供展示。
// 按优先级取最高等级线路（CN2 GIA > CN2 > 163 > CUII > 169 > CMI > CMNET 等）。
func detectPathLine(hops []model.Hop, identify func(ip string) (asn, org, line, isp string)) (line, isp string) {
	// 特征 ASN 优先级（下标越小越优先）
	priority := []string{
		"AS4809",  // CN2 GIA/GT
		"AS4812",  // CN2
		"AS4134",  // 163骨干
		"AS9929",  // CUII
		"AS4837",  // 169骨干
		"AS58807", // CMIN2
		"AS58453", // CMI
		"AS9808",  // CMNET
		"AS4538",  // CERNET
		"AS7497",  // CSTNET
	}
	rank := make(map[string]int, len(priority))
	for i, a := range priority {
		rank[a] = i
	}

	bestRank := len(priority)
	var bestLine, bestISP string
	seen := make(map[string]bool)

	for i := range hops {
		h := &hops[i]
		if h.IP == "" || seen[h.IP] {
			continue
		}
		asn, org, lineStr, ispStr := identify(h.IP)
		if asn != "" {
			// 回填 hop 的识别信息（供展示）
			h.ASN = asn
			h.Org = org
			h.Isp = ispStr
			h.Line = lineStr
			seen[h.IP] = true
		}
		if lineStr == "" {
			continue
		}
		if r, ok := rank[asn]; ok && r < bestRank {
			bestRank = r
			bestLine = lineStr
			bestISP = ispStr
		}
	}
	return bestLine, bestISP
}

// Identify 识别 IP 的 ASN、组织、特征线路与运营商。
// 命中特征 ASN 时返回线路；否则 line/isp 返回空串（由调用方决定兜底文案）。
func (e *Engine) Identify(ip string) (asn, org, line, isp string) {
	// 优先 mmdb
	if e.MMDB != nil {
		asn, org = e.MMDB.Lookup(ip)
	}
	// 其次前缀索引
	if asn == "" && e.PrefixIndex != nil {
		if a, err := netip.ParseAddr(ip); err == nil {
			asn = e.PrefixIndex.Lookup(a)
		}
	}
	if asn != "" {
		if li := geo.MatchFeature(asn); li.Line != "" {
			return asn, org, li.Line, li.ISP
		}
	}
	return asn, org, "", ""
}

// locationFor 尝试获取 IP 的国家城市、运营商、组织与 ASN（在线数据）。
// 优先从 org 名中提取机场码（IATA）匹配本地 locations.json，失败后在线查询。
func (e *Engine) locationFor(ctx context.Context, ip, org string) (country, city, isp, onlineOrg, asn string) {
	// 1. 本地：从 org 名中提取机场码匹配 locations.json
	if e.Locations != nil && org != "" {
		if c, ci := matchIATAFromOrg(e.Locations, org); c != "" {
			return c, ci, "", "", ""
		}
	}
	// 2. 在线查询
	loc := geo.LookupOnline(ctx, ip)
	if loc.Status == "success" {
		return loc.Country, loc.City, loc.Isp, loc.Org, loc.AS
	}
	return "", "", "", "", ""
}

// matchIATAFromOrg 从组织名中查找 3 字母大写机场码（IATA），匹配 locations.json
func matchIATAFromOrg(locs *geo.Locations, org string) (country, city string) {
	if locs == nil {
		return "", ""
	}
	for i := 0; i+3 < len(org); i += 2 {
		// 3 字母大写段，两侧边界非字母或字符串边界
		candidate := org[i : i+3]
		isUpperAlpha := true
		for _, ch := range candidate {
			if ch < 'A' || ch > 'Z' {
				isUpperAlpha = false
				break
			}
		}
		if !isUpperAlpha {
			continue
		}
		// 检查右侧边界
		if i+3 < len(org) && ((org[i+3] >= 'A' && org[i+3] <= 'Z') || (org[i+3] >= '0' && org[i+3] <= '9')) {
			continue
		}
		if c, ci := locs.LookupIATA(candidate); c != "" {
			return ci, c
		}
	}
	return "", ""
}

// formatLine 生成 CSV/文本输出行
func (e *Engine) formatLine(r *Result) string {
	return fmt.Sprintf("%s,%s,%s,%s,%s,%s",
		r.IP, r.DetectedASN, r.DetectedISP, r.DetectedLine,
		r.Country, r.City)
}

// FormatHeader 返回 CSV 表头
func (e *Engine) FormatHeader() string {
	return "IP,ASN,运营商,线路,国家,城市"
}

// HopsSummary 生成 tracert 路径文本（用于展示）
func (e *Engine) HopsSummary(hops []model.Hop) string {
	if len(hops) == 0 {
		return ""
	}
	var sb strings.Builder
	for _, h := range hops {
		if h.IP == "" {
			fmt.Fprintf(&sb, "  %2d  * * *\n", h.TTL)
			continue
		}
		asn, org, line, isp := e.Identify(h.IP)
		lineStr := ""
		if line != "" {
			lineStr = " " + isp + " " + line
		}
		fmt.Fprintf(&sb, "  %2d  %-15s %-12s %s%s%s\n", h.TTL, h.IP, h.Latency, org, asn, lineStr)
	}
	return sb.String()
}

// LoadTargets 从文件加载目标列表（每行一个 IP/域名，支持 # 注释）
func LoadTargets(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	var targets []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line != "" {
			targets = append(targets, line)
		}
	}
	return targets, nil
}

// ConcurrentScan 并发扫描多个目标
func (e *Engine) ConcurrentScan(ctx context.Context, targets []string, workers int, onResult func(*Result)) {
	if workers <= 0 {
		workers = 16
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			ip, _, err := e.ResolveTarget(t)
			if err != nil {
				e.Log("  [-] 跳过无效目标 %s: %v", t, err)
				return
			}
			r := e.Scan(ctx, ip)
			if onResult != nil {
				onResult(r)
			}
		}(t)
	}
	wg.Wait()
}
