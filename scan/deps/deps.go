package deps

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type Asset struct {
	Name    string
	URL     string
	MinSize int64
}

var Assets = []Asset{
	{
		Name:    "GeoLite2-ASN.mmdb",
		URL:     "https://raw.githubusercontent.com/yu-929/Selected-by-Monte-Carlo/main/GeoLite2-ASN.mmdb",
		MinSize: 1 << 20,
	},
	{
		Name:    "asn_prefixes.json",
		URL:     "https://raw.githubusercontent.com/yu-929/Selected-by-Monte-Carlo/main/asn_prefixes.json",
		MinSize: 1 << 10,
	},
	{
		Name:    "locations.json",
		URL:     "https://raw.githubusercontent.com/yu-929/Selected-by-Monte-Carlo/main/locations.json",
		MinSize: 1 << 10,
	},
}

func assetExists(path string, minSize int64) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Size() >= minSize
}

func download(url, dest string) error {
	client := &http.Client{Timeout: 5 * time.Minute}
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
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	tmp := dest + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dest)
}

// CandidateDirs 返回依赖文件可能的存放目录，按优先级排列：
// 1. 环境变量 ASSET_DIR；2. 当前工作目录；3. 可执行文件目录；4. 可执行文件上级目录（仓库主文件夹）。
func CandidateDirs() []string {
	var dirs []string
	seen := make(map[string]bool)
	add := func(d string) {
		if d == "" {
			return
		}
		abs, err := filepath.Abs(d)
		if err != nil {
			abs = d
		}
		if !seen[abs] {
			seen[abs] = true
			dirs = append(dirs, abs)
		}
	}

	if env := os.Getenv("ASSET_DIR"); env != "" {
		add(env)
	}
	if cwd, err := os.Getwd(); err == nil {
		add(cwd)
	}
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		add(exeDir)
		add(filepath.Dir(exeDir))
	}
	add(".")
	return dirs
}

// findExisting 在候选目录中查找已存在的依赖文件，返回第一个命中的完整路径。
func findExisting(candidates []string, a Asset) string {
	for _, d := range candidates {
		p := filepath.Join(d, a.Name)
		if assetExists(p, a.MinSize) {
			return p
		}
	}
	return ""
}

// downloadDir 决定下载到哪个目录：优先 ASSET_DIR，其次当前工作目录，再次可执行文件目录。
func downloadDir(candidates []string) string {
	for _, d := range candidates {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			return d
		}
	}
	return "."
}

// EnsureAssets 检查三个依赖文件，缺失或过小时自动下载。
// 返回每个资产就绪的完整路径；下载失败仅记录日志，不阻断程序。
func EnsureAssets(logf func(format string, args ...interface{})) (map[string]string, error) {
	if logf == nil {
		logf = func(format string, args ...interface{}) { fmt.Printf(format+"\n", args...) }
	}
	candidates := CandidateDirs()
	destDir := downloadDir(candidates)
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return nil, err
	}

	ready := make(map[string]string)
	var failed []string
	for _, a := range Assets {
		if path := findExisting(candidates, a); path != "" {
			ready[a.Name] = path
			continue
		}
		logf("[*] 依赖文件 %s 缺失或过小，自动下载到 %s ...", a.Name, destDir)
		dest := filepath.Join(destDir, a.Name)
		if err := download(a.URL, dest); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", a.Name, err))
			logf("[-] 下载 %s 失败: %v", a.Name, err)
			continue
		}
		ready[a.Name] = dest
		logf("[+] 已下载 %s", a.Name)
	}
	if len(failed) > 0 {
		return ready, fmt.Errorf("依赖文件下载失败: %s", joinComma(failed))
	}
	return ready, nil
}

func joinComma(items []string) string {
	out := ""
	for i, s := range items {
		if i > 0 {
			out += "; "
		}
		out += s
	}
	return out
}
