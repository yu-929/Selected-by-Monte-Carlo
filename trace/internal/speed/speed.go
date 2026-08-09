package speed

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// PingTCP 通过 TCP 连接测量延迟（毫秒），失败返回空串
func PingTCP(ctx context.Context, ip string, port int, timeout time.Duration) string {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	d := net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ""
	}
	conn.Close()
	return fmt.Sprintf("%d ms", time.Since(start).Milliseconds())
}

// Download 通过 HTTP 下载测速，返回带宽字符串（Mbps）
func Download(ctx context.Context, url string, timeout time.Duration) string {
	if url == "" {
		return ""
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	start := time.Now()
	var total int64
	buf := make([]byte, 256*1024)
	for {
		n, err := resp.Body.Read(buf)
		total += int64(n)
		if err != nil {
			break
		}
	}
	elapsed := time.Since(start)
	if elapsed <= 0 || total <= 0 {
		return ""
	}
	mbps := float64(total*8) / elapsed.Seconds() / 1e6
	return fmt.Sprintf("%.2f Mbps", mbps)
}

var _ = io.EOF
