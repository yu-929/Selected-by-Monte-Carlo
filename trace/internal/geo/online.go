package geo

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// OnlineLoc 在线 IP 定位结果
type OnlineLoc struct {
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"region"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	Isp         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	Status      string  `json:"status"`
	Query       string  `json:"query"`
	Message     string  `json:"message"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
}

// LookupOnline 通过 ip-api.com 在线查询 IP 地理位置（免费接口，限速 45 次/分钟）。
// 返回国家（中文）、城市（中文）与原始数据。失败返回空结构。
func LookupOnline(ctx context.Context, ip string) OnlineLoc {
	var loc OnlineLoc
	url := fmt.Sprintf("http://ip-api.com/json/%s?lang=zh-CN", ip)
	client := &http.Client{Timeout: 8 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return loc
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return loc
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return loc
	}
	if err := json.NewDecoder(resp.Body).Decode(&loc); err != nil {
		return loc
	}
	return loc
}
