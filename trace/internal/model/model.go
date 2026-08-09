package model

// Hop 表示 tracert 单跳节点信息
type Hop struct {
	TTL     int    `json:"ttl"`
	IP      string `json:"ip"`
	ASN     string `json:"asn"`
	Org     string `json:"org"`
	Isp     string `json:"isp"`
	Line    string `json:"line"`
	Latency string `json:"latency"`
	Country string `json:"country"`
	City    string `json:"city"`
}

// TargetResult 表示单个目标的完整扫描结果
type TargetResult struct {
	Target       string `json:"target"`
	IP           string `json:"ip"`
	Hops         []Hop  `json:"hops"`
	DetectedASN  string `json:"detected_asn"`
	DetectedISP  string `json:"detected_isp"`
	DetectedLine string `json:"detected_line"`
	Country      string `json:"country"`
	City         string `json:"city"`
	Latency      string `json:"latency"`
	Download     string `json:"download"`
}

// LineInfo 描述一条特征线路
type LineInfo struct {
	ASN   string `json:"asn"`
	ISP   string `json:"isp"`
	Line  string `json:"line"`
}
