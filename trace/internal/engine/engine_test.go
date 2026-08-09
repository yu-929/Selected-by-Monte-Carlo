package engine

import (
	"testing"

	"trace/internal/model"
)

// fakeIdentify 根据 IP 返回模拟的 ASN 识别结果
func fakeIdentify(table map[string]string) func(ip string) (asn, org, line, isp string) {
	return func(ip string) (string, string, string, string) {
		asn, ok := table[ip]
		if !ok {
			return "", "", "", ""
		}
		switch asn {
		case "AS4809":
			return asn, "China Telecom", "CN2 GIA/GT", "中国电信"
		case "AS4134":
			return asn, "China Telecom", "163骨干", "中国电信"
		case "AS58453":
			return asn, "China Mobile", "CMI", "中国移动"
		case "AS9929":
			return asn, "China Unicom", "CUII（A网）", "中国联通"
		}
		return asn, "Unknown Org", "", ""
	}
}

func TestDetectPathLine(t *testing.T) {
	table := map[string]string{
		"1.0.0.1": "AS4809",
		"1.0.0.2": "AS4134",
		"1.0.0.3": "AS58453",
		"1.0.0.4": "AS9929",
		"1.0.0.5": "AS13335", // 非特征
	}
	ident := fakeIdentify(table)

	cases := []struct {
		name     string
		hops     []model.Hop
		wantLine string
		wantISP  string
	}{
		{
			name: "空路径",
			hops: []model.Hop{},
		},
		{
			name: "路径无特征ASN",
			hops: []model.Hop{
				{TTL: 1, IP: "1.0.0.5"},
				{TTL: 2, IP: "192.168.1.1"},
			},
		},
		{
			name: "CN2 GIA 优先于 CMI",
			hops: []model.Hop{
				{TTL: 1, IP: "1.0.0.3"},  // CMI
				{TTL: 2, IP: "1.0.0.1"},  // CN2 GIA
				{TTL: 3, IP: "1.0.0.2"},  // 163
			},
			wantLine: "CN2 GIA/GT",
			wantISP:  "中国电信",
		},
		{
			name: "163 优先于 CUII",
			hops: []model.Hop{
				{TTL: 1, IP: "1.0.0.4"}, // CUII
				{TTL: 2, IP: "1.0.0.2"}, // 163
			},
			wantLine: "163骨干",
			wantISP:  "中国电信",
		},
		{
			name: "未知节点忽略",
			hops: []model.Hop{
				{TTL: 1, IP: ""},       // 超时节点
				{TTL: 2, IP: "1.0.0.3"}, // CMI
			},
			wantLine: "CMI",
			wantISP:  "中国移动",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hops := make([]model.Hop, len(c.hops))
			copy(hops, c.hops)
			line, isp := detectPathLine(hops, ident)
			if line != c.wantLine || isp != c.wantISP {
				t.Errorf("detectPathLine = (%q, %q), want (%q, %q)", line, isp, c.wantLine, c.wantISP)
			}
		})
	}
}

func TestDetectPathLineBackfill(t *testing.T) {
	table := map[string]string{"1.0.0.1": "AS4809"}
	ident := fakeIdentify(table)
	hops := []model.Hop{{TTL: 1, IP: "1.0.0.1"}}
	detectPathLine(hops, ident)
	if hops[0].ASN != "AS4809" {
		t.Errorf("hop ASN 未回填: %q", hops[0].ASN)
	}
	if hops[0].Line != "CN2 GIA/GT" {
		t.Errorf("hop Line 未回填: %q", hops[0].Line)
	}
}
