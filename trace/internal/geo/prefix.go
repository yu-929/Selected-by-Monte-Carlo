package geo

import (
	"encoding/json"
	"net/netip"
	"os"
	"sort"
	"strings"

	"trace/internal/model"
)

// featureLines 内置特征线路表（与 Trace README 一致）
var featureLines = []model.LineInfo{
	{ASN: "AS4134", ISP: "中国电信", Line: "163骨干"},
	{ASN: "AS4812", ISP: "中国电信", Line: "CN2"},
	{ASN: "AS4809", ISP: "中国电信", Line: "CN2 GIA/GT"},
	{ASN: "AS4837", ISP: "中国联通", Line: "169骨干"},
	{ASN: "AS9929", ISP: "中国联通", Line: "CUII（A网）"},
	{ASN: "AS9808", ISP: "中国移动", Line: "CMNET"},
	{ASN: "AS58453", ISP: "中国移动", Line: "CMI"},
	{ASN: "AS58807", ISP: "中国移动", Line: "CMIN2"},
	{ASN: "AS4538", ISP: "中国教育网", Line: "CERNET"},
	{ASN: "AS7497", ISP: "中国科技网", Line: "CSTNET"},
}

// PrefixIndex 由 asn_prefixes.json 构建的 ASN -> CIDR 前缀索引
type PrefixIndex struct {
	byASN map[string][]netip.Prefix
}

// LoadPrefixes 从 asn_prefixes.json 加载 ASN 路由前缀索引
func LoadPrefixes(path string) (*PrefixIndex, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string][]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	idx := &PrefixIndex{byASN: make(map[string][]netip.Prefix)}
	for asn, cidrs := range raw {
		key := strings.ToUpper(asn)
		if !strings.HasPrefix(key, "AS") {
			key = "AS" + key
		}
		for _, cidr := range cidrs {
			if p, err := netip.ParsePrefix(strings.TrimSpace(cidr)); err == nil {
				idx.byASN[key] = append(idx.byASN[key], p.Masked())
			}
		}
	}
	return idx, nil
}

// Lookup 返回 ip 命中的第一个 ASN（按前缀最长匹配），未命中返回空串
func (idx *PrefixIndex) Lookup(ip netip.Addr) string {
	if idx == nil {
		return ""
	}
	best := ""
	bestBits := -1
	for asn, prefixes := range idx.byASN {
		for _, p := range prefixes {
			if p.Contains(ip) && p.Bits() > bestBits {
				best = asn
				bestBits = p.Bits()
			}
		}
	}
	return best
}

// MatchFeature 将 ASN 映射到特征线路，未命中返回空 LineInfo
func MatchFeature(asn string) model.LineInfo {
	a := strings.ToUpper(asn)
	if !strings.HasPrefix(a, "AS") {
		a = "AS" + a
	}
	for _, li := range featureLines {
		if li.ASN == a {
			return li
		}
	}
	return model.LineInfo{}
}

// AllFeatures 返回全部特征线路表
func AllFeatures() []model.LineInfo {
	return featureLines
}

// 防止 sort 未被使用
var _ = sort.Strings
