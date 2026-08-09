package geo

import (
	"net"

	"github.com/oschwald/maxminddb-golang"
)

// MMDB 封装 GeoLite2-ASN.mmdb 查询
type MMDB struct {
	reader *maxminddb.Reader
	path   string
}

type asnRecord struct {
	ASN         uint32 `maxminddb:"autonomous_system_number"`
	Org         string `maxminddb:"autonomous_system_organization"`
}

// OpenMMDB 打开 mmdb 文件
func OpenMMDB(path string) (*MMDB, error) {
	reader, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	return &MMDB{reader: reader, path: path}, nil
}

// Close 关闭数据库
func (m *MMDB) Close() error {
	if m != nil && m.reader != nil {
		return m.reader.Close()
	}
	return nil
}

// Lookup 返回 IP 对应的 ASN 号与组织名
func (m *MMDB) Lookup(ipStr string) (asn string, org string) {
	if m == nil || m.reader == nil {
		return "", ""
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", ""
	}
	var rec asnRecord
	if err := m.reader.Lookup(ip, &rec); err != nil {
		return "", ""
	}
	if rec.ASN == 0 {
		return "", ""
	}
	return "AS" + uintToStr(rec.ASN), rec.Org
}

func uintToStr(v uint32) string {
	if v == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
