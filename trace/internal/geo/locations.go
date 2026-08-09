package geo

import (
	"encoding/json"
	"os"
	"strings"
)

type locationEntry struct {
	IATA   string  `json:"iata"`
	Lat    float64 `json:"lat"`
	Lon    float64 `json:"lon"`
	Cca2   string  `json:"cca2"`
	Region string  `json:"region"`
	City   string  `json:"city"`
}

// Locations 封装 locations.json 查询
type Locations struct {
	byIATA map[string]locationEntry
}

// LoadLocations 加载机场位置数据库
func LoadLocations(path string) (*Locations, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var entries []locationEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	l := &Locations{byIATA: make(map[string]locationEntry)}
	for _, e := range entries {
		l.byIATA[strings.ToUpper(e.IATA)] = e
	}
	return l, nil
}

// LookupIATA 按机场代码查找城市与所在国代码
func (l *Locations) LookupIATA(iata string) (city, country string) {
	if l == nil {
		return "", ""
	}
	if e, ok := l.byIATA[strings.ToUpper(iata)]; ok {
		return e.City, e.Cca2
	}
	return "", ""
}
