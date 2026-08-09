package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"

	"winscan/deps"
	"winscan/scanner"
)

func main() {
	if _, err := deps.EnsureAssets(func(format string, args ...interface{}) {
		fmt.Printf(format+"\n", args...)
	}); err != nil {
		fmt.Printf("[!] 依赖文件自动下载未完全成功: %v\n", err)
	}

	targetInput := flag.String("target", "", "目标列表：ASN / CIDR / IP / 文件路径，逗号分隔")
	portsInput := flag.String("ports", "443", "端口列表，逗号分隔")
	concurrency := flag.Int("concurrency", 0, "并发数（默认自动）")
	domain := flag.String("domain", "", "自定义 CF 域名（留空跳过第三阶段）")
	flag.Parse()

	if *targetInput == "" {
		*targetInput = os.Getenv("TARGET_LIST")
	}
	if *targetInput == "" {
		*targetInput = os.Getenv("ASN_LIST")
	}
	if *targetInput == "" {
		flag.Usage()
		fmt.Fprintln(os.Stderr, "\n错误：必须指定目标，请使用 -target 指定 ASN / CIDR / IP / 文件路径")
		os.Exit(2)
	}

	cfg := scanner.Config{
		Concurrency:  *concurrency,
		CustomDomain: *domain,
		OutputDir:    os.Getenv("OUTPUT_DIR"),
		Validate:     true,
	}
	if cfg.CustomDomain == "" {
		cfg.CustomDomain = os.Getenv("CUSTOM_CF_DOMAIN")
	}
	if env := os.Getenv("SCAN_CONCURRENCY"); env != "" {
		if n, err := strconv.Atoi(env); err == nil && n > 0 {
			cfg.Concurrency = n
		}
	}

	_, err := scanner.Scan(context.Background(), *targetInput, *portsInput, cfg, nil)
	if err != nil {
		fmt.Printf("[-] %v\n", err)
		os.Exit(1)
	}
}
