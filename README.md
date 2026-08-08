# Cloudflare 优选 IP 扫描器

高性能 Go 实现，基于 TLS 握手 + HTTP 301 校验，快速筛选出可用的 Cloudflare 优选 IP。

## 组件

| 组件 | 用途 |
|------|------|
| `win-scan` | 命令行扫描器，输出结果到文件 |
| `win-web`  | Web 管理界面，可视化扫描和结果查看 |

## 一键安装

```bash
# 安装 CLI 扫描器
sudo curl -L -o /usr/local/bin/win-scan https://github.com/your/repo/releases/latest/download/win-scan && sudo chmod +x /usr/local/bin/win-scan

# 安装 Web 管理界面
sudo curl -L -o /usr/local/bin/win-web https://github.com/your/repo/releases/latest/download/win-web && sudo chmod +x /usr/local/bin/win-web
```

## 使用

### CLI 扫描

```bash
# 按 ASN 扫描
win-scan -target AS206300 -ports "443,13720"

# 按 CIDR 网段扫描
win-scan -target 16.162.0.0/16 -ports "443,13720"

# 自定义域名（第三阶段校验）
win-scan -target AS206300 -ports 443 -domain example.com

# 指定并发数
win-scan -target AS206300 -ports 443 -concurrency 5000
```

### Web 管理界面

```bash
# 启动（默认端口 8080）
win-web

# 指定端口
win-web 3000

# 或通过环境变量
PORT=3000 win-web
```

打开浏览器访问 `http://你的IP:端口`。

### 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `TARGET_LIST` | 默认目标（ASN / CIDR / IP） | `AS206300` |
| `ASN_LIST` | 同 TARGET_LIST（后备） | - |
| `CUSTOM_CF_DOMAIN` | 自定义 CF 域名，启用第三阶段校验 | - |
| `OUTPUT_DIR` | 结果输出目录 | `check/history` |
| `SCAN_CONCURRENCY` | 扫描并发数 | `2000` |
| `PORT` | Web 服务端口 | `8080` |

## 卸载

```bash
# 删除 CLI 扫描器
sudo rm -f /usr/local/bin/win-scan

# 删除 Web 管理界面
sudo rm -f /usr/local/bin/win-web

# 清理扫描结果（可选）
rm -rf ~/check/history
```

## 从源码构建

```bash
git clone <your-repo>
cd win

# 构建 CLI
go build -ldflags="-s -w" -o win-scan main.go

# 构建 Web
go build -ldflags="-s -w" -o win-web ./web/main.go
```

## 扫描流程

1. **第一阶段（TLS 探测）** — 并发 TLS 握手，匹配 Cloudflare 证书
2. **第二阶段（HTTP 校验）** — 检查 301/302 重定向 + Location 头
3. **第三阶段（自定义域名校验）** — 可选，验证目标域名是否支持自定义托管