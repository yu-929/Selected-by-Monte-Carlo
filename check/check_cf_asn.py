import asyncio
import ssl
import sys
import os
import resource
import urllib.request
import json
import ipaddress
import subprocess
from concurrent.futures import ThreadPoolExecutor

# ==================== 极限性能配置区域 ====================
DEFAULT_ASNS = os.getenv("ASN_LIST", "AS13335")
CUSTOM_CF_DOMAIN = os.getenv("CUSTOM_CF_DOMAIN", "example.com")
MAX_IPS = 10000

# 阶段 1：TLS 粗筛 (www.cloudflare.com)
CF_SNI_1 = "www.cloudflare.com"
STAGE1_CONCURRENCY = 1000   # 1000 线程/并发
STAGE1_TIMEOUT = 1.0       # 1秒握手超时

# 阶段 2：HTTP 并发限制
STAGE2_CONCURRENCY = 20    # 同时最多 20 个 curl 请求

# 阶段 2：HTTP 验证 Host (crypto.cloudflare.com)
CF_HOST_TEST = "crypto.cloudflare.com"

# 突破 Linux 系统文件句柄限制 (防止 Too many open files 报错)
try:
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
    print(f"[*] 系统 Socket 文件描述符上限已提升至: {hard}", flush=True)
except Exception as e:
    print(f"[!] 提升文件描述符失败 (若非 Linux 环境可忽略): {e}", flush=True)

custom_executor = ThreadPoolExecutor(max_workers=STAGE1_CONCURRENCY)
# =========================================================

def expand_cidrs(cidr_list):
    """将 CIDR 列表展开为 IPv4 地址列表，限制 MAX_IPS 个"""
    ip_list = []
    for cidr in cidr_list:
        if len(ip_list) >= MAX_IPS:
            print(f"[!] 达到最大 IP 数限制 ({MAX_IPS})，截断", flush=True)
            break
        cidr = cidr.strip()
        if not cidr:
            continue
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if net.prefixlen >= 31:
                for ip in net:
                    ip_list.append(str(ip))
                    if len(ip_list) >= MAX_IPS:
                        break
            else:
                for ip in net.hosts():
                    ip_list.append(str(ip))
                    if len(ip_list) >= MAX_IPS:
                        break
        except Exception:
            print(f"[!] 无效 CIDR: {cidr}", flush=True)
    return ip_list


def get_ips_from_asn(asn_input):
    """获取 ASN 对应的 IPv4 列表"""
    asn_clean = asn_input.strip().upper().replace("AS", "")
    if not asn_clean.isdigit():
        print(f"[-] 无效的 ASN 输入: {asn_input}", flush=True)
        return []

    print(f"[*] 正在自动查询并拉取 AS{asn_clean} 的网段信息...", flush=True)
    cidrs = []
    
    try:
        ripe_url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_clean}"
        req = urllib.request.Request(ripe_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            prefixes = data.get("data", {}).get("prefixes", [])
            for p in prefixes:
                prefix = p.get("prefix")
                if prefix and ":" not in prefix:
                    cidrs.append(prefix)
    except Exception as e:
        print(f"[!] RIPE API 获取失败: {e}", flush=True)

    if not cidrs:
        try:
            bgp_url = f"https://api.bgpview.io/asn/{asn_clean}/prefixes"
            req = urllib.request.Request(bgp_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())
                ipv4_prefixes = data.get("data", {}).get("ipv4_prefixes", [])
                for p in ipv4_prefixes:
                    prefix = p.get("prefix")
                    if prefix:
                        cidrs.append(prefix)
        except Exception as e:
            print(f"[!] BGPView API 获取失败: {e}", flush=True)

    ip_list = expand_cidrs(cidrs)
    print(f"[+] AS{asn_clean} 共解析出 {len(ip_list)} 个待测 IPv4 地址。", flush=True)
    return ip_list


def get_ips_from_cidr_str(cidr_str):
    """解析逗号/空格/换行分隔的 CIDR 字符串"""
    import re
    parts = re.split(r'[,\s\n]+', cidr_str.strip())
    parts = [p for p in parts if p and '/' in p]
    if not parts:
        print(f"[-] 未找到有效的 CIDR 网段", flush=True)
        return [], ''
    label = '_'.join([p.split('/')[0] for p in parts[:3]])
    if len(parts) > 3:
        label += f'_etc'
    ip_list = expand_cidrs(parts)
    print(f"[+] 共解析出 {len(ip_list)} 个待测 IPv4 地址 (来自 {len(parts)} 个 CIDR)", flush=True)
    return ip_list, label


def check_tls_sni(ip, sni, timeout_val):
    """第一阶段/第三阶段：TLS 极速握手及证书匹配"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    try:
        with ssl.create_connection((ip, 443), timeout=timeout_val) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                if not der_cert:
                    return False
                cert_str = der_cert.decode('latin1', errors='ignore').lower()
                return sni.lower() in cert_str
    except Exception:
        return False


def check_http_via_curl(ip, host, timeout_val):
    """第二阶段：curl 原生 HTTP/2 HEAD 请求校验 301/302"""
    cmd = [
        "curl",
        "-I",
        "-s",
        "-o", "/dev/null",
        "-w", "%{http_code}",
        "--connect-timeout", "1",
        "-m", str(int(timeout_val)),
        "--resolve", f"{host}:443:{ip}",
        f"https://{host}/"
    ]
    
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        http_code = res.stdout.strip()
        return http_code in ("301", "302")
    except Exception:
        return False


stage2_sem = asyncio.Semaphore(STAGE2_CONCURRENCY)

async def stage2_task(ip):
    async with stage2_sem:
        loop = asyncio.get_running_loop()
        ok = await loop.run_in_executor(custom_executor, check_http_via_curl, ip, CF_HOST_TEST, 2.0)
        return ip if ok else None


stage3_sem = asyncio.Semaphore(20)

async def stage3_task(ip, custom_domain):
    async with stage3_sem:
        loop = asyncio.get_running_loop()
        ok = await loop.run_in_executor(custom_executor, check_tls_sni, ip, custom_domain, 2.0)
        return ip if ok else None


async def run_stage1_worker_queue(ip_list):
    """采用队列+固定工作者模式，按 10% 步长进行精简输出"""
    total = len(ip_list)
    completed = 0
    passed_ips = []
    
    # 修改点 1：计算每 10% 打印一次的步长（保证分为 10 段）
    step = max(1, total // 10) 
    last_printed_step = 0

    queue = asyncio.Queue()
    for ip in ip_list:
        queue.put_nowait(ip)

    print(f"\n[1/3 第一阶段 TLS 探测] 开始测试，共 {total} 个目标...", flush=True)

    loop = asyncio.get_running_loop()

    async def worker():
        nonlocal completed, last_printed_step
        while not queue.empty():
            try:
                ip = queue.get_nowait()
            except asyncio.QueueEmpty:
                break

            ok = await loop.run_in_executor(custom_executor, check_tls_sni, ip, CF_SNI_1, STAGE1_TIMEOUT)
            
            completed += 1
            if ok:
                passed_ips.append(ip)

            # 每到达 10% 的步长刷出一条进度
            current_step = completed // step
            if current_step > last_printed_step or completed == total:
                last_printed_step = current_step
                percent = (completed / total) * 100
                print(f"[1/3 进度] {completed}/{total} ({percent:.1f}%) | 当前通过: {len(passed_ips)} 个", flush=True)
            
            queue.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(STAGE1_CONCURRENCY)]
    await asyncio.gather(*workers)

    return passed_ips


async def main():
    raw = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ASNS
    raw = raw.strip()

    # 检测输入类型：CIDR 网段 / 文件路径 / ASN 号
    if '/' in raw:
        # 直接传入 CIDR 网段
        all_ips, label = get_ips_from_cidr_str(raw)
        output_label = label
        print(f"[*] 输入类型: CIDR 网段", flush=True)
    elif raw.endswith('.txt'):
        # 从文件读取 CIDR 网段列表
        try:
            with open(raw) as f:
                cidr_content = f.read()
            all_ips, label = get_ips_from_cidr_str(cidr_content)
            output_label = label
            print(f"[*] 输入类型: CIDR 文件 ({raw})", flush=True)
        except Exception as e:
            print(f"[-] 读取文件失败: {e}", flush=True)
            return
    else:
        # ASN 号
        asn_clean = raw.upper()
        if not asn_clean.startswith("AS"):
            asn_clean = f"AS{asn_clean}"
        output_label = asn_clean
        all_ips = get_ips_from_asn(asn_clean)
        print(f"[*] 输入类型: ASN ({asn_clean})", flush=True)

    all_ips = list(dict.fromkeys(all_ips))

    if not all_ips:
        print("[-] 未能获取到任何待测 IP，程序退出。", flush=True)
        return

    if len(all_ips) > 50000:
        print(f"[!] 待测 IP 超过 50000 个 ({len(all_ips)})，继续可能超时。建议使用更小的网段。", flush=True)

    # ==================== 1. 极限 TLS 粗筛 ====================
    pass_1 = await run_stage1_worker_queue(all_ips)
    print(f"[+] 第一阶段完成！匹配 CF 证书保留 IP: {len(pass_1)} 个\n", flush=True)

    if not pass_1:
        print("[-] 无有效 IP 通过第一阶段。", flush=True)
        return

    # ==================== 2. HTTP 301 校验 ====================
    print(f"[2/3 第二阶段 HTTP 校验] 正在快速校验 {len(pass_1)} 个候选 IP...", flush=True)
    tasks2 = [stage2_task(ip) for ip in pass_1]
    res2 = await asyncio.gather(*tasks2)
    pass_2 = [ip for ip in res2 if ip is not None]
    print(f"[+] 第二阶段完成！返回 301 的可用 IP: {len(pass_2)} 个\n", flush=True)

    if not pass_2:
        print("[-] 无有效 IP 通过第二阶段。", flush=True)
        return

    # ==================== 3. 自定义托管域名反代校验 ====================
    final_ips = pass_2
    if CUSTOM_CF_DOMAIN and CUSTOM_CF_DOMAIN.strip():
        domain = CUSTOM_CF_DOMAIN.strip()
        print(f"[3/3 第三阶段自定义域名校验] 正在校验域名 {domain}...", flush=True)
        tasks3 = [stage3_task(ip, domain) for ip in pass_2]
        res3 = await asyncio.gather(*tasks3)
        final_ips = [ip for ip in res3 if ip is not None]
        print(f"[+] 第三阶段完成！支持自定义托管域名的优选反代 IP: {len(final_ips)} 个", flush=True)
    else:
        print("[3/3] 未检测到 CUSTOM_CF_DOMAIN，自动跳过第三阶段。", flush=True)

    final_ips = sorted(final_ips, key=lambda ip: ipaddress.ip_address(ip))

    # ==================== 导出结果 ====================
    print("\n==================== 扫描结束 ====================", flush=True)
    print(f"目标: {output_label}", flush=True)
    print(f"最终有效 IP 总数: {len(final_ips)}", flush=True)

    output_filename = f"{output_label}.txt"
    with open(output_filename, "w", encoding="utf-8") as f:
        for ip in final_ips:
            f.write(f"{ip}\n")

    print(f"\n[+] 最终结果已排序并保存至：{output_filename}", flush=True)

if __name__ == "__main__":
    asyncio.run(main())
