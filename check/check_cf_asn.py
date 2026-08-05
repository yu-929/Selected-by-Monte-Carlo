import asyncio
import ssl
import sys
import os
import resource
import json
import ipaddress
import urllib.request
import socket

DEFAULT_ASNS = os.getenv("ASN_LIST", "AS13335")
CUSTOM_CF_DOMAIN = os.getenv("CUSTOM_CF_DOMAIN", "example.com")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "check/history")

TARGET_PORTS = [443]

CF_SNI_1 = "www.cloudflare.com"
STAGE1_CONCURRENCY = 2000
STAGE1_TIMEOUT = 0.8

CF_HOST_TEST = "crypto.cloudflare.com"
STAGE2_TIMEOUT = 2.0

STAGE3_TIMEOUT = 2.0

try:
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
    soft = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    print(f"[*] 系统 Socket 文件描述符上限已提升至: {soft}", flush=True)
    STAGE1_CONCURRENCY = min(STAGE1_CONCURRENCY, max(64, soft // 2))
    print(f"[*] 阶段一并发数调整为: {STAGE1_CONCURRENCY}", flush=True)
except Exception as e:
    print(f"[!] 提升文件描述符失败 (若非 Linux 环境可忽略): {e}", flush=True)

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


async def open_tls_connection(ip, port, sni, timeout_val):
    """自定义 TLS 连接：开启 TCP_NODELAY 降低短连接延迟"""
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), timeout=timeout_val)
    except Exception:
        sock.close()
        raise

    reader = asyncio.StreamReader(limit=2 ** 16, loop=loop)
    protocol = asyncio.StreamReaderProtocol(reader, loop=loop)
    transport, _ = await loop.create_connection(lambda: protocol, sock=sock)
    try:
        transport = await asyncio.wait_for(
            loop.start_tls(transport, protocol, SSL_CTX, server_hostname=sni),
            timeout=timeout_val
        )
        writer = asyncio.StreamWriter(transport, protocol, reader, loop)
        return reader, writer
    except Exception:
        transport.close()
        raise

def get_ips_from_asn(asn_input):
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


def expand_cidrs(cidr_list):
    ip_list = []
    for cidr in cidr_list:
        cidr = cidr.strip()
        if not cidr:
            continue
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            for ip in net.hosts():
                ip_list.append(str(ip))
        except Exception:
            print(f"[!] 无效 CIDR: {cidr}", flush=True)
    return ip_list


def get_ips_from_cidr_str(cidr_str):
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


async def check_tls_sni_async(ip, port, sni, timeout_val, sem):
    async with sem:
        try:
            reader, writer = await open_tls_connection(ip, port, sni, timeout_val)

            ssl_obj = writer.get_extra_info('ssl_object')
            der_cert = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None

            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1)
            except Exception:
                pass

            if not der_cert:
                return False

            cert_str = der_cert.decode('latin1', errors='ignore').lower()
            return sni.lower() in cert_str
        except Exception:
            return False


async def check_http_async(ip, port, host, timeout_val, sem):
    async with sem:
        try:
            reader, writer = await open_tls_connection(ip, port, host, timeout_val)

            req = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            writer.write(req.encode('latin1'))
            await writer.drain()

            data = await asyncio.wait_for(reader.read(1024), timeout=timeout_val)
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1)
            except Exception:
                pass

            if not data:
                return False

            resp_str = data.decode('latin1', errors='ignore').lower()

            is_redirect = any(code in resp_str for code in ["http/1.1 301", "http/1.1 302", "http/1.1 307", "http/1.1 308"])
            is_cf = "server: cloudflare" in resp_str or "http/1.1 403" in resp_str

            return is_redirect or is_cf
        except Exception:
            return False


async def run_stage1(targets, sem):
    total = len(targets)
    completed = 0
    passed_items = []
    BATCH_SIZE = 10000

    step = max(1, total // 10)
    last_printed_step = 0

    print(f"\n[1/3 第一阶段 TLS 探测] 开始测试，共 {total} 个目标 (IP:端口组合)，分批调度每批 {BATCH_SIZE}...", flush=True)

    async def worker(item):
        nonlocal completed, last_printed_step
        ip, port = item
        ok = await check_tls_sni_async(ip, port, CF_SNI_1, STAGE1_TIMEOUT, sem)
        completed += 1

        if ok:
            passed_items.append((ip, port))

        current_step = completed // step
        if current_step > last_printed_step or completed == total:
            last_printed_step = current_step
            percent = (completed / total) * 100
            print(f"[1/3 进度] {completed}/{total} ({percent:.1f}%) | 当前通过: {len(passed_items)} 个", flush=True)

    for i in range(0, total, BATCH_SIZE):
        batch = targets[i:i + BATCH_SIZE]
        await asyncio.gather(*(worker(item) for item in batch))
    return passed_items


async def main():
    raw = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_ASNS
    raw = raw.strip()

    if '/' in raw:
        all_ips, label = get_ips_from_cidr_str(raw)
        output_label = label
        print(f"[*] 输入类型: CIDR 网段", flush=True)
    elif raw.endswith('.txt'):
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

    targets = [(ip, port) for ip in all_ips for port in TARGET_PORTS]
    print(f"[*] 解析完成：{len(all_ips)} 个 IP × {len(TARGET_PORTS)} 个端口 = 共有 {len(targets)} 个连接目标。", flush=True)

    sem = asyncio.Semaphore(STAGE1_CONCURRENCY)

    pass_1 = await run_stage1(targets, sem)
    print(f"[+] 第一阶段完成！匹配 CF 证书保留目标: {len(pass_1)} 个\n", flush=True)

    if not pass_1:
        print("[-] 无有效 IP:端口 通过第一阶段。", flush=True)
        return

    print(f"[2/3 第二阶段 HTTP 校验] 正在快速校验 {len(pass_1)} 个候选目标...", flush=True)
    tasks2 = [check_http_async(ip, port, CF_HOST_TEST, STAGE2_TIMEOUT, sem) for ip, port in pass_1]
    res2 = await asyncio.gather(*tasks2)
    pass_2 = [pass_1[i] for i, ok in enumerate(res2) if ok]
    print(f"[+] 第二阶段完成！可用目标: {len(pass_2)} 个\n", flush=True)

    if not pass_2:
        print("[-] 无有效 IP:端口 通过第二阶段。", flush=True)
        return

    final_items = pass_2
    if CUSTOM_CF_DOMAIN and CUSTOM_CF_DOMAIN.strip():
        domain = CUSTOM_CF_DOMAIN.strip()
        print(f"[3/3 第三阶段自定义域名校验] 正在校验域名 {domain}...", flush=True)
        tasks3 = [check_tls_sni_async(ip, port, domain, STAGE3_TIMEOUT, sem) for ip, port in pass_2]
        res3 = await asyncio.gather(*tasks3)
        final_items = [pass_2[i] for i, ok in enumerate(res3) if ok]
        print(f"[+] 第三阶段完成！支持自定义托管域名的优选反代 IP: {len(final_items)} 个", flush=True)
    else:
        print("[3/3] 未检测到 CUSTOM_CF_DOMAIN，自动跳过第三阶段。", flush=True)

    final_items = sorted(final_items, key=lambda x: (ipaddress.ip_address(x[0]), x[1]))

    print("\n==================== 扫描结束 ====================", flush=True)
    print(f"目标: {output_label} | 测试端口: {TARGET_PORTS}", flush=True)
    print(f"最终有效目标总数: {len(final_items)}", flush=True)

    output_filename = f"{output_label}.txt"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, output_filename)
    with open(output_path, "w", encoding="utf-8") as f:
        for ip, port in final_items:
            f.write(f"{ip}:{port}\n")

    print(f"\n[+] 最终结果已排序保存至：{output_path} (格式为 IP:PORT)", flush=True)

    await asyncio.sleep(0.5)


if __name__ == "__main__":
    asyncio.run(main())