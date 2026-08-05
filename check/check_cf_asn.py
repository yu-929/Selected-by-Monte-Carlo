import asyncio
import ssl
import sys
import os
import re
import resource
import json
import ipaddress
import urllib.request
import socket

DEFAULT_TARGETS = os.getenv("TARGET_LIST", os.getenv("ASN_LIST", "AS206300"))
DEFAULT_PORTS = "443"
CUSTOM_CF_DOMAIN = os.getenv("CUSTOM_CF_DOMAIN", "example.com")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "check/history")

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


def parse_ports(port_str):
    """动态解析输入的端口列表"""
    if not port_str:
        return [443]
    raw_ports = re.split(r'[\s,]+', str(port_str).strip())
    ports = []
    for p in raw_ports:
        if p.isdigit() and 1 <= int(p) <= 65535:
            ports.append(int(p))
    return list(dict.fromkeys(ports)) if ports else [443]


def expand_cidrs(cidr_list):
    ip_list = []
    for cidr in cidr_list:
        cidr = cidr.strip()
        if not cidr:
            continue
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if net.prefixlen >= 31:
                for ip in net:
                    ip_list.append(str(ip))
            else:
                for ip in net.hosts():
                    ip_list.append(str(ip))
        except Exception:
            print(f"[!] 无效 CIDR: {cidr}", flush=True)
    return ip_list


def get_ips_from_asn(asn_clean):
    """从网络 API 查询 ASN 对应的 IPv4 列表"""
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
    return ip_list


def parse_targets(input_str):
    """智能解析目标输入：ASN、CIDR 网段、单个 IP 或目标文件，支持混合"""
    raw_targets = [t.strip() for t in re.split(r'[\s,]+', input_str) if t.strip()]
    all_ips = []

    for item in raw_targets:
        if item.endswith('.txt') and os.path.isfile(item):
            try:
                with open(item) as f:
                    content = f.read()
                all_ips.extend(parse_targets(content))
                print(f"[+] 从文件 [{item}] 加载目标", flush=True)
            except Exception as e:
                print(f"[-] 读取文件失败: {item}: {e}", flush=True)
            continue

        try:
            net = ipaddress.ip_network(item, strict=False)
            if net.prefixlen >= 31:
                for ip in net:
                    all_ips.append(str(ip))
            else:
                for ip in net.hosts():
                    all_ips.append(str(ip))
            print(f"[+] 识别为 IP/网段 [{item}]，展开出 {net.num_addresses} 个地址", flush=True)
            continue
        except ValueError:
            pass

        asn_clean = item.upper().replace("AS", "")
        if asn_clean.isdigit():
            ips = get_ips_from_asn(asn_clean)
            print(f"[+] AS{asn_clean} 解析完成，提取出 {len(ips)} 个待测 IPv4 地址。", flush=True)
            all_ips.extend(ips)
        else:
            print(f"[-] 无法识别的目标格式: {item}", flush=True)

    unique_ips = list(dict.fromkeys(all_ips))
    print(f"[+] 所有目标汇总去重后，共有 {len(unique_ips)} 个待测 IP 地址。", flush=True)
    return unique_ips


def match_domain_in_cert(sni_domain, cert_str):
    """支持通配符 (*.domain.com) 与主域名的智能证书匹配"""
    sni_domain = sni_domain.lower()
    cert_str = cert_str.lower()

    if sni_domain in cert_str:
        return True

    parts = sni_domain.split(".")
    if len(parts) >= 2:
        main_domain = ".".join(parts[-2:])
        wildcard_domain = f"*.{main_domain}"
        if main_domain in cert_str or wildcard_domain in cert_str:
            return True

    if "cloudflare" in sni_domain and "cloudflare" in cert_str:
        return True

    return False


async def check_tls_sni_async(ip, port, sni, timeout_val, sem):
    """阶段一/阶段三：原生异步 TLS 握手"""
    async with sem:
        writer = None
        try:
            reader, writer = await open_tls_connection(ip, port, sni, timeout_val)

            ssl_obj = writer.get_extra_info('ssl_object')
            der_cert = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None

            if not der_cert:
                return False

            cert_str = der_cert.decode('latin1', errors='ignore').lower()
            return match_domain_in_cert(sni, cert_str)
        except Exception:
            return False
        finally:
            if writer:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
                except Exception:
                    pass


async def check_http_async(ip, port, host, timeout_val, sem):
    """阶段二：严格校验 301/302 重定向 + Location 头"""
    async with sem:
        writer = None
        try:
            reader, writer = await open_tls_connection(ip, port, host, timeout_val)

            req = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            writer.write(req.encode('latin1'))
            await writer.drain()

            data = await asyncio.wait_for(reader.read(1024), timeout=timeout_val)

            if not data:
                return False

            resp_str = data.decode('latin1', errors='ignore').lower()

            has_redirect_code = "http/1.1 301" in resp_str or "http/1.1 302" in resp_str
            has_location_header = "location:" in resp_str

            return has_redirect_code and has_location_header
        except Exception:
            return False
        finally:
            if writer:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
                except Exception:
                    pass


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
    target_input = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGETS
    ports_input = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_PORTS

    target_ports = parse_ports(ports_input)
    print(f"[*] 目标输入: {target_input} | 端口列表: {target_ports}", flush=True)
    all_ips = parse_targets(target_input)

    if not all_ips:
        print("[-] 未能获取到任何待测 IP，程序退出。", flush=True)
        return

    if len(all_ips) > 50000:
        print(f"[!] 待测 IP 超过 50000 个 ({len(all_ips)})，继续可能超时。建议使用更小的网段。", flush=True)

    targets = [(ip, port) for ip in all_ips for port in target_ports]
    print(f"[*] 解析完成：{len(all_ips)} 个 IP × {len(target_ports)} 个端口 {target_ports} = 共有 {len(targets)} 个连接目标。", flush=True)

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
    print(f"[+] 第二阶段完成！可用 301 重定向目标: {len(pass_2)} 个\n", flush=True)

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
    print(f"最终有效目标总数: {len(final_items)}", flush=True)

    clean_name = re.sub(r'[^\w\.-]', '_', target_input.split(',')[0].strip())
    if clean_name.lower().endswith(".txt"):
        clean_name = os.path.basename(clean_name)[:-4]
    output_filename = f"{clean_name}.txt"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, output_filename)
    with open(output_path, "w", encoding="utf-8") as f:
        for ip, port in final_items:
            f.write(f"{ip}:{port}\n")

    print(f"\n[+] 最终结果已排序保存至：{output_path} (格式为 IP:PORT)", flush=True)

    await asyncio.sleep(0.5)


if __name__ == "__main__":
    asyncio.run(main())