import asyncio
import ssl
import sys
import os
import re
import random
import resource
import json
import ipaddress
import urllib.request
import socket
from datetime import datetime

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

# CF Trace 验证配置：替代外部 API 依赖，本地确认代理转发能力并获取 colo 机房与地区
CF_TRACE_HOST = "cloudflare.com"
CF_TRACE_PATH = "/cdn-cgi/trace"
TRACE_TIMEOUT = float(os.getenv("TRACE_TIMEOUT", "3.0"))
TRACE_CONCURRENCY = int(os.getenv("TRACE_CONCURRENCY", "500"))

# Smart Subnet Tiering 配置：大段按 /24 分组，每组采样探测端口，仅保留活跃子网
# 超时/并发复用 STAGE1_TIMEOUT / STAGE1_CONCURRENCY；触发阈值与采样数自动自适应
SMART_TIERING = os.getenv("SMART_TIERING", "1") != "0"
SMART_SUBNET_PREFIX = 24
SMART_PROBE_BUDGET = 20000
SMART_SAMPLE_MIN = 2
SMART_SAMPLE_MAX = 6


def calc_smart_sample(total_ips, total_groups, ports):
    """采样数自适应：探测预算摊到每个子网后 clamp 到 [SMART_SAMPLE_MIN, SMART_SAMPLE_MAX]"""
    per_subnet = max(1, SMART_PROBE_BUDGET // max(1, total_groups))
    sample = per_subnet // max(1, len(ports))
    return max(SMART_SAMPLE_MIN, min(SMART_SAMPLE_MAX, sample))

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


class QuietStreamReaderProtocol(asyncio.StreamReaderProtocol):
    """自定义协议：抑制 eof_received 警告，并正确处理 start_tls 二次 connection_made"""
    def eof_received(self):
        return False

    def connection_made(self, transport):
        if self._transport is None:
            super().connection_made(transport)
            return
        # 手动 create_connection + start_tls 会让 SSLProtocol 在握手完成后
        # 再次回调 connection_made(app_transport)。此时需把 reader 重新
        # 绑定到新的 TLS transport，避免 set_transport 的 assert 崩溃。
        self._transport = transport
        reader = self._stream_reader
        if reader is not None and reader._transport is not None:
            reader._transport = transport
        self._over_ssl = transport.get_extra_info('sslcontext') is not None


async def open_tls_connection(ip, port, sni, timeout_val):
    """自定义 TLS 连接：TCP_NODELAY + 超时重试一次"""
    loop = asyncio.get_running_loop()
    for attempt in range(2):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), timeout=timeout_val)
            break
        except asyncio.TimeoutError:
            sock.close()
            if attempt == 0:
                continue
            raise
        except OSError:
            sock.close()
            raise

    reader = asyncio.StreamReader(limit=2 ** 16, loop=loop)
    protocol = QuietStreamReaderProtocol(reader, loop=loop)
    raw_transport = None
    try:
        raw_transport, _ = await loop.create_connection(lambda: protocol, sock=sock)
        tls_transport = await asyncio.wait_for(
            loop.start_tls(raw_transport, protocol, SSL_CTX, server_hostname=sni),
            timeout=timeout_val
        )
        if tls_transport is None:
            # Python 3.10 竞态：握手完成瞬间底层连接断开会导致
            # start_tls 返回 None，此时连接已不可用，按失败处理
            raise OSError(f"start_tls 返回 None，连接已关闭: {ip}:{port}")
        writer = asyncio.StreamWriter(tls_transport, protocol, reader, loop)
        return reader, writer
    except Exception:
        if raw_transport is not None:
            raw_transport.close()
        raise


def parse_ports(port_str):
    """动态解析输入的端口列表，支持端口区间如 80-1000,443"""
    if not port_str:
        return [443]
    raw_ports = re.split(r'[\s,，]+', str(port_str).strip())
    ports = []
    for p in raw_ports:
        m = re.match(r'^(\d+)-(\d+)$', p)
        if m:
            start, end = int(m.group(1)), int(m.group(2))
            ports.extend(range(max(1, start), min(65535, end) + 1))
        elif p.isdigit() and 1 <= int(p) <= 65535:
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
            if ':' in str(net.network_address):
                print(f"[-] 跳过 IPv6 网段: {cidr}", flush=True)
                continue
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
    print(f"[*] 查询 AS{asn_clean} 网段...", flush=True)
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
    raw_targets = [t.strip() for t in re.split(r'[\s,，]+', input_str) if t.strip()]
    all_ips = []

    for item in raw_targets:
        if item.endswith('.txt') and os.path.isfile(item):
            try:
                with open(item) as f:
                    content = f.read()
                all_ips.extend(parse_targets(content))
                print(f"[+] 加载文件: {item}", flush=True)
            except Exception as e:
                print(f"[-] 读取文件失败: {item}: {e}", flush=True)
            continue

        try:
            net = ipaddress.ip_network(item, strict=False)
            if ':' in str(net.network_address):
                print(f"[-] 跳过 IPv6 网段: {item}", flush=True)
                continue
            if net.prefixlen >= 31:
                for ip in net:
                    all_ips.append(str(ip))
            else:
                for ip in net.hosts():
                    all_ips.append(str(ip))
            print(f"[+] 网段 [{item}] 展开 {net.num_addresses} 个地址", flush=True)
            continue
        except ValueError:
            pass

        asn_clean = item.upper().replace("AS", "")
        if asn_clean.isdigit():
            ips = get_ips_from_asn(asn_clean)
            all_ips.extend(ips)
        else:
            print(f"[-] 无法识别的目标格式: {item}", flush=True)

    unique_ips = list(dict.fromkeys(all_ips))
    raw = len(all_ips)
    if raw != len(unique_ips):
        print(f"[+] 解析完成: {raw} raw → {len(unique_ips)} unique", flush=True)
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


async def check_cf_trace_async(ip, port, timeout_val, sem):
    """CF Trace 验证：通过代理 IP 请求 cloudflare.com/cdn-cgi/trace，
    解析 colo 机房代码与 loc 国家代码，成功即确认代理转发能力。"""
    async with sem:
        writer = None
        try:
            reader, writer = await open_tls_connection(ip, port, CF_TRACE_HOST, timeout_val)
            req = (
                f"GET {CF_TRACE_PATH} HTTP/1.1\r\n"
                f"Host: {CF_TRACE_HOST}\r\n"
                f"User-Agent: curl/8.0\r\n"
                f"Connection: close\r\n\r\n"
            )
            writer.write(req.encode('latin1'))
            await writer.drain()
            data = await asyncio.wait_for(reader.read(2048), timeout=timeout_val)
            if not data:
                return None
            body = data.decode('latin1', errors='ignore')
            body_start = body.find('\r\n\r\n')
            if body_start >= 0:
                body = body[body_start + 4:]
            colo = ""
            loc = ""
            for line in body.split('\n'):
                line = line.strip()
                if line.startswith('colo='):
                    colo = line.split('=', 1)[1].strip()
                elif line.startswith('loc='):
                    loc = line.split('=', 1)[1].strip()
            if colo:
                return (ip, port, colo, loc)
            return None
        except Exception:
            return None
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

    print(f"\n[1/3 TLS] 开始测试 {total} 个目标...", flush=True)

    async def worker(item):
        nonlocal completed, last_printed_step
        ip, port = item
        ok = await check_tls_sni_async(ip, port, CF_SNI_1, STAGE1_TIMEOUT, sem)
        completed += 1

        if ok:
            passed_items.append((ip, port))

        current_step = completed // step
        if current_step > last_printed_step:
            last_printed_step = current_step
            percent = (completed / total) * 100
            print(f"[1/3] {completed}/{total} ({percent:.1f}%) 通过 {len(passed_items)}", flush=True)

    for i in range(0, total, BATCH_SIZE):
        batch = targets[i:i + BATCH_SIZE]
        await asyncio.gather(*(worker(item) for item in batch))
    return passed_items


async def run_batched(items, coro_factory, batch_size=10000):
    """分批执行异步任务，结果顺序与输入一致，降低协程内存峰值"""
    results = []
    for i in range(0, len(items), batch_size):
        batch = items[i:i + batch_size]
        results.extend(await asyncio.gather(*(coro_factory(item) for item in batch)))
    return results


async def probe_tcp_async(ip, port, timeout_val):
    """快速 TCP 连通性探测：仅建连，不做 TLS 握手"""
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    try:
        await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), timeout=timeout_val)
        return True
    except Exception:
        return False
    finally:
        sock.close()


async def smart_tiering(all_ips, ports):
    """Smart Subnet Tiering：按 /24 分组，每组采样探测目标端口，
    任一采样 IP 连通即视为活跃子网并保留组内全部 IP，死段直接过滤。

    组内 IP 数不超过采样数时不预筛直接保留，避免误杀稀疏段。
    超时/并发复用主流程，触发阈值由调用方按并发决定，采样数自动自适应。
    """
    groups = {}
    for ip in all_ips:
        try:
            net = ipaddress.ip_network(f"{ip}/{SMART_SUBNET_PREFIX}", strict=False)
        except ValueError:
            continue
        groups.setdefault(str(net.network_address), []).append(ip)

    if not groups:
        return []

    total_groups = len(groups)
    sample_n = calc_smart_sample(len(all_ips), total_groups, ports)
    sem = asyncio.Semaphore(STAGE1_CONCURRENCY)

    async def probe_group(ips):
        async with sem:
            if len(ips) <= sample_n:
                return ips
            sample_ips = random.sample(ips, min(sample_n, len(ips)))
            for s_ip in sample_ips:
                for port in ports:
                    if await probe_tcp_async(s_ip, port, STAGE1_TIMEOUT):
                        return ips
            return None

    results = await asyncio.gather(*(probe_group(ips) for ips in groups.values()))
    kept_groups = [ips for ips in results if ips]
    kept_flat = [ip for ips in kept_groups for ip in ips]
    print(
        f"[*] Smart Tiering: {total_groups} 个子网，自适应采样 {sample_n} 个/组 → "
        f"活跃 {len(kept_groups)}，过滤死段 {total_groups - len(kept_groups)} | "
        f"保留 {len(kept_flat)}/{len(all_ips)} 个 IP",
        flush=True
    )
    return kept_flat


async def main():
    target_input = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGETS
    ports_input = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_PORTS

    target_ports = parse_ports(ports_input)
    print(f"[*] 目标: {target_input} | 端口: {target_ports}", flush=True)
    all_ips = parse_targets(target_input)

    if not all_ips:
        print("[-] 未能获取到任何待测 IP，程序退出。", flush=True)
        return

    if len(all_ips) > 50000:
        print(f"[!] IP 数 {len(all_ips)} 超过 50000，可能超时", flush=True)

    smart_min_ips = STAGE1_CONCURRENCY * 2
    if SMART_TIERING and len(all_ips) >= smart_min_ips:
        print(
            f"[*] Smart Tiering 启用: 按 /24 采样，探测 {target_ports} "
            f"(超时 {STAGE1_TIMEOUT}s, 并发 {STAGE1_CONCURRENCY})",
            flush=True
        )
        all_ips = await smart_tiering(all_ips, target_ports)
        if not all_ips:
            print("[-] Smart Tiering 后无存活子网，程序退出。", flush=True)
            return
    else:
        print(f"[*] Smart Tiering 跳过 (IP数={len(all_ips)} < 阈值 {smart_min_ips})", flush=True)

    targets = [(ip, port) for ip in all_ips for port in target_ports]
    print(f"[*] 连接目标: {len(targets)} 个 ({len(all_ips)} IP × {len(target_ports)} 端口)", flush=True)

    sem = asyncio.Semaphore(STAGE1_CONCURRENCY)

    pass_1 = await run_stage1(targets, sem)
    print(f"[+] 第一阶段完成！CF 证书匹配: {len(pass_1)} 个\n", flush=True)

    if not pass_1:
        print("[-] 无有效 IP:端口 通过第一阶段。", flush=True)
        return

    print(f"[2/3 HTTP] 校验 {len(pass_1)} 个候选...", flush=True)
    res2 = await run_batched(
        pass_1,
        lambda item: check_http_async(item[0], item[1], CF_HOST_TEST, STAGE2_TIMEOUT, sem)
    )
    pass_2 = [pass_1[i] for i, ok in enumerate(res2) if ok]
    print(f"[+] 第二阶段完成！301 重定向: {len(pass_2)} 个\n", flush=True)

    if not pass_2:
        print("[-] 无有效 IP:端口 通过第二阶段。", flush=True)
        return

    final_items = pass_2
    if CUSTOM_CF_DOMAIN and CUSTOM_CF_DOMAIN.strip():
        domain = CUSTOM_CF_DOMAIN.strip()
        print(f"[3/3 自定义域名] 校验 {domain}...", flush=True)
        res3 = await run_batched(
            pass_2,
            lambda item: check_tls_sni_async(item[0], item[1], domain, STAGE3_TIMEOUT, sem)
        )
        final_items = [pass_2[i] for i, ok in enumerate(res3) if ok]
        print(f"[+] 第三阶段完成！自定义域名匹配: {len(final_items)} 个", flush=True)
    else:
        print("[3/3] 未设置自定义域名，跳过", flush=True)

    # ----- CF Trace 验证（替代外部 API 依赖） -----
    if not final_items:
        print("[-] 无目标进入 Trace 验证阶段，程序退出。", flush=True)
        return

    print(f"\n[Trace] CF /cdn-cgi/trace 验证 {len(final_items)} 个...", flush=True)
    trace_sem = asyncio.Semaphore(TRACE_CONCURRENCY)
    trace_results = await run_batched(
        final_items,
        lambda item: check_cf_trace_async(item[0], item[1], TRACE_TIMEOUT, trace_sem)
    )
    valid = [r for r in trace_results if r is not None]
    print(f"[+] Trace 完成: {len(valid)}/{len(final_items)} 可转发", flush=True)

    if not valid:
        print("[-] 无有效转发代理 IP，程序退出。", flush=True)
        return

    # ----- 排序输出 -----
    filtered = sorted(
        [(ip, port, colo) for ip, port, colo, loc in valid],
        key=lambda x: (ipaddress.ip_address(x[0]), x[1])
    )

    print(f"\n========== 扫描结束 ==========", flush=True)
    print(f"最终有效: {len(filtered)} 条", flush=True)

    output_filename = f'{datetime.now().strftime("%Y%m%d_%H%M")}.txt'
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, output_filename)
    with open(output_path, "w", encoding="utf-8") as f:
        for ip, port, colo in filtered:
            f.write(f"{ip}:{port}#{colo}\n")

    print(f"[+] 结果: {output_path} ({len(filtered)} 条, IP:PORT#COLO)", flush=True)

    await asyncio.sleep(0.5)


if __name__ == "__main__":
    asyncio.run(main())