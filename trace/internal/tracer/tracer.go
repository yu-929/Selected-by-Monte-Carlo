package tracer

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"trace/internal/model"
)

// Config 控制 tracert 探测行为
type Config struct {
	MaxHops      int
	MaxEmpty     int
	TimeoutHop   time.Duration
	TimeoutTotal time.Duration
	ProbesPerHop int // 每跳探测次数
}

// DefaultConfig 返回默认配置（与 Trace README 一致）
func DefaultConfig() Config {
	return Config{
		MaxHops:      12,
		MaxEmpty:     8,
		TimeoutHop:   500 * time.Millisecond,
		TimeoutTotal: 60 * time.Second,
		ProbesPerHop: 3,
	}
}

// RetryConfig 返回重试放宽后的配置（-m 25, -ht 1000ms, -tt 90000ms）
func (c Config) RetryConfig() Config {
	c.MaxHops = 25
	c.TimeoutHop = 1000 * time.Millisecond
	c.TimeoutTotal = 90 * time.Second
	return c
}

// Trace 对单个目标执行 tracert，返回沿途节点。
// 使用 UDP 探测包 + ICMP Time Exceeded 响应，识别路由路径。
func Trace(ctx context.Context, target string, cfg Config) ([]model.Hop, error) {
	if cfg.MaxHops <= 0 {
		cfg.MaxHops = 12
	}
	if cfg.MaxEmpty <= 0 {
		cfg.MaxEmpty = 8
	}
	if cfg.TimeoutHop <= 0 {
		cfg.TimeoutHop = 500 * time.Millisecond
	}
	if cfg.TimeoutTotal <= 0 {
		cfg.TimeoutTotal = 60 * time.Second
	}
	if cfg.ProbesPerHop <= 0 {
		cfg.ProbesPerHop = 3
	}

	dst := net.ParseIP(target)
	if dst == nil || dst.To4() == nil {
		return nil, fmt.Errorf("无效的目标 IP: %s", target)
	}

	// 打开 ICMP raw socket 接收响应（需要 root / CAP_NET_RAW）
	icmpConn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("无法创建 ICMP socket（需要 root 权限）: %v", err)
	}
	defer icmpConn.Close()

	// 每跳使用随机 UDP 端口作为探测包
	rand.Seed(time.Now().UnixNano())

	var hops []model.Hop
	emptyStreak := 0
	totalStart := time.Now()

	for ttl := 1; ttl <= cfg.MaxHops; ttl++ {
		if ctx.Err() != nil {
			return hops, ctx.Err()
		}
		if time.Since(totalStart) > cfg.TimeoutTotal {
			break
		}

		hop := probeHop(ctx, icmpConn, dst, ttl, cfg.TimeoutHop, cfg.ProbesPerHop)
		hop.TTL = ttl

		if hop.IP == "" {
			emptyStreak++
			hops = append(hops, hop)
			if emptyStreak >= cfg.MaxEmpty {
				break
			}
			continue
		}
		emptyStreak = 0
		hops = append(hops, hop)

		if hop.IP == dst.String() {
			break // 已到达目标
		}
	}

	if len(hops) == 0 {
		return nil, errors.New("tracert 无任何响应")
	}
	return hops, nil
}

// probeHop 探测单跳：向目标发送 TTL 递增的 UDP 包，接收 ICMP 响应
func probeHop(ctx context.Context, icmpConn net.PacketConn, dst net.IP, ttl int, timeout time.Duration, probes int) model.Hop {
	hop := model.Hop{IP: "", Latency: "-"}
	var rtts []time.Duration
	seen := make(map[string]bool)

	for i := 0; i < probes; i++ {
		if ctx.Err() != nil {
			break
		}

		// 建立到目标的 UDP 连接，设置 TTL
		port := 33434 + rand.Intn(3000)
		udpConn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: dst, Port: port})
		if err != nil {
			continue
		}
		if err := ipv4.NewConn(udpConn).SetTTL(ttl); err != nil {
			udpConn.Close()
			continue
		}

		start := time.Now()
		if _, err := udpConn.Write([]byte("trace")); err != nil {
			udpConn.Close()
			continue
		}
		udpConn.Close() // 发送后关闭，目标会回 Port Unreachable

		// 等待 ICMP 响应
		_ = icmpConn.SetReadDeadline(time.Now().Add(timeout))
		buf := make([]byte, 1500)
		for {
			n, peer, err := icmpConn.ReadFrom(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					break
				}
				break
			}
			if n < 8 {
				continue
			}
			rtt := time.Since(start)

			msg, err := icmp.ParseMessage(1, buf[:n])
			if err != nil {
				continue
			}
			switch msg.Type {
			case ipv4.ICMPTypeTimeExceeded, ipv4.ICMPTypeDestinationUnreachable:
				ip := peer.String()
				if !seen[ip] {
					seen[ip] = true
				}
				hop.IP = ip
				rtts = append(rtts, rtt)
				if ip == dst.String() {
					return hop
				}
				// 本跳已得到响应，跳出等待循环
				return finalizeHop(hop, rtts)
			case ipv4.ICMPTypeEchoReply:
				hop.IP = peer.String()
				rtts = append(rtts, rtt)
				return finalizeHop(hop, rtts)
			}
		}
	}

	return finalizeHop(hop, rtts)
}

func finalizeHop(hop model.Hop, rtts []time.Duration) model.Hop {
	if len(rtts) > 0 {
		var total time.Duration
		for _, r := range rtts {
			total += r
		}
		avg := total / time.Duration(len(rtts))
		hop.Latency = fmt.Sprintf("%d ms", avg.Milliseconds())
	}
	return hop
}
