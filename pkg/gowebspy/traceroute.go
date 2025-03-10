package gowebspy

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type TracerouteHop struct {
	Number int
	IP     string
	RTT    time.Duration
	Host   string
}

func SimpleTraceroute(ctx context.Context, host string, maxHops int) ([]TracerouteHop, error) {
	var hops []TracerouteHop
	
	nativeHops, err := nativeTraceroute(ctx, host, maxHops)
	if err == nil {
		return nativeHops, nil
	}
	
	return externalTraceroute(ctx, host, maxHops)
}

func nativeTraceroute(ctx context.Context, host string, maxHops int) ([]TracerouteHop, error) {
	var hops []TracerouteHop
	
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("couldn't resolve host %s: %w", host, err)
	}
	
	var targetIP net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			targetIP = ip
			break
		}
	}
	
	if targetIP == nil && len(ips) > 0 {
		targetIP = ips[0]
	}
	
	for ttl := 1; ttl <= maxHops; ttl++ {
		hop := TracerouteHop{Number: ttl}
		
		hopCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		
		dialer := net.Dialer{
			Timeout: 1 * time.Second,
			Control: func(network, address string, c syscall.RawConn) error {
				return c.Control(func(fd uintptr) {
					if targetIP.To4() != nil {
						syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
					} else {
						syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
					}
				})
			},
		}
		
		start := time.Now()
		
		conn, err := dialer.DialContext(hopCtx, "udp", targetIP.String()+":33434")
		elapsed := time.Since(start)
		
		if conn != nil {
			conn.Close()
		}
		
		hopIP := extractIPFromError(err)
		if hopIP != "" {
			hop.IP = hopIP
			hop.RTT = elapsed
			
			hosts, err := net.LookupAddr(hopIP)
			if err == nil && len(hosts) > 0 {
				hop.Host = hosts[0]
			}
			
			hops = append(hops, hop)
			
			if hopIP == targetIP.String() {
				break
			}
		} else {
			hop.IP = "*"
			hop.RTT = elapsed
			hops = append(hops, hop)
		}
	}
	
	return hops, nil
}

func extractIPFromError(err error) string {
	if err == nil {
		return ""
	}
	
	errMsg := err.Error()
	
	ipv4Regex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv4Matches := ipv4Regex.FindAllString(errMsg, -1)
	
	if len(ipv4Matches) > 0 {
		return ipv4Matches[0]
	}
	
	ipv6Regex := regexp.MustCompile(`([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}`)
	ipv6Matches := ipv6Regex.FindAllString(errMsg, -1)
	
	if len(ipv6Matches) > 0 {
		return ipv6Matches[0]
	}
	
	return ""
}

func externalTraceroute(ctx context.Context, host string, maxHops int) ([]TracerouteHop, error) {
	var cmd *exec.Cmd
	
	if isWindows() {
		cmd = exec.CommandContext(ctx, "tracert", "-d", "-h", strconv.Itoa(maxHops), host)
	} else {
		cmd = exec.CommandContext(ctx, "traceroute", "-n", "-m", strconv.Itoa(maxHops), host)
	}
	
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("traceroute command failed: %w", err)
	}
	
	return parseTracerouteOutput(string(output)), nil
}

func parseTracerouteOutput(output string) []TracerouteHop {
	var hops []TracerouteHop
	
	lines := strings.Split(output, "\n")
	
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		
		hop := parseLine(line)
		if hop.Number > 0 {
			hops = append(hops, hop)
		}
	}
	
	return hops
}

func parseLine(line string) TracerouteHop {
	hop := TracerouteHop{}
	
	numRegex := regexp.MustCompile(`^\s*(\d+)`)
	numMatch := numRegex.FindStringSubmatch(line)
	if len(numMatch) > 1 {
		hop.Number, _ = strconv.Atoi(numMatch[1])
	}
	
	ipRegex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b|([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}`)
	ipMatch := ipRegex.FindString(line)
	if ipMatch != "" {
		hop.IP = ipMatch
	} else {
		hop.IP = "*"
	}
	
	rttRegex := regexp.MustCompile(`(\d+(?:\.\d+)?) ms`)
	rttMatch := rttRegex.FindStringSubmatch(line)
	if len(rttMatch) > 1 {
		rttMs, _ := strconv.ParseFloat(rttMatch[1], 64)
		hop.RTT = time.Duration(rttMs * float64(time.Millisecond))
	}
	
	return hop
}

func isWindows() bool {
	return runtime.GOOS == "windows"
}

func TracerouteIPv6(ctx context.Context, host string, maxHops int) ([]TracerouteHop, error) {
	var cmd *exec.Cmd
	
	if isWindows() {
		cmd = exec.CommandContext(ctx, "tracert", "-6", "-d", "-h", strconv.Itoa(maxHops), host)
	} else {
		cmd = exec.CommandContext(ctx, "traceroute6", "-n", "-m", strconv.Itoa(maxHops), host)
	}
	
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("IPv6 traceroute command failed: %w", err)
	}
	
	return parseTracerouteOutput(string(output)), nil
}
