package gowebspy

import (
	"fmt"
	"net"
	"strings"
	"time"
)

type IPAddressInfo struct {
	IPv4Addresses []string
	IPv6Addresses []string
}

func GetIPAddresses(domain string) (*IPAddressInfo, error) {
	info := &IPAddressInfo{}
	
	ips, err := net.LookupIP(domain)
	if err != nil {
		return info, fmt.Errorf("IP lookup failed: %w", err)
	}
	
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			info.IPv4Addresses = append(info.IPv4Addresses, ipv4.String())
		} else {
			info.IPv6Addresses = append(info.IPv6Addresses, ip.String())
		}
	}
	
	return info, nil
}

func PortScanIPv6(host string, ports []int) map[int]bool {
	results := make(map[int]bool)
	
	if !strings.Contains(host, ":") {
		ipInfo, err := GetIPAddresses(host)
		if err != nil || len(ipInfo.IPv6Addresses) == 0 {
			for _, port := range ports {
				results[port] = false
			}
			return results
		}
		
		host = ipInfo.IPv6Addresses[0]
	}
	
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	
	for _, port := range ports {
		timeout := 2 * time.Second
		conn, err := net.DialTimeout("tcp6", fmt.Sprintf("%s:%d", host, port), timeout)
		if err == nil {
			conn.Close()
			results[port] = true
		} else {
			results[port] = false
		}
	}
	
	return results
}

func CheckDualStack(domain string) (bool, error) {
	ipInfo, err := GetIPAddresses(domain)
	if err != nil {
		return false, err
	}
	
	hasIPv4 := len(ipInfo.IPv4Addresses) > 0
	hasIPv6 := len(ipInfo.IPv6Addresses) > 0
	
	return hasIPv4 && hasIPv6, nil
}

func GetIPv6DNSRecords(domain string) (map[string][]string, error) {
	records := map[string][]string{}
	
	aaaaRecords, err := net.LookupIP(domain)
	if err == nil {
		var ipv6Records []string
		for _, ip := range aaaaRecords {
			if ip.To4() == nil {
				ipv6Records = append(ipv6Records, ip.String())
			}
		}
		if len(ipv6Records) > 0 {
			records["AAAA"] = ipv6Records
		}
	}
	
	return records, nil
}
