package gowebspy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

type WebsiteInfo struct {
	URL             string
	IP              []string
	StatusCode      int
	ServerInfo      string
	ContentType     string
	ResponseTime    time.Duration
	SSLInfo         *SSLInfo
	Headers         http.Header
	WhoisInfo       *WhoisInfo
	Title           string
	MetaDescription string
}

type SSLInfo struct {
	Issued     time.Time
	Expiry     time.Time
	Issuer     string
	CommonName string
	DNSNames   []string
	Valid      bool
}

type WhoisInfo struct {
	Registrar    string
	CreatedDate  string
	ExpiresDate  string
	UpdatedDate  string
	NameServers  []string
	DomainStatus []string
	Raw          string
}

func GetWebsiteInfo(rawURL string) (*WebsiteInfo, error) {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	info := &WebsiteInfo{
		URL: parsedURL.String(),
	}

	ips, err := net.LookupIP(parsedURL.Hostname())
	if err != nil {
		fmt.Printf("Warning: Failed to lookup IP: %v\n", err)
	} else {
		for _, ip := range ips {
			info.IP = append(info.IP, ip.String())
		}
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	startTime := time.Now()
	resp, err := client.Get(parsedURL.String())
	if err != nil {
		return info, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()
	info.ResponseTime = time.Since(startTime)

	info.StatusCode = resp.StatusCode
	info.Headers = resp.Header
	info.ServerInfo = resp.Header.Get("Server")
	info.ContentType = resp.Header.Get("Content-Type")

	if strings.Contains(info.ContentType, "text/html") {
		doc, err := goquery.NewDocumentFromReader(resp.Body)
		if err == nil {
			info.Title = doc.Find("title").Text()
			info.MetaDescription, _ = doc.Find("meta[name='description']").Attr("content")
		}
	}

	if parsedURL.Scheme == "https" {
		info.SSLInfo = getSSLInfo(parsedURL.Hostname())
	}

	info.WhoisInfo = getWhoisInfo(parsedURL.Hostname())

	return info, nil
}

func getSSLInfo(hostname string) *SSLInfo {
	conn, err := tls.Dial("tcp", hostname+":443", &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return &SSLInfo{Valid: false}
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return &SSLInfo{Valid: false}
	}

	cert := certs[0]
	return &SSLInfo{
		Issued:     cert.NotBefore,
		Expiry:     cert.NotAfter,
		Issuer:     cert.Issuer.CommonName,
		CommonName: cert.Subject.CommonName,
		DNSNames:   cert.DNSNames,
		Valid:      time.Now().After(cert.NotBefore) && time.Now().Before(cert.NotAfter),
	}
}

func getWhoisInfo(domain string) *WhoisInfo {
	info := &WhoisInfo{}

	parts := strings.Split(domain, ".")
	if len(parts) > 2 {
		domain = strings.Join(parts[len(parts)-2:], ".")
	}

	rawWhois, err := whois.Whois(domain)
	if err != nil {
		return info
	}

	info.Raw = rawWhois

	parsed, err := whoisparser.Parse(rawWhois)
	if err != nil {
		return info
	}

	info.Registrar = parsed.Registrar.Name
	info.CreatedDate = parsed.Domain.CreatedDate
	info.ExpiresDate = parsed.Domain.ExpirationDate
	info.UpdatedDate = parsed.Domain.UpdatedDate
	info.NameServers = parsed.Domain.NameServers
	info.DomainStatus = parsed.Domain.Status

	return info
}

func GetDNSRecords(domain string) (map[string][]string, error) {
	records := map[string][]string{}

	mxRecords, err := net.LookupMX(domain)
	if err == nil {
		for _, mx := range mxRecords {
			records["MX"] = append(records["MX"], fmt.Sprintf("%s (priority: %d)", mx.Host, mx.Pref))
		}
	}

	txtRecords, err := net.LookupTXT(domain)
	if err == nil {
		records["TXT"] = txtRecords
	}

	nsRecords, err := net.LookupNS(domain)
	if err == nil {
		for _, ns := range nsRecords {
			records["NS"] = append(records["NS"], ns.Host)
		}
	}

	aRecords, err := net.LookupHost(domain)
	if err == nil {
		records["A/AAAA"] = aRecords
	}

	cname, err := net.LookupCNAME(domain)
	if err == nil && cname != domain+"." {
		records["CNAME"] = []string{cname}
	}

	return records, nil
}

func PortScan(host string, ports []int) map[int]bool {
	results := make(map[int]bool)
	
	for _, port := range ports {
		timeout := 2 * time.Second
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
		if err == nil {
			conn.Close()
			results[port] = true
		} else {
			results[port] = false
		}
	}
	
	return results
}

func CheckHTTPRedirects(rawURL string) ([]string, error) {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	var redirects []string
	redirects = append(redirects, rawURL)
	
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			redirects = append(redirects, req.URL.String())
			return nil
		},
		Timeout: 10 * time.Second,
	}
	
	_, err := client.Get(rawURL)
	if err != nil {
		return redirects, err
	}
	
	return redirects, nil
}

type TracerouteHop struct {
	Number int
	IP     string
	RTT    time.Duration
}

func SimpleTraceroute(ctx context.Context, host string, maxHops int) ([]TracerouteHop, error) {
	var hops []TracerouteHop
	
	for ttl := 1; ttl <= maxHops; ttl++ {
		dialer := net.Dialer{
			Timeout: 2 * time.Second,
			LocalAddr: nil,
			Control: func(network, address string, c syscall.RawConn) error {
				return syscall.SetsockoptInt(int(c.Fd()), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
			},
		}
		
		start := time.Now()
		conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:80", host))
		rtt := time.Since(start)
		
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok {
				if sysErr, ok := opErr.Err.(*os.SyscallError); ok {
					if sysErr.Err == syscall.EHOSTUNREACH || sysErr.Err == syscall.ETIMEDOUT {
						ip := extractIPFromError(opErr)
						hops = append(hops, TracerouteHop{
							Number: ttl,
							IP:     ip,
							RTT:    rtt,
						})
						continue
					}
				}
			}
			return hops, fmt.Errorf("traceroute error at hop %d: %w", ttl, err)
		}
		
		localAddr := conn.RemoteAddr().String()
		conn.Close()
		hostIP := strings.Split(localAddr, ":")[0]
		
		hops = append(hops, TracerouteHop{
			Number: ttl,
			IP:     hostIP,
			RTT:    rtt,
		})
		
		break
	}
	
	return hops, nil
}

func extractIPFromError(err *net.OpError) string {
	return "unknown"
}
