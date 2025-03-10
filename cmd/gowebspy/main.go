package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/ArjunShardahey/gowebspy/pkg/gowebspy"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	showSSL      bool
	showHeaders  bool
	showWhois    bool
	showDNS      bool
	scanPorts    bool
	checkMobile  bool
	formatJSON   bool
	traceRoute   bool
	allInfo      bool
	checkSpeed   bool
)

func init() {
	rootCmd.Flags().BoolVarP(&showSSL, "ssl", "s", false, "Show SSL certificate information")
	rootCmd.Flags().BoolVarP(&showHeaders, "headers", "H", false, "Show HTTP headers")
	rootCmd.Flags().BoolVarP(&showWhois, "whois", "w", false, "Show WHOIS information")
	rootCmd.Flags().BoolVarP(&showDNS, "dns", "d", false, "Show DNS records")
	rootCmd.Flags().BoolVarP(&scanPorts, "ports", "p", false, "Scan common ports")
	rootCmd.Flags().BoolVarP(&formatJSON, "json", "j", false, "Output in JSON format")
	rootCmd.Flags().BoolVarP(&traceRoute, "trace", "t", false, "Perform simple traceroute")
	rootCmd.Flags().BoolVarP(&allInfo, "all", "a", false, "Show all information")
}

var rootCmd = &cobra.Command{
	Use:   "gowebspy [url]",
	Short: "Get information about a website",
	Long: `A CLI tool to retrieve comprehensive information about websites
including DNS records, HTTP headers, SSL certificates, and more.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		url := args[0]
		
		if allInfo {
			showSSL = true
			showHeaders = true
			showWhois = true
			showDNS = true
			scanPorts = true
			traceRoute = true
			checkSpeed = true
		}
		
		info, err := gowebspy.GetWebsiteInfo(url)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		
		if formatJSON {
			outputJSON(info)
			return
		}
		
		printBasicInfo(info)
		
		if showSSL && info.SSLInfo != nil {
			printSSLInfo(info.SSLInfo)
		}
		
		if showHeaders {
			printHeaders(info.Headers)
		}
		
		if showWhois && info.WhoisInfo != nil {
			printWhoisInfo(info.WhoisInfo)
		}
		
		if showDNS {
			printDNSRecords(url)
		}
		
		if scanPorts {
			printPortScan(url)
		}
		
		if traceRoute {
			printTraceroute(url)
		}
	},
}

func outputJSON(info *gowebspy.WebsiteInfo) {
	fmt.Println("JSON output would appear here")
}

func printBasicInfo(info *gowebspy.WebsiteInfo) {
	titleColor := color.New(color.FgHiCyan, color.Bold).PrintlnFunc()
	keyColor := color.New(color.FgHiYellow).PrintFunc()
	valueColor := color.New(color.FgHiWhite).PrintlnFunc()
	
	titleColor("BASIC INFORMATION")
	fmt.Println(strings.Repeat("=", 50))
	
	keyColor("URL:            ")
	valueColor(info.URL)
	
	keyColor("Title:          ")
	valueColor(info.Title)
	
	if info.MetaDescription != "" {
		keyColor("Description:    ")
		valueColor(info.MetaDescription)
	}
	
	keyColor("Status Code:    ")
	valueColor(info.StatusCode)
	
	keyColor("Server:         ")
	valueColor(info.ServerInfo)
	
	keyColor("Content Type:   ")
	valueColor(info.ContentType)
	
	keyColor("Response Time:  ")
	valueColor(info.ResponseTime)
	
	keyColor("IP Addresses:   ")
	valueColor(strings.Join(info.IP, ", "))
	
	fmt.Println()
}

func printSSLInfo(sslInfo *gowebspy.SSLInfo) {
	titleColor := color.New(color.FgHiGreen, color.Bold).PrintlnFunc()
	keyColor := color.New(color.FgHiYellow).PrintFunc()
	valueColor := color.New(color.FgHiWhite).PrintlnFunc()
	
	titleColor("SSL CERTIFICATE INFORMATION")
	fmt.Println(strings.Repeat("=", 50))
	
	keyColor("Common Name:    ")
	valueColor(sslInfo.CommonName)
	
	keyColor("Issuer:         ")
	valueColor(sslInfo.Issuer)
	
	keyColor("Valid:          ")
	if sslInfo.Valid {
		color.New(color.FgHiGreen).Println("Yes")
	} else {
		color.New(color.FgHiRed).Println("No")
	}
	
	keyColor("Issued Date:    ")
	valueColor(sslInfo.Issued.Format(time.RFC3339))
	
	keyColor("Expiry Date:    ")
	valueColor(sslInfo.Expiry.Format(time.RFC3339))
	
	keyColor("Days Until Expiry: ")
	daysLeft := int(sslInfo.Expiry.Sub(time.Now()).Hours() / 24)
	if daysLeft > 30 {
		color.New(color.FgHiGreen).Printf("%d days\n", daysLeft)
	} else if daysLeft > 7 {
		color.New(color.FgHiYellow).Printf("%d days\n", daysLeft)
	} else {
		color.New(color.FgHiRed).Printf("%d days\n", daysLeft)
	}
	
	keyColor("Alternative Names: ")
	if len(sslInfo.DNSNames) > 0 {
		valueColor(strings.Join(sslInfo.DNSNames[:min(5, len(sslInfo.DNSNames))], ", ") + 
			(len(sslInfo.DNSNames) > 5 ? "..." : ""))
	} else {
		valueColor("None")
	}
	
	fmt.Println()
}

func printHeaders(headers map[string][]string) {
	titleColor := color.New(color.FgHiMagenta, color.Bold).PrintlnFunc()
	keyColor := color.New(color.FgHiYellow).PrintFunc()
	valueColor := color.New(color.FgHiWhite).PrintlnFunc()
	
	titleColor("HTTP HEADERS")
	fmt.Println(strings.Repeat("=", 50))
	
	for name, values := range headers {
		keyColor(name + ": ")
		valueColor(strings.Join(values, ", "))
	}
	
	fmt.Println()
}

func printWhoisInfo(whoisInfo *gowebspy.WhoisInfo) {
	titleColor := color.New(color.FgHiBlue, color.Bold).PrintlnFunc()
	keyColor := color.New(color.FgHiYellow).PrintFunc()
	valueColor := color.New(color.FgHiWhite).PrintlnFunc()
	
	titleColor("WHOIS INFORMATION")
	fmt.Println(strings.Repeat("=", 50))
	
	keyColor("Registrar:      ")
	valueColor(whoisInfo.Registrar)
	
	keyColor("Created Date:   ")
	valueColor(whoisInfo.CreatedDate)
	
	keyColor("Updated Date:   ")
	valueColor(whoisInfo.UpdatedDate)
	
	keyColor("Expires Date:   ")
	valueColor(whoisInfo.ExpiresDate)
	
	keyColor("Name Servers:   ")
	valueColor(strings.Join(whoisInfo.NameServers, ", "))
	
	keyColor("Domain Status:  ")
	valueColor(strings.Join(whoisInfo.DomainStatus, ", "))
	
	fmt.Println()
}

func printDNSRecords(domain string) {
	domain = extractDomain(domain)
	
	titleColor := color.New(color.FgHiYellow, color.Bold).PrintlnFunc()
	keyColor := color.New(color.FgHiYellow).PrintFunc()
	valueColor := color.New(color.FgHiWhite).PrintlnFunc()
	
	titleColor("DNS RECORDS")
	fmt.Println(strings.Repeat("=", 50))
	
	records, err := gowebspy.GetDNSRecords(domain)
	if err != nil {
		fmt.Printf("Error retrieving DNS records: %v\n", err)
		return
	}
	
	for recordType, values := range records {
		keyColor(recordType + " Records: ")
		valueColor(strings.Join(values, ", "))
	}
	
	fmt.Println()
}

func printPortScan(host string) {
	host = extractDomain(host)
	
	titleColor := color.New(color.FgHiRed, color.Bold).PrintlnFunc()
	
	titleColor("PORT SCAN")
	fmt.Println(strings.Repeat("=", 50))
	
	commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 8080, 8443}
	results := gowebspy.PortScan(host, commonPorts)
	
	for port, open := range results {
		portName := getPortName(port)
		if open {
			color.New(color.FgHiGreen).Printf("✓ Port %d (%s): Open\n", port, portName)
		} else {
			color.New(color.FgHiRed).Printf("✗ Port %d (%s): Closed\n", port, portName)
		}
	}
	
	fmt.Println()
}

func printTraceroute(host string) {
	host = extractDomain(host)
	
	titleColor := color.New(color.FgHiCyan, color.Bold).PrintlnFunc()
	
	titleColor("TRACEROUTE")
	fmt.Println(strings.Repeat("=", 50))
	
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	hops, err := gowebspy.SimpleTraceroute(ctx, host, 30)
	if err != nil {
		fmt.Printf("Error performing traceroute: %v\n", err)
		return
	}
	
	for _, hop := range hops {
		fmt.Printf("%2d  %s  %s\n", hop.Number, hop.IP, hop.RTT)
	}
	
	fmt.Println()
}

func extractDomain(urlStr string) string {
	urlStr = strings.TrimPrefix(urlStr, "http://")
	urlStr = strings.TrimPrefix(urlStr, "https://")
	return strings.Split(urlStr, "/")[0]
}

func getPortName(port int) string {
	portMap := map[int]string{
		21:   "FTP",
		22:   "SSH",
		23:   "Telnet",
		25:   "SMTP",
		53:   "DNS",
		80:   "HTTP",
		110:  "POP3",
		143:  "IMAP",
		443:  "HTTPS",
		465:  "SMTPS",
		587:  "SMTP",
		993:  "IMAPS",
		995:  "POP3S",
		3306: "MySQL",
		5432: "PostgreSQL",
		8080: "HTTP-ALT",
		8443: "HTTPS-ALT",
	}
	
	if name, ok := portMap[port]; ok {
		return name
	}
	return "Unknown"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
