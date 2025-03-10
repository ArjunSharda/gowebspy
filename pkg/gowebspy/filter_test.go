package gowebspy

import (
	"net/http"
	"testing"
	"time"
)

func TestApplyFilter(t *testing.T) {
	// Create a sample website info
	info := &WebsiteInfo{
		URL:             "https://example.com",
		StatusCode:      200,
		ServerInfo:      "nginx/1.18.0",
		ContentType:     "text/html; charset=UTF-8",
		ResponseTime:    150 * time.Millisecond,
		IP:              []string{"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"},
		Title:           "Example Domain",
		MetaDescription: "This is an example website for testing",
		Headers:         make(http.Header),
		SSLInfo: &SSLInfo{
			Issued:     time.Now().Add(-30 * 24 * time.Hour),
			Expiry:     time.Now().Add(60 * 24 * time.Hour),
			Issuer:     "Let's Encrypt",
			CommonName: "example.com",
			DNSNames:   []string{"example.com", "www.example.com"},
			Valid:      true,
		},
	}

	// Add some headers
	info.Headers.Add("Content-Type", "text/html; charset=UTF-8")
	info.Headers.Add("Server", "nginx/1.18.0")
	info.Headers.Add("Strict-Transport-Security", "max-age=31536000")

	// Test cases
	tests := []struct {
		name   string
		opts   *FilterOptions
		expect bool
	}{
		{
			name:   "No filters",
			opts:   NewFilterOptions(),
			expect: true,
		},
		{
			name: "Status code match",
			opts: &FilterOptions{
				MinStatusCode: 200,
				MaxStatusCode: 200,
			},
			expect: true,
		},
		{
			name: "Status code not match",
			opts: &FilterOptions{
				MinStatusCode: 300,
				MaxStatusCode: 400,
			},
			expect: false,
		},
		{
			name: "Server name match",
			opts: &FilterOptions{
				ServerContains: "nginx",
			},
			expect: true,
		},
		{
			name: "Server name not match",
			opts: &FilterOptions{
				ServerContains: "Apache",
			},
			expect: false,
		},
		{
			name: "Header exists",
			opts: &FilterOptions{
				HeaderKeyMustExist: []string{"Strict-Transport-Security"},
			},
			expect: true,
		},
		{
			name: "Header not exists",
			opts: &FilterOptions{
				HeaderKeyMustExist: []string{"Content-Security-Policy"},
			},
			expect: false,
		},
		{
			name: "Response time within range",
			opts: &FilterOptions{
				MinResponseTime: 100 * time.Millisecond,
				MaxResponseTime: 200 * time.Millisecond,
			},
			expect: true,
		},
		{
			name: "Response time outside range",
			opts: &FilterOptions{
				MinResponseTime: 200 * time.Millisecond,
				MaxResponseTime: 300 * time.Millisecond,
			},
			expect: false,
		},
		{
			name: "SSL valid",
			opts: &FilterOptions{
				SSLMustBeValid: true,
			},
			expect: true,
		},
		{
			name: "SSL days remaining pass",
			opts: &FilterOptions{
				SSLMinDaysRemaining: 30,
			},
			expect: true,
		},
		{
			name: "SSL days remaining fail",
			opts: &FilterOptions{
				SSLMinDaysRemaining: 90,
			},
			expect: false,
		},
		{
			name: "Content type match",
			opts: &FilterOptions{
				ContentTypeMustMatch: "text/html",
			},
			expect: true,
		},
		{
			name: "Content type not match",
			opts: &FilterOptions{
				ContentTypeMustMatch: "application/json",
			},
			expect: false,
		},
		{
			name: "IP match",
			opts: &FilterOptions{
				IPMustMatch: "93.184",
			},
			expect: true,
		},
		{
			name: "IP not match",
			opts: &FilterOptions{
				IPMustMatch: "1.1.1.1",
			},
			expect: false,
		},
		{
			name: "IPv6 required and present",
			opts: &FilterOptions{
				RequireIPv6: true,
			},
			expect: true,
		},
		{
			name: "Pattern include match",
			opts: &FilterOptions{
				IncludePattern: "Example",
			},
			expect: true,
		},
		{
			name: "Pattern include not match",
			opts: &FilterOptions{
				IncludePattern: "Nonexistent",
			},
			expect: false,
		},
		{
			name: "Pattern exclude match",
			opts: &FilterOptions{
				ExcludePattern: "Example",
			},
			expect: false,
		},
		{
			name: "Pattern exclude not match",
			opts: &FilterOptions{
				ExcludePattern: "Nonexistent",
			},
			expect: true,
		},
		{
			name: "Multiple filters all pass",
			opts: &FilterOptions{
				MinStatusCode:      200,
				ServerContains:     "nginx",
				HeaderKeyMustExist: []string{"Strict-Transport-Security"},
				SSLMustBeValid:     true,
				RequireIPv6:        true,
			},
			expect: true,
		},
		{
			name: "Multiple filters one fails",
			opts: &FilterOptions{
				MinStatusCode:      200,
				ServerContains:     "nginx",
				HeaderKeyMustExist: []string{"Content-Security-Policy"}, // This will fail
				SSLMustBeValid:     true,
			},
			expect: false,
		},
	}

	// Run test cases
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ApplyFilter(info, tc.opts)
			if result != tc.expect {
				t.Errorf("Expected %v but got %v", tc.expect, result)
			}
		})
	}
}

func TestBatchFilter(t *testing.T) {
	// Create sample website infos
	sites := []*WebsiteInfo{
		{
			URL:        "https://example1.com",
			StatusCode: 200,
			ServerInfo: "nginx",
			IP:         []string{"1.1.1.1"},
			SSLInfo:    &SSLInfo{Valid: true},
		},
		{
			URL:        "https://example2.com",
			StatusCode: 404,
			ServerInfo: "Apache",
			IP:         []string{"2.2.2.2"},
			SSLInfo:    &SSLInfo{Valid: false},
		},
		{
			URL:        "https://example3.com",
			StatusCode: 200,
			ServerInfo: "nginx",
			IP:         []string{"3.3.3.3", "2001:db8::1"},
			SSLInfo:    &SSLInfo{Valid: true},
		},
	}

	// Test batch filtering
	opts := &FilterOptions{
		MinStatusCode:  200,
		MaxStatusCode:  200,
		ServerContains: "nginx",
		SSLMustBeValid: true,
	}

	filtered := BatchFilter(sites, opts)
	
	if len(filtered) != 2 {
		t.Errorf("Expected 2 results but got %d", len(filtered))
	}

	// Test with IPv6 requirement
	optsIPv6 := &FilterOptions{
		RequireIPv6: true,
	}

	filteredIPv6 := BatchFilter(sites, optsIPv6)
	
	if len(filteredIPv6) != 1 {
		t.Errorf("Expected 1 result but got %d", len(filteredIPv6))
	}
}
