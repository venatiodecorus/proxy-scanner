package proxy

import (
	"net/http"
	"testing"
)

func TestDetectAnonymity(t *testing.T) {
	checker := NewChecker(CheckerConfig{
		OriginIP: "203.0.113.10",
	})

	tests := []struct {
		name    string
		headers http.Header
		body    string
		want    Anonymity
	}{
		{
			name:    "elite - no headers, no origin IP in body",
			headers: http.Header{},
			body:    `{"origin": "45.33.32.156"}`,
			want:    AnonymityElite,
		},
		{
			name: "anonymous - proxy headers but no origin IP",
			headers: http.Header{
				"Via": []string{"1.1 proxy.example.com"},
			},
			body: `{"origin": "45.33.32.156"}`,
			want: AnonymityAnonymous,
		},
		{
			name: "transparent - origin IP in X-Forwarded-For",
			headers: http.Header{
				"X-Forwarded-For": []string{"203.0.113.10"},
			},
			body: `{"origin": "45.33.32.156"}`,
			want: AnonymityTransparent,
		},
		{
			name:    "transparent - origin IP in body",
			headers: http.Header{},
			body:    `{"origin": "203.0.113.10"}`,
			want:    AnonymityTransparent,
		},
		{
			name: "transparent - origin IP in Via header",
			headers: http.Header{
				"Via": []string{"1.1 203.0.113.10"},
			},
			body: `{"origin": "45.33.32.156"}`,
			want: AnonymityTransparent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checker.detectAnonymity(tt.headers, tt.body)
			if got != tt.want {
				t.Errorf("detectAnonymity() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestDetectAnonymityNoOriginIP(t *testing.T) {
	// When OriginIP is not set, should default to anonymous
	checker := NewChecker(CheckerConfig{
		OriginIP: "",
	})

	got := checker.detectAnonymity(http.Header{}, `{"origin": "anything"}`)
	if got != AnonymityAnonymous {
		t.Errorf("expected anonymous when origin IP unknown, got %s", got)
	}
}

func TestExtractHost(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"http://httpbin.org/ip", "httpbin.org:80"},
		{"https://httpbin.org/ip", "httpbin.org:443"},
		{"http://example.com:8080/path", "example.com:8080"},
		{"https://example.com:9443/", "example.com:9443"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := extractHost(tt.url)
			if got != tt.want {
				t.Errorf("extractHost(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestSplitHostPort(t *testing.T) {
	tests := []struct {
		input       string
		defaultPort int
		wantHost    string
		wantPort    int
	}{
		{"example.com:80", 80, "example.com", 80},
		{"example.com:8080", 80, "example.com", 8080},
		{"example.com", 80, "example.com", 80},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			host, port := splitHostPort(tt.input, tt.defaultPort)
			if host != tt.wantHost || port != tt.wantPort {
				t.Errorf("splitHostPort(%q, %d) = (%q, %d), want (%q, %d)",
					tt.input, tt.defaultPort, host, port, tt.wantHost, tt.wantPort)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Timeout == 0 {
		t.Error("expected non-zero timeout")
	}
	if cfg.TestURL == "" {
		t.Error("expected non-empty test URL")
	}
	if cfg.Logger == nil {
		t.Error("expected non-nil logger")
	}
}
