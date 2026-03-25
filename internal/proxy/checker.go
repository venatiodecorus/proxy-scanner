package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CheckerConfig holds configuration for the proxy checker.
type CheckerConfig struct {
	// Timeout is the maximum time to wait for a proxy check.
	Timeout time.Duration

	// TestURL is the URL to request through the proxy to validate it.
	// Should return the requesting IP in the response body.
	TestURL string

	// OriginIP is the scanner's own IP address, used for anonymity detection.
	// If empty, anonymity detection is skipped.
	OriginIP string

	// Logger for structured logging.
	Logger *slog.Logger
}

// DefaultConfig returns a CheckerConfig with sensible defaults.
func DefaultConfig() CheckerConfig {
	return CheckerConfig{
		Timeout: 10 * time.Second,
		TestURL: "http://httpbin.org/ip",
		Logger:  slog.Default(),
	}
}

// Checker validates proxy candidates.
type Checker struct {
	cfg CheckerConfig
}

// NewChecker creates a new Checker with the given config.
func NewChecker(cfg CheckerConfig) *Checker {
	return &Checker{cfg: cfg}
}

// Check tests a candidate across all proxy protocols and returns results
// for each protocol that works. Returns nil results if nothing works.
func (c *Checker) Check(ctx context.Context, candidate Candidate) []CheckResult {
	var results []CheckResult

	// Try each protocol. A single IP:port may support multiple protocols.
	protocols := []struct {
		proto Protocol
		check func(ctx context.Context, candidate Candidate) *CheckResult
	}{
		{ProtocolHTTP, c.checkHTTP},
		{ProtocolHTTPS, c.checkHTTPS},
		{ProtocolSOCKS5, c.checkSOCKS5},
		{ProtocolSOCKS4, c.checkSOCKS4},
	}

	for _, p := range protocols {
		result := p.check(ctx, candidate)
		if result != nil && result.Alive {
			results = append(results, *result)
		}
	}

	return results
}

// checkHTTP tests if the candidate works as an HTTP proxy.
func (c *Checker) checkHTTP(ctx context.Context, candidate Candidate) *CheckResult {
	proxyURL := fmt.Sprintf("http://%s:%d", candidate.IP, candidate.Port)
	return c.checkHTTPProxy(ctx, candidate, proxyURL, ProtocolHTTP)
}

// checkHTTPS tests if the candidate works as an HTTPS (CONNECT) proxy.
func (c *Checker) checkHTTPS(ctx context.Context, candidate Candidate) *CheckResult {
	proxyURL := fmt.Sprintf("http://%s:%d", candidate.IP, candidate.Port)
	return c.checkHTTPProxy(ctx, candidate, proxyURL, ProtocolHTTPS)
}

// checkHTTPProxy performs the actual HTTP/HTTPS proxy check.
func (c *Checker) checkHTTPProxy(ctx context.Context, candidate Candidate, proxyURL string, proto Protocol) *CheckResult {
	result := &CheckResult{
		Candidate: candidate,
		Protocol:  proto,
		Alive:     false,
	}

	pURL, err := url.Parse(proxyURL)
	if err != nil {
		result.Error = fmt.Errorf("parsing proxy URL: %w", err)
		return result
	}

	testURL := c.cfg.TestURL
	if proto == ProtocolHTTPS {
		// For HTTPS proxy test, use an HTTPS target to force CONNECT tunnel
		testURL = strings.Replace(testURL, "http://", "https://", 1)
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(pURL),
		DialContext: (&net.Dialer{
			Timeout: c.cfg.Timeout,
		}).DialContext,
		TLSHandshakeTimeout: c.cfg.Timeout,
		DisableKeepAlives:   true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   c.cfg.Timeout,
	}
	defer client.CloseIdleConnections()

	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		result.Error = fmt.Errorf("creating request: %w", err)
		return result
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; proxy-check/1.0)")

	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start)
	if err != nil {
		result.Error = fmt.Errorf("proxy request: %w", err)
		return result
	}
	defer resp.Body.Close()

	// Read body (limited to 4KB — we only need the IP)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		result.Error = fmt.Errorf("reading response: %w", err)
		return result
	}

	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Errorf("unexpected status: %d", resp.StatusCode)
		return result
	}

	result.Alive = true
	result.LatencyMs = int(latency.Milliseconds())
	result.Anonymity = c.detectAnonymity(resp.Header, string(body))

	return result
}

// checkSOCKS5 tests if the candidate works as a SOCKS5 proxy.
func (c *Checker) checkSOCKS5(ctx context.Context, candidate Candidate) *CheckResult {
	result := &CheckResult{
		Candidate: candidate,
		Protocol:  ProtocolSOCKS5,
		Alive:     false,
	}

	proxyAddr := fmt.Sprintf("%s:%d", candidate.IP, candidate.Port)
	targetHost := extractHost(c.cfg.TestURL)
	if targetHost == "" {
		result.Error = fmt.Errorf("could not extract host from test URL")
		return result
	}

	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	start := time.Now()

	// Connect to the SOCKS5 proxy
	dialer := &net.Dialer{Timeout: c.cfg.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		result.Error = fmt.Errorf("connecting to proxy: %w", err)
		return result
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if ok {
		conn.SetDeadline(deadline)
	}

	// SOCKS5 handshake
	// Send greeting: version 5, 1 auth method (no auth)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		result.Error = fmt.Errorf("socks5 greeting: %w", err)
		return result
	}

	// Read server choice
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		result.Error = fmt.Errorf("socks5 greeting response: %w", err)
		return result
	}
	if greeting[0] != 0x05 || greeting[1] != 0x00 {
		result.Error = fmt.Errorf("socks5: unsupported auth method %d", greeting[1])
		return result
	}

	// Send connect request
	// Version(1) + CMD_CONNECT(1) + RSV(1) + ATYP_DOMAIN(1) + domain_len(1) + domain + port(2)
	host, port := splitHostPort(targetHost, 80)
	connectReq := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	connectReq = append(connectReq, []byte(host)...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	connectReq = append(connectReq, portBytes...)

	if _, err := conn.Write(connectReq); err != nil {
		result.Error = fmt.Errorf("socks5 connect: %w", err)
		return result
	}

	// Read connect response (at least 4 bytes for header)
	connectResp := make([]byte, 4)
	if _, err := io.ReadFull(conn, connectResp); err != nil {
		result.Error = fmt.Errorf("socks5 connect response: %w", err)
		return result
	}
	if connectResp[1] != 0x00 {
		result.Error = fmt.Errorf("socks5: connect failed with code %d", connectResp[1])
		return result
	}

	// Read the rest of the response based on address type
	switch connectResp[3] {
	case 0x01: // IPv4
		discard := make([]byte, 4+2) // 4 bytes IP + 2 bytes port
		io.ReadFull(conn, discard)
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		io.ReadFull(conn, lenBuf)
		discard := make([]byte, int(lenBuf[0])+2)
		io.ReadFull(conn, discard)
	case 0x04: // IPv6
		discard := make([]byte, 16+2)
		io.ReadFull(conn, discard)
	}

	// Now we have a tunnel — send HTTP request through it
	httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (compatible; proxy-check/1.0)\r\nConnection: close\r\n\r\n", host)
	if _, err := conn.Write([]byte(httpReq)); err != nil {
		result.Error = fmt.Errorf("socks5 http request: %w", err)
		return result
	}

	// Read HTTP response
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		result.Error = fmt.Errorf("socks5 http response: %w", err)
		return result
	}
	defer resp.Body.Close()

	latency := time.Since(start)

	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Errorf("socks5: unexpected status %d", resp.StatusCode)
		return result
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	result.Alive = true
	result.LatencyMs = int(latency.Milliseconds())
	result.Anonymity = c.detectAnonymity(resp.Header, string(body))

	return result
}

// checkSOCKS4 tests if the candidate works as a SOCKS4 proxy.
func (c *Checker) checkSOCKS4(ctx context.Context, candidate Candidate) *CheckResult {
	result := &CheckResult{
		Candidate: candidate,
		Protocol:  ProtocolSOCKS4,
		Alive:     false,
	}

	proxyAddr := fmt.Sprintf("%s:%d", candidate.IP, candidate.Port)
	targetHost := extractHost(c.cfg.TestURL)
	if targetHost == "" {
		result.Error = fmt.Errorf("could not extract host from test URL")
		return result
	}

	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	start := time.Now()

	dialer := &net.Dialer{Timeout: c.cfg.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		result.Error = fmt.Errorf("connecting to proxy: %w", err)
		return result
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if ok {
		conn.SetDeadline(deadline)
	}

	// Resolve target host to IP (SOCKS4 requires IP, not domain)
	host, port := splitHostPort(targetHost, 80)
	ips, err := net.LookupHost(host)
	if err != nil || len(ips) == 0 {
		result.Error = fmt.Errorf("resolving target host: %w", err)
		return result
	}
	targetIP := net.ParseIP(ips[0]).To4()
	if targetIP == nil {
		result.Error = fmt.Errorf("target resolved to non-IPv4: %s", ips[0])
		return result
	}

	// SOCKS4 connect request:
	// VN(1) + CD(1) + DSTPORT(2) + DSTIP(4) + USERID + NULL(1)
	connectReq := []byte{0x04, 0x01}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	connectReq = append(connectReq, portBytes...)
	connectReq = append(connectReq, targetIP...)
	connectReq = append(connectReq, 0x00) // null-terminated user ID

	if _, err := conn.Write(connectReq); err != nil {
		result.Error = fmt.Errorf("socks4 connect: %w", err)
		return result
	}

	// Read response (8 bytes)
	resp4 := make([]byte, 8)
	if _, err := io.ReadFull(conn, resp4); err != nil {
		result.Error = fmt.Errorf("socks4 response: %w", err)
		return result
	}
	// resp4[1] should be 0x5A for success
	if resp4[1] != 0x5A {
		result.Error = fmt.Errorf("socks4: connect failed with code 0x%02X", resp4[1])
		return result
	}

	// Send HTTP request through tunnel
	httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (compatible; proxy-check/1.0)\r\nConnection: close\r\n\r\n", host)
	if _, err := conn.Write([]byte(httpReq)); err != nil {
		result.Error = fmt.Errorf("socks4 http request: %w", err)
		return result
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		result.Error = fmt.Errorf("socks4 http response: %w", err)
		return result
	}
	defer resp.Body.Close()

	latency := time.Since(start)

	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Errorf("socks4: unexpected status %d", resp.StatusCode)
		return result
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	result.Alive = true
	result.LatencyMs = int(latency.Milliseconds())
	result.Anonymity = c.detectAnonymity(resp.Header, string(body))

	return result
}

// detectAnonymity determines the anonymity level based on headers and response body.
func (c *Checker) detectAnonymity(headers http.Header, body string) Anonymity {
	if c.cfg.OriginIP == "" {
		// Can't detect without knowing our own IP
		return AnonymityAnonymous
	}

	// Check if our origin IP appears in the response body
	originInBody := strings.Contains(body, c.cfg.OriginIP)

	// Check proxy-revealing headers
	proxyHeaders := []string{
		"X-Forwarded-For",
		"X-Real-IP",
		"Via",
		"X-Proxy-ID",
		"Forwarded",
	}

	hasProxyHeaders := false
	originInHeaders := false
	for _, h := range proxyHeaders {
		val := headers.Get(h)
		if val != "" {
			hasProxyHeaders = true
			if strings.Contains(val, c.cfg.OriginIP) {
				originInHeaders = true
			}
		}
	}

	if originInBody || originInHeaders {
		return AnonymityTransparent
	}
	if hasProxyHeaders {
		return AnonymityAnonymous
	}
	return AnonymityElite
}

// extractHost extracts the host:port from a URL string.
func extractHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(host, port)
}

// splitHostPort splits a host:port string, returning defaults for missing port.
func splitHostPort(hostport string, defaultPort int) (string, int) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport, defaultPort
	}
	port := defaultPort
	if portStr != "" {
		fmt.Sscanf(portStr, "%d", &port)
	}
	return host, port
}
