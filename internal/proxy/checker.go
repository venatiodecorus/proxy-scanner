package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var ipRegex = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)

type CheckerConfig struct {
	Timeout  time.Duration
	TestURL  string
	OriginIP string
	Logger   *slog.Logger
}

func DefaultConfig() CheckerConfig {
	return CheckerConfig{
		Timeout: 10 * time.Second,
		TestURL: "http://httpbin.org/ip",
		Logger:  slog.Default(),
	}
}

type Checker struct {
	cfg CheckerConfig
}

func NewChecker(cfg CheckerConfig) *Checker {
	return &Checker{cfg: cfg}
}

func (c *Checker) Check(ctx context.Context, candidate Candidate) []CheckResult {
	var results []CheckResult

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

func (c *Checker) checkHTTP(ctx context.Context, candidate Candidate) *CheckResult {
	proxyURL := fmt.Sprintf("http://%s:%d", candidate.IP, candidate.Port)
	return c.checkHTTPProxy(ctx, candidate, proxyURL, ProtocolHTTP)
}

func (c *Checker) checkHTTPS(ctx context.Context, candidate Candidate) *CheckResult {
	proxyURL := fmt.Sprintf("http://%s:%d", candidate.IP, candidate.Port)
	return c.checkHTTPProxy(ctx, candidate, proxyURL, ProtocolHTTPS)
}

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
		testURL = strings.Replace(testURL, "http://", "https://", 1)
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(pURL),
		DialContext: (&net.Dialer{
			Timeout: c.cfg.Timeout,
		}).DialContext,
		TLSHandshakeTimeout: c.cfg.Timeout,
		DisableKeepAlives:    true,
	}

	if proto == ProtocolHTTPS {
		transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: c.cfg.Timeout}
			rawConn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			host, _, _ := net.SplitHostPort(addr)
			tlsConn := tls.Client(rawConn, &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         host,
			})
			if err := tlsConn.Handshake(); err != nil {
				rawConn.Close()
				return nil, err
			}
			state := tlsConn.ConnectionState()
			verified := len(state.VerifiedChains) > 0
			if !verified {
				result.TLSInsecure = true
			} else {
				for _, chain := range state.VerifiedChains {
					for _, cert := range chain {
						if cert.VerifyHostname(host) != nil {
							result.TLSInsecure = true
						}
					}
				}
			}
			return tlsConn, nil
		}
	} else {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
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
	result.ExitIP = extractIP(string(body))
	result.Anonymity = c.detectAnonymity(resp.Header, string(body))

	if proto == ProtocolHTTP {
		result.SupportsConnect = c.checkConnectMethod(ctx, candidate)
	}

	return result
}

func (c *Checker) checkConnectMethod(ctx context.Context, candidate Candidate) bool {
	proxyAddr := fmt.Sprintf("%s:%d", candidate.IP, candidate.Port)
	testHost := extractHostFromURL(c.cfg.TestURL)
	_, port, err := net.SplitHostPort(testHost)
	if err != nil {
		port = "80"
	}
	host := strings.TrimSuffix(testHost, ":"+port)

	connectReq := fmt.Sprintf("CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\n\r\n", host, port, host, port)

	dialer := &net.Dialer{Timeout: c.cfg.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return false
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if ok {
		conn.SetDeadline(deadline)
	}

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		return false
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	return strings.Contains(line, "200")
}

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

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		result.Error = fmt.Errorf("socks5 greeting: %w", err)
		return result
	}

	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		result.Error = fmt.Errorf("socks5 greeting response: %w", err)
		return result
	}
	if greeting[0] != 0x05 || greeting[1] != 0x00 {
		result.Error = fmt.Errorf("socks5: unsupported auth method %d", greeting[1])
		return result
	}

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

	connectResp := make([]byte, 4)
	if _, err := io.ReadFull(conn, connectResp); err != nil {
		result.Error = fmt.Errorf("socks5 connect response: %w", err)
		return result
	}
	if connectResp[1] != 0x00 {
		result.Error = fmt.Errorf("socks5: connect failed with code %d", connectResp[1])
		return result
	}

	switch connectResp[3] {
	case 0x01:
		discard := make([]byte, 4+2)
		io.ReadFull(conn, discard)
	case 0x03:
		lenBuf := make([]byte, 1)
		io.ReadFull(conn, lenBuf)
		discard := make([]byte, int(lenBuf[0])+2)
		io.ReadFull(conn, discard)
	case 0x04:
		discard := make([]byte, 16+2)
		io.ReadFull(conn, discard)
	}

	httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (compatible; proxy-check/1.0)\r\nConnection: close\r\n\r\n", host)
	if _, err := conn.Write([]byte(httpReq)); err != nil {
		result.Error = fmt.Errorf("socks5 http request: %w", err)
		return result
	}

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
	result.ExitIP = extractIP(string(body))

	return result
}

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

	connectReq := []byte{0x04, 0x01}
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	connectReq = append(connectReq, portBytes...)
	connectReq = append(connectReq, targetIP...)
	connectReq = append(connectReq, 0x00)

	if _, err := conn.Write(connectReq); err != nil {
		result.Error = fmt.Errorf("socks4 connect: %w", err)
		return result
	}

	resp4 := make([]byte, 8)
	if _, err := io.ReadFull(conn, resp4); err != nil {
		result.Error = fmt.Errorf("socks4 response: %w", err)
		return result
	}
	if resp4[1] != 0x5A {
		result.Error = fmt.Errorf("socks4: connect failed with code 0x%02X", resp4[1])
		return result
	}

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
	result.ExitIP = extractIP(string(body))

	return result
}

func (c *Checker) detectAnonymity(headers http.Header, body string) Anonymity {
	if c.cfg.OriginIP == "" {
		return AnonymityAnonymous
	}

	originInBody := strings.Contains(body, c.cfg.OriginIP)

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

func extractIP(body string) string {
	match := ipRegex.FindString(body)
	return match
}

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

func extractHostFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Host
}

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