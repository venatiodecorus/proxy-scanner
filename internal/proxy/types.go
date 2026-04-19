package proxy

import "time"

// Protocol represents the type of proxy protocol.
type Protocol string

const (
	ProtocolHTTP   Protocol = "http"
	ProtocolHTTPS  Protocol = "https"
	ProtocolSOCKS4 Protocol = "socks4"
	ProtocolSOCKS5 Protocol = "socks5"
)

// Anonymity represents the anonymity level of a proxy.
type Anonymity string

const (
	AnonymityTransparent Anonymity = "transparent"
	AnonymityAnonymous   Anonymity = "anonymous"
	AnonymityElite       Anonymity = "elite"
)

// ProxyStatus values describe the lifecycle state of a proxy in the database.
const (
	// ProxyStatusActive indicates the proxy was validated recently. API
	// consumers receive only active proxies by default.
	ProxyStatusActive = "active"
	// ProxyStatusStale indicates the proxy has failed enough consecutive
	// rechecks to be hidden from the API, but is still kept around in case
	// it comes back. Stale proxies are eventually evicted.
	ProxyStatusStale = "stale"
)

// Proxy represents a validated proxy server.
type Proxy struct {
	ID                  int64      `json:"id"`
	IP                  string     `json:"ip"`
	Port                int        `json:"port"`
	Protocol            Protocol   `json:"protocol"`
	Anonymity           Anonymity  `json:"anonymity,omitempty"`
	Country             string     `json:"country,omitempty"`
	City                string     `json:"city,omitempty"`
	ASN                 int        `json:"asn,omitempty"`
	ASNOrg              string     `json:"asn_org,omitempty"`
	ExitIP              string     `json:"exit_ip,omitempty"`
	LatencyMs           int        `json:"latency_ms,omitempty"`
	SupportsConnect     bool       `json:"supports_connect"`
	TLSInsecure         bool       `json:"tls_insecure"`
	Blocklisted         bool       `json:"blocklisted"`
	Blocklists          string     `json:"blocklists,omitempty"`
	LastSeen            time.Time  `json:"last_seen"`
	FirstSeen           time.Time  `json:"first_seen"`
	LastCheckedAt       *time.Time `json:"last_checked_at,omitempty"`
	LastOkAt            *time.Time `json:"last_ok_at,omitempty"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	CheckCount          int        `json:"check_count"`
	SuccessCount        int        `json:"success_count"`
	Status              string     `json:"status"`
	// Alive is a legacy field derived from Status == ProxyStatusActive.
	// Kept for backward compatibility with existing API consumers; new code
	// should read Status instead.
	Alive bool `json:"alive"`
}

// Candidate represents a raw scan result from masscan — an IP:port pair
// that has an open port but has not yet been validated as a working proxy.
type Candidate struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// CheckResult is the outcome of validating a single candidate.
type CheckResult struct {
	Candidate       Candidate
	Protocol        Protocol
	Anonymity       Anonymity
	ExitIP          string
	Country         string
	City            string
	LatencyMs       int
	SupportsConnect bool
	TLSInsecure     bool
	Alive           bool
	Error           error
}

// ScanRun tracks metadata about a scan/validation run.
type ScanRun struct {
	ID         int64      `json:"id"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Candidates int        `json:"candidates"`
	Verified   int        `json:"verified"`
	Status     string     `json:"status"`
}

// ProxyFilter contains query parameters for filtering proxies.
type ProxyFilter struct {
	Protocol   Protocol  `json:"protocol,omitempty"`
	Anonymity  Anonymity `json:"anonymity,omitempty"`
	Country    string    `json:"country,omitempty"`
	MaxLatency int       `json:"max_latency,omitempty"`
	Blocklisted *bool    `json:"blocklisted,omitempty"`
	AliveOnly  bool      `json:"alive_only"`
	Limit      int       `json:"limit,omitempty"`
	Offset     int       `json:"offset,omitempty"`
}

// CandidateEntry represents a candidate in the validation queue.
// It tracks candidates from the scanner through the validation pipeline.
type CandidateEntry struct {
	ID        int64     `json:"id"`
	IP        string    `json:"ip"`
	Port      int       `json:"port"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CandidateStatus constants for the validation queue.
const (
	CandidateStatusPending    = "pending"
	CandidateStatusProcessing = "processing"
)

// Stats contains aggregate statistics about the proxy database.
type Stats struct {
	TotalProxies int            `json:"total_proxies"`
	AliveProxies int            `json:"alive_proxies"`
	ByProtocol   map[string]int `json:"by_protocol"`
	ByAnonymity  map[string]int `json:"by_anonymity"`
	ByCountry    map[string]int `json:"by_country"`
	LastScanRun  *ScanRun       `json:"last_scan_run,omitempty"`
	AvgLatencyMs int            `json:"avg_latency_ms"`
}
