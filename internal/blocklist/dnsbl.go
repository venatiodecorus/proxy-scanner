package blocklist

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	EFnetList           = "rbl.efnetrbl.org"
	efnetLookupTimeout  = 5 * time.Second
	efnetLookupAttempts = 2
	efnetRetryDelay     = 250 * time.Millisecond
)

var defaultLists = []string{
	"zen.spamhaus.org",
	"dnsbl-1.uceprotect.net",
	"dnsbl.sorbs.net",
	"dnsbl.dronebl.org",
}

type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

type Result struct {
	Listed     bool
	Blocklists []string
	Errors     map[string]error
}

// LookupResult is the outcome of checking one IP against one DNSBL. A nil Err
// with Listed=false means the resolver returned an authoritative not-found
// response. Any other resolver failure is indeterminate and must not be treated
// as proof that the IP is eligible for a mandatory blocklist policy.
type LookupResult struct {
	List      string
	Listed    bool
	Addresses []string
	Err       error
}

type Checker struct {
	lists    []string
	logger   *slog.Logger
	resolver Resolver
}

type Option func(*Checker)

func WithLists(lists []string) Option {
	return func(c *Checker) {
		c.lists = lists
	}
}

func WithLogger(logger *slog.Logger) Option {
	return func(c *Checker) {
		c.logger = logger
	}
}

func WithResolver(r Resolver) Option {
	return func(c *Checker) {
		c.resolver = r
	}
}

func NewChecker(opts ...Option) *Checker {
	c := &Checker{
		lists:    defaultLists,
		logger:   slog.Default(),
		resolver: net.DefaultResolver,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *Checker) Check(ctx context.Context, ip string) Result {
	var wg sync.WaitGroup
	results := make(chan LookupResult, len(c.lists))

	for _, list := range c.lists {
		wg.Add(1)
		go func(list string) {
			defer wg.Done()
			results <- c.CheckList(ctx, ip, list)
		}(list)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var hitLists []string
	lookupErrors := make(map[string]error)
	for r := range results {
		if r.Listed {
			hitLists = append(hitLists, r.List)
		}
		if r.Err != nil {
			lookupErrors[r.List] = r.Err
		}
	}
	if len(lookupErrors) == 0 {
		lookupErrors = nil
	}

	return Result{
		Listed:     len(hitLists) > 0,
		Blocklists: hitLists,
		Errors:     lookupErrors,
	}
}

// CheckList checks one IPv4 address against one DNSBL. DNS not-found is the
// only clean result; timeouts, SERVFAIL, cancellation, and other resolver
// failures are returned as indeterminate errors.
func (c *Checker) CheckList(ctx context.Context, ip, list string) LookupResult {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return LookupResult{List: list, Err: fmt.Errorf("invalid IPv4 address %q", ip)}
	}

	query := fmt.Sprintf("%s.%s", reverseIP(ip), list)
	addrs, err := c.resolver.LookupHost(ctx, query)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return LookupResult{List: list}
		}
		return LookupResult{List: list, Err: fmt.Errorf("looking up %s: %w", query, err)}
	}
	if len(addrs) == 0 {
		return LookupResult{List: list, Err: fmt.Errorf("looking up %s: empty DNS response", query)}
	}

	c.logger.Debug("blocklist hit", "ip", ip, "list", list, "addrs", addrs)
	return LookupResult{List: list, Listed: true, Addresses: addrs}
}

// CheckEFnet applies bounded retries and a hard timeout to the mandatory EFnet
// lookup. Callers must treat a non-nil Err as an indeterminate eligibility
// result rather than as not listed.
func (c *Checker) CheckEFnet(ctx context.Context, ip string) LookupResult {
	lookupCtx, cancel := context.WithTimeout(ctx, efnetLookupTimeout)
	defer cancel()
	return c.CheckListWithRetry(lookupCtx, ip, EFnetList, efnetLookupAttempts, efnetRetryDelay)
}

// CheckListWithRetry retries only indeterminate lookups. Listed and
// authoritative not-listed results are returned immediately.
func (c *Checker) CheckListWithRetry(ctx context.Context, ip, list string, attempts int, retryDelay time.Duration) LookupResult {
	if attempts < 1 {
		attempts = 1
	}

	var result LookupResult
	for attempt := 1; attempt <= attempts; attempt++ {
		result = c.CheckList(ctx, ip, list)
		if result.Err == nil || attempt == attempts {
			return result
		}

		timer := time.NewTimer(retryDelay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return LookupResult{List: list, Err: ctx.Err()}
		case <-timer.C:
		}
	}
	return result
}

func (c *Checker) CheckBatch(ctx context.Context, ips []string) map[string]Result {
	results := make(map[string]Result, len(ips))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			r := c.Check(ctx, ip)
			mu.Lock()
			results[ip] = r
			mu.Unlock()
		}(ip)
	}
	wg.Wait()

	return results
}

func (r Result) BlocklistsString() string {
	if len(r.Blocklists) == 0 {
		return ""
	}
	shortNames := make([]string, len(r.Blocklists))
	for i, bl := range r.Blocklists {
		parts := strings.SplitN(bl, ".", 2)
		shortNames[i] = parts[0]
	}
	return strings.Join(shortNames, ",")
}

func reverseIP(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ip
	}
	return fmt.Sprintf("%s.%s.%s.%s", parts[3], parts[2], parts[1], parts[0])
}
