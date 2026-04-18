package blocklist

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
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
	reversed := reverseIP(ip)
	var wg sync.WaitGroup
	type listResult struct {
		list  string
		found bool
	}
	results := make(chan listResult, len(c.lists))

	for _, list := range c.lists {
		wg.Add(1)
		go func(list string) {
			defer wg.Done()
			query := fmt.Sprintf("%s.%s", reversed, list)
			addrs, err := c.resolver.LookupHost(ctx, query)
			if err != nil || len(addrs) == 0 {
				results <- listResult{list: list, found: false}
				return
			}
			c.logger.Debug("blocklist hit", "ip", ip, "list", list, "addrs", addrs)
			results <- listResult{list: list, found: true}
		}(list)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var hitLists []string
	for r := range results {
		if r.found {
			hitLists = append(hitLists, r.list)
		}
	}

	return Result{
		Listed:     len(hitLists) > 0,
		Blocklists: hitLists,
	}
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