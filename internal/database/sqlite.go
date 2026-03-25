package database

import (
	"database/sql"
	"fmt"
	"math/rand"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/venatiodecorus/proxy-scanner/internal/proxy"
)

// DB wraps a SQLite database connection.
type DB struct {
	db *sql.DB
}

// Open opens a SQLite database at the given path and runs migrations.
// Use ":memory:" for an in-memory database (tests).
func Open(path string) (*DB, error) {
	dsn := path + "?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL"
	if path == ":memory:" {
		dsn = ":memory:?_journal_mode=WAL"
	}

	sqlDB, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	sqlDB.SetMaxOpenConns(1) // SQLite handles one writer at a time
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(0)

	d := &DB{db: sqlDB}
	if err := d.migrate(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("running migrations: %w", err)
	}

	return d, nil
}

// Close closes the database connection.
func (d *DB) Close() error {
	return d.db.Close()
}

func (d *DB) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS proxies (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		ip          TEXT NOT NULL,
		port        INTEGER NOT NULL,
		protocol    TEXT NOT NULL,
		anonymity   TEXT,
		country     TEXT,
		city        TEXT,
		asn         INTEGER,
		asn_org     TEXT,
		latency_ms  INTEGER,
		last_seen   DATETIME NOT NULL,
		first_seen  DATETIME NOT NULL,
		alive       BOOLEAN DEFAULT TRUE,
		UNIQUE(ip, port, protocol)
	);

	CREATE TABLE IF NOT EXISTS scan_runs (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		started_at  DATETIME NOT NULL,
		finished_at DATETIME,
		candidates  INTEGER DEFAULT 0,
		verified    INTEGER DEFAULT 0,
		status      TEXT DEFAULT 'running'
	);

	CREATE INDEX IF NOT EXISTS idx_proxies_alive ON proxies(alive, protocol);
	CREATE INDEX IF NOT EXISTS idx_proxies_latency ON proxies(alive, latency_ms);
	CREATE INDEX IF NOT EXISTS idx_proxies_country ON proxies(alive, country);
	`
	_, err := d.db.Exec(schema)
	return err
}

// UpsertProxy inserts or updates a proxy record. If the proxy already exists
// (same ip, port, protocol), it updates the fields and sets alive=true.
func (d *DB) UpsertProxy(p *proxy.Proxy) error {
	now := time.Now().UTC()
	_, err := d.db.Exec(`
		INSERT INTO proxies (ip, port, protocol, anonymity, country, city, asn, asn_org, latency_ms, last_seen, first_seen, alive)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip, port, protocol) DO UPDATE SET
			anonymity = excluded.anonymity,
			country = excluded.country,
			city = excluded.city,
			asn = excluded.asn,
			asn_org = excluded.asn_org,
			latency_ms = excluded.latency_ms,
			last_seen = excluded.last_seen,
			alive = excluded.alive
	`, p.IP, p.Port, string(p.Protocol), string(p.Anonymity),
		p.Country, p.City, p.ASN, p.ASNOrg, p.LatencyMs, now, now, p.Alive)
	if err != nil {
		return fmt.Errorf("upserting proxy %s:%d: %w", p.IP, p.Port, err)
	}
	return nil
}

// MarkAllDead marks all currently alive proxies as dead. Called at the start
// of a new validation run so only freshly validated proxies remain alive.
func (d *DB) MarkAllDead() error {
	_, err := d.db.Exec("UPDATE proxies SET alive = FALSE")
	return err
}

// GetProxy returns a single proxy by ID.
func (d *DB) GetProxy(id int64) (*proxy.Proxy, error) {
	row := d.db.QueryRow(`
		SELECT id, ip, port, protocol, anonymity, country, city, asn, asn_org, latency_ms, last_seen, first_seen, alive
		FROM proxies WHERE id = ?
	`, id)
	return scanProxy(row)
}

// ListProxies returns proxies matching the given filter.
func (d *DB) ListProxies(f proxy.ProxyFilter) ([]proxy.Proxy, error) {
	query := "SELECT id, ip, port, protocol, anonymity, country, city, asn, asn_org, latency_ms, last_seen, first_seen, alive FROM proxies"
	where, args := buildWhere(f)
	if where != "" {
		query += " WHERE " + where
	}
	query += " ORDER BY latency_ms ASC"
	if f.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", f.Limit)
	}
	if f.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", f.Offset)
	}

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing proxies: %w", err)
	}
	defer rows.Close()

	var proxies []proxy.Proxy
	for rows.Next() {
		p, err := scanProxyRows(rows)
		if err != nil {
			return nil, err
		}
		proxies = append(proxies, *p)
	}
	return proxies, rows.Err()
}

// RandomProxy returns a random proxy matching the given filter.
func (d *DB) RandomProxy(f proxy.ProxyFilter) (*proxy.Proxy, error) {
	// Get count first, then pick a random offset.
	countQuery := "SELECT COUNT(*) FROM proxies"
	where, args := buildWhere(f)
	if where != "" {
		countQuery += " WHERE " + where
	}

	var count int
	if err := d.db.QueryRow(countQuery, args...).Scan(&count); err != nil {
		return nil, fmt.Errorf("counting proxies: %w", err)
	}
	if count == 0 {
		return nil, nil
	}

	offset := rand.Intn(count)
	query := "SELECT id, ip, port, protocol, anonymity, country, city, asn, asn_org, latency_ms, last_seen, first_seen, alive FROM proxies"
	if where != "" {
		query += " WHERE " + where
	}
	query += fmt.Sprintf(" LIMIT 1 OFFSET %d", offset)

	row := d.db.QueryRow(query, args...)
	return scanProxy(row)
}

// Stats returns aggregate statistics about the proxy database.
func (d *DB) Stats() (*proxy.Stats, error) {
	s := &proxy.Stats{
		ByProtocol:  make(map[string]int),
		ByAnonymity: make(map[string]int),
		ByCountry:   make(map[string]int),
	}

	// Total and alive counts
	d.db.QueryRow("SELECT COUNT(*) FROM proxies").Scan(&s.TotalProxies)
	d.db.QueryRow("SELECT COUNT(*) FROM proxies WHERE alive = TRUE").Scan(&s.AliveProxies)
	d.db.QueryRow("SELECT COALESCE(AVG(latency_ms), 0) FROM proxies WHERE alive = TRUE").Scan(&s.AvgLatencyMs)

	// By protocol
	rows, err := d.db.Query("SELECT protocol, COUNT(*) FROM proxies WHERE alive = TRUE GROUP BY protocol")
	if err != nil {
		return nil, fmt.Errorf("querying by protocol: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var proto string
		var count int
		if err := rows.Scan(&proto, &count); err != nil {
			return nil, err
		}
		s.ByProtocol[proto] = count
	}

	// By anonymity
	rows2, err := d.db.Query("SELECT COALESCE(anonymity, 'unknown'), COUNT(*) FROM proxies WHERE alive = TRUE GROUP BY anonymity")
	if err != nil {
		return nil, fmt.Errorf("querying by anonymity: %w", err)
	}
	defer rows2.Close()
	for rows2.Next() {
		var anon string
		var count int
		if err := rows2.Scan(&anon, &count); err != nil {
			return nil, err
		}
		s.ByAnonymity[anon] = count
	}

	// By country (top 20)
	rows3, err := d.db.Query("SELECT COALESCE(country, 'unknown'), COUNT(*) FROM proxies WHERE alive = TRUE GROUP BY country ORDER BY COUNT(*) DESC LIMIT 20")
	if err != nil {
		return nil, fmt.Errorf("querying by country: %w", err)
	}
	defer rows3.Close()
	for rows3.Next() {
		var country string
		var count int
		if err := rows3.Scan(&country, &count); err != nil {
			return nil, err
		}
		s.ByCountry[country] = count
	}

	// Last scan run
	run, err := d.LastScanRun()
	if err != nil {
		return nil, err
	}
	s.LastScanRun = run

	return s, nil
}

// StartScanRun creates a new scan run record and returns its ID.
func (d *DB) StartScanRun() (int64, error) {
	result, err := d.db.Exec(
		"INSERT INTO scan_runs (started_at, status) VALUES (?, 'running')",
		time.Now().UTC(),
	)
	if err != nil {
		return 0, fmt.Errorf("starting scan run: %w", err)
	}
	return result.LastInsertId()
}

// FinishScanRun marks a scan run as completed with the given stats.
func (d *DB) FinishScanRun(id int64, candidates, verified int, status string) error {
	_, err := d.db.Exec(
		"UPDATE scan_runs SET finished_at = ?, candidates = ?, verified = ?, status = ? WHERE id = ?",
		time.Now().UTC(), candidates, verified, status, id,
	)
	return err
}

// LastScanRun returns the most recent scan run, or nil if none exists.
func (d *DB) LastScanRun() (*proxy.ScanRun, error) {
	row := d.db.QueryRow(`
		SELECT id, started_at, finished_at, candidates, verified, status
		FROM scan_runs ORDER BY id DESC LIMIT 1
	`)

	var run proxy.ScanRun
	var finishedAt sql.NullTime
	err := row.Scan(&run.ID, &run.StartedAt, &finishedAt, &run.Candidates, &run.Verified, &run.Status)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("querying last scan run: %w", err)
	}
	if finishedAt.Valid {
		run.FinishedAt = &finishedAt.Time
	}
	return &run, nil
}

// buildWhere constructs a WHERE clause from a ProxyFilter.
func buildWhere(f proxy.ProxyFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}

	if f.AliveOnly {
		conditions = append(conditions, "alive = TRUE")
	}
	if f.Protocol != "" {
		conditions = append(conditions, "protocol = ?")
		args = append(args, string(f.Protocol))
	}
	if f.Anonymity != "" {
		conditions = append(conditions, "anonymity = ?")
		args = append(args, string(f.Anonymity))
	}
	if f.Country != "" {
		conditions = append(conditions, "country = ?")
		args = append(args, f.Country)
	}
	if f.MaxLatency > 0 {
		conditions = append(conditions, "latency_ms <= ?")
		args = append(args, f.MaxLatency)
	}

	return strings.Join(conditions, " AND "), args
}

// scannable is an interface for *sql.Row and *sql.Rows.
type scannable interface {
	Scan(dest ...interface{}) error
}

func scanProxy(s scannable) (*proxy.Proxy, error) {
	var p proxy.Proxy
	var protocol, anonymity string
	var country, city, asnOrg sql.NullString
	var latencyMs, asn sql.NullInt64
	err := s.Scan(
		&p.ID, &p.IP, &p.Port, &protocol, &anonymity,
		&country, &city, &asn, &asnOrg, &latencyMs,
		&p.LastSeen, &p.FirstSeen, &p.Alive,
	)
	if err != nil {
		return nil, err
	}
	p.Protocol = proxy.Protocol(protocol)
	p.Anonymity = proxy.Anonymity(anonymity)
	if country.Valid {
		p.Country = country.String
	}
	if city.Valid {
		p.City = city.String
	}
	if asn.Valid {
		p.ASN = int(asn.Int64)
	}
	if asnOrg.Valid {
		p.ASNOrg = asnOrg.String
	}
	if latencyMs.Valid {
		p.LatencyMs = int(latencyMs.Int64)
	}
	return &p, nil
}

func scanProxyRows(rows *sql.Rows) (*proxy.Proxy, error) {
	return scanProxy(rows)
}
