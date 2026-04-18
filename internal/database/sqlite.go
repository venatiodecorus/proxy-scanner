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
		id               INTEGER PRIMARY KEY AUTOINCREMENT,
		ip               TEXT NOT NULL,
		port             INTEGER NOT NULL,
		protocol         TEXT NOT NULL,
		anonymity        TEXT,
		country          TEXT,
		city             TEXT,
		asn              INTEGER,
		asn_org          TEXT,
		exit_ip          TEXT,
		latency_ms       INTEGER,
		supports_connect BOOLEAN DEFAULT FALSE,
		tls_insecure     BOOLEAN DEFAULT FALSE,
		blocklisted      BOOLEAN DEFAULT FALSE,
		blocklists       TEXT,
		last_seen        DATETIME NOT NULL,
		first_seen       DATETIME NOT NULL,
		alive            BOOLEAN DEFAULT TRUE,
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
	CREATE INDEX IF NOT EXISTS idx_proxies_blocklisted ON proxies(alive, blocklisted);

	CREATE TABLE IF NOT EXISTS candidates (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		ip         TEXT NOT NULL,
		port       INTEGER NOT NULL,
		status     TEXT NOT NULL DEFAULT 'pending',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(ip, port)
	);

	CREATE INDEX IF NOT EXISTS idx_candidates_status ON candidates(status);
	CREATE INDEX IF NOT EXISTS idx_candidates_ip_port ON candidates(ip, port);
	`
	_, err := d.db.Exec(schema)
	if err != nil {
		return err
	}

	var exitIPExists int
	d.db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('proxies') WHERE name = 'exit_ip'").Scan(&exitIPExists)
	if exitIPExists == 0 {
		if _, err := d.db.Exec("ALTER TABLE proxies ADD COLUMN exit_ip TEXT"); err != nil {
			return fmt.Errorf("migrating exit_ip column: %w", err)
		}
	}

	var supportsConnectExists int
	d.db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('proxies') WHERE name = 'supports_connect'").Scan(&supportsConnectExists)
	if supportsConnectExists == 0 {
		if _, err := d.db.Exec("ALTER TABLE proxies ADD COLUMN supports_connect BOOLEAN DEFAULT FALSE"); err != nil {
			return fmt.Errorf("migrating supports_connect column: %w", err)
		}
	}

	var tlsInsecureExists int
	d.db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('proxies') WHERE name = 'tls_insecure'").Scan(&tlsInsecureExists)
	if tlsInsecureExists == 0 {
		if _, err := d.db.Exec("ALTER TABLE proxies ADD COLUMN tls_insecure BOOLEAN DEFAULT FALSE"); err != nil {
			return fmt.Errorf("migrating tls_insecure column: %w", err)
		}
	}

	var blocklistedExists int
	d.db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('proxies') WHERE name = 'blocklisted'").Scan(&blocklistedExists)
	if blocklistedExists == 0 {
		if _, err := d.db.Exec("ALTER TABLE proxies ADD COLUMN blocklisted BOOLEAN DEFAULT FALSE"); err != nil {
			return fmt.Errorf("migrating blocklisted column: %w", err)
		}
	}

	var blocklistsExists int
	d.db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('proxies') WHERE name = 'blocklists'").Scan(&blocklistsExists)
	if blocklistsExists == 0 {
		if _, err := d.db.Exec("ALTER TABLE proxies ADD COLUMN blocklists TEXT"); err != nil {
			return fmt.Errorf("migrating blocklists column: %w", err)
		}
	}

	return nil
}

// UpsertProxy inserts or updates a proxy record. If the proxy already exists
// (same ip, port, protocol), it updates the fields and sets alive=true.
func (d *DB) UpsertProxy(p *proxy.Proxy) error {
	now := time.Now().UTC()
	_, err := d.db.Exec(`
		INSERT INTO proxies (ip, port, protocol, anonymity, country, city, asn, asn_org, exit_ip, latency_ms, supports_connect, tls_insecure, blocklisted, blocklists, last_seen, first_seen, alive)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip, port, protocol) DO UPDATE SET
			anonymity = excluded.anonymity,
			country = excluded.country,
			city = excluded.city,
			asn = excluded.asn,
			asn_org = excluded.asn_org,
			exit_ip = excluded.exit_ip,
			latency_ms = excluded.latency_ms,
			supports_connect = excluded.supports_connect,
			tls_insecure = excluded.tls_insecure,
			blocklisted = excluded.blocklisted,
			blocklists = excluded.blocklists,
			last_seen = excluded.last_seen,
			alive = excluded.alive
	`, p.IP, p.Port, string(p.Protocol), string(p.Anonymity),
		p.Country, p.City, p.ASN, p.ASNOrg, p.ExitIP, p.LatencyMs,
		p.SupportsConnect, p.TLSInsecure, p.Blocklisted, p.Blocklists,
		now, now, p.Alive)
	if err != nil {
		return fmt.Errorf("upserting proxy %s:%d: %w", p.IP, p.Port, err)
	}
	return nil
}

// EnqueueCandidates inserts candidates into the queue, skipping duplicates.
// Returns the number of newly enqueued candidates.
func (d *DB) EnqueueCandidates(candidates []proxy.Candidate) (int64, error) {
	tx, err := d.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("INSERT OR IGNORE INTO candidates (ip, port, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		return 0, fmt.Errorf("preparing insert: %w", err)
	}
	defer stmt.Close()

	var enqueued int64
	now := time.Now().UTC()
	for _, c := range candidates {
		result, err := stmt.Exec(c.IP, c.Port, proxy.CandidateStatusPending, now, now)
		if err != nil {
			return 0, fmt.Errorf("inserting candidate %s:%d: %w", c.IP, c.Port, err)
		}
		affected, _ := result.RowsAffected()
		enqueued += affected
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("committing transaction: %w", err)
	}

	return enqueued, nil
}

// DequeueCandidates claims up to `limit` pending candidates for processing.
// It sets their status to 'processing' and returns them.
func (d *DB) DequeueCandidates(limit int) ([]proxy.CandidateEntry, error) {
	tx, err := d.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.Query("SELECT id, ip, port, status, created_at, updated_at FROM candidates WHERE status = ? ORDER BY id LIMIT ?", proxy.CandidateStatusPending, limit)
	if err != nil {
		return nil, fmt.Errorf("querying pending candidates: %w", err)
	}
	defer rows.Close()

	var entries []proxy.CandidateEntry
	var ids []int64
	for rows.Next() {
		var e proxy.CandidateEntry
		if err := rows.Scan(&e.ID, &e.IP, &e.Port, &e.Status, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning candidate: %w", err)
		}
		entries = append(entries, e)
		ids = append(ids, e.ID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating candidates: %w", err)
	}

	for i := range entries {
		entries[i].Status = proxy.CandidateStatusProcessing
		entries[i].UpdatedAt = time.Now().UTC()
	}

	if len(ids) > 0 {
		placeholders := strings.Repeat("?,", len(ids))
		placeholders = placeholders[:len(placeholders)-1]
		args := make([]interface{}, len(ids))
		for i, id := range ids {
			args[i] = id
		}
		query := fmt.Sprintf("UPDATE candidates SET status = ?, updated_at = ? WHERE id IN (%s)", placeholders)
		now := time.Now().UTC()
		allArgs := append([]interface{}{proxy.CandidateStatusProcessing, now}, args...)
		if _, err := tx.Exec(query, allArgs...); err != nil {
			return nil, fmt.Errorf("updating candidates to processing: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing transaction: %w", err)
	}

	return entries, nil
}

// DeleteCandidate removes a candidate from the queue after processing.
func (d *DB) DeleteCandidate(id int64) error {
	_, err := d.db.Exec("DELETE FROM candidates WHERE id = ?", id)
	return err
}

// DeleteCandidates removes multiple candidates from the queue after processing.
func (d *DB) DeleteCandidates(ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	placeholders := strings.Repeat("?,", len(ids))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	query := fmt.Sprintf("DELETE FROM candidates WHERE id IN (%s)", placeholders)
	_, err := d.db.Exec(query, args...)
	return err
}

// ResetProcessingCandidates resets all 'processing' candidates back to 'pending'.
// Called on validator startup to recover from crashes.
func (d *DB) ResetProcessingCandidates() (int64, error) {
	result, err := d.db.Exec("UPDATE candidates SET status = ?, updated_at = ? WHERE status = ?", proxy.CandidateStatusPending, time.Now().UTC(), proxy.CandidateStatusProcessing)
	if err != nil {
		return 0, fmt.Errorf("resetting processing candidates: %w", err)
	}
	return result.RowsAffected()
}

// PendingCandidateCount returns the number of candidates waiting to be validated.
func (d *DB) PendingCandidateCount() (int, error) {
	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM candidates WHERE status = ?", proxy.CandidateStatusPending).Scan(&count)
	return count, err
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
		SELECT id, ip, port, protocol, anonymity, country, city, asn, asn_org, exit_ip, latency_ms, supports_connect, tls_insecure, blocklisted, blocklists, last_seen, first_seen, alive
		FROM proxies WHERE id = ?
	`, id)
	return scanProxy(row)
}

// ListProxies returns proxies matching the given filter.
func (d *DB) ListProxies(f proxy.ProxyFilter) ([]proxy.Proxy, error) {
	query := "SELECT id, ip, port, protocol, anonymity, country, city, asn, asn_org, exit_ip, latency_ms, supports_connect, tls_insecure, blocklisted, blocklists, last_seen, first_seen, alive FROM proxies"
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
	query := "SELECT id, ip, port, protocol, anonymity, country, city, asn, asn_org, exit_ip, latency_ms, supports_connect, tls_insecure, blocklisted, blocklists, last_seen, first_seen, alive FROM proxies"
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
	if f.Blocklisted != nil {
		conditions = append(conditions, "blocklisted = ?")
		args = append(args, *f.Blocklisted)
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
	var country, city, asnOrg, exitIP sql.NullString
	var latencyMs, asn sql.NullInt64
	var supportsConnect, tlsInsecure, blocklisted, alive sql.NullBool
	var blocklists sql.NullString
	err := s.Scan(
		&p.ID, &p.IP, &p.Port, &protocol, &anonymity,
		&country, &city, &asn, &asnOrg, &exitIP, &latencyMs,
		&supportsConnect, &tlsInsecure, &blocklisted, &blocklists,
		&p.LastSeen, &p.FirstSeen, &alive,
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
	if exitIP.Valid {
		p.ExitIP = exitIP.String
	}
	if latencyMs.Valid {
		p.LatencyMs = int(latencyMs.Int64)
	}
	if supportsConnect.Valid {
		p.SupportsConnect = supportsConnect.Bool
	}
	if tlsInsecure.Valid {
		p.TLSInsecure = tlsInsecure.Bool
	}
	if blocklisted.Valid {
		p.Blocklisted = blocklisted.Bool
	}
	if blocklists.Valid {
		p.Blocklists = blocklists.String
	}
	if alive.Valid {
		p.Alive = alive.Bool
	}
	return &p, nil
}

func scanProxyRows(rows *sql.Rows) (*proxy.Proxy, error) {
	return scanProxy(rows)
}
