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
		id                   INTEGER PRIMARY KEY AUTOINCREMENT,
		ip                   TEXT NOT NULL,
		port                 INTEGER NOT NULL,
		protocol             TEXT NOT NULL,
		anonymity            TEXT,
		country              TEXT,
		city                 TEXT,
		asn                  INTEGER,
		asn_org              TEXT,
		exit_ip              TEXT,
		latency_ms           INTEGER,
		supports_connect     BOOLEAN DEFAULT FALSE,
		tls_insecure         BOOLEAN DEFAULT FALSE,
		blocklisted          BOOLEAN DEFAULT FALSE,
		blocklists           TEXT,
		last_seen            DATETIME NOT NULL,
		first_seen           DATETIME NOT NULL,
		alive                BOOLEAN DEFAULT TRUE,
		last_checked_at      DATETIME,
		last_ok_at           DATETIME,
		consecutive_failures INTEGER NOT NULL DEFAULT 0,
		check_count          INTEGER NOT NULL DEFAULT 0,
		success_count        INTEGER NOT NULL DEFAULT 0,
		status               TEXT NOT NULL DEFAULT 'active',
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
	CREATE INDEX IF NOT EXISTS idx_proxies_status ON proxies(status, protocol);
	CREATE INDEX IF NOT EXISTS idx_proxies_last_checked ON proxies(last_checked_at);

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

	// Backwards-compatible column additions for existing databases. These mirror
	// the columns declared in the CREATE TABLE above so old deployments pick up
	// the new columns on next start.
	for _, m := range []struct {
		name string
		ddl  string
	}{
		{"exit_ip", "ALTER TABLE proxies ADD COLUMN exit_ip TEXT"},
		{"supports_connect", "ALTER TABLE proxies ADD COLUMN supports_connect BOOLEAN DEFAULT FALSE"},
		{"tls_insecure", "ALTER TABLE proxies ADD COLUMN tls_insecure BOOLEAN DEFAULT FALSE"},
		{"blocklisted", "ALTER TABLE proxies ADD COLUMN blocklisted BOOLEAN DEFAULT FALSE"},
		{"blocklists", "ALTER TABLE proxies ADD COLUMN blocklists TEXT"},
		{"last_checked_at", "ALTER TABLE proxies ADD COLUMN last_checked_at DATETIME"},
		{"last_ok_at", "ALTER TABLE proxies ADD COLUMN last_ok_at DATETIME"},
		{"consecutive_failures", "ALTER TABLE proxies ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0"},
		{"check_count", "ALTER TABLE proxies ADD COLUMN check_count INTEGER NOT NULL DEFAULT 0"},
		{"success_count", "ALTER TABLE proxies ADD COLUMN success_count INTEGER NOT NULL DEFAULT 0"},
		{"status", "ALTER TABLE proxies ADD COLUMN status TEXT NOT NULL DEFAULT 'active'"},
	} {
		var exists int
		if err := d.db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('proxies') WHERE name = ?", m.name).Scan(&exists); err != nil {
			return fmt.Errorf("checking column %s: %w", m.name, err)
		}
		if exists == 0 {
			if _, err := d.db.Exec(m.ddl); err != nil {
				return fmt.Errorf("migrating %s column: %w", m.name, err)
			}
		}
	}

	// Backfill liveness fields on existing rows so older data becomes
	// queryable by the new code paths. Uses last_seen as a reasonable proxy
	// for "last_ok_at" since previously every successful upsert touched it.
	if _, err := d.db.Exec(`
		UPDATE proxies
		SET last_checked_at = COALESCE(last_checked_at, last_seen),
		    last_ok_at      = COALESCE(last_ok_at, last_seen),
		    status          = CASE
		                          WHEN status IS NULL OR status = '' THEN
		                              CASE WHEN alive = 1 THEN 'active' ELSE 'stale' END
		                          ELSE status
		                      END
		WHERE last_checked_at IS NULL OR last_ok_at IS NULL OR status IS NULL OR status = ''
	`); err != nil {
		return fmt.Errorf("backfilling liveness fields: %w", err)
	}

	// Older rows had check_count/success_count default to 0 even though they
	// represent at least one successful validation. Bump them to 1 so the
	// counters are coherent for revalidator metrics. Uses success_count = 0
	// on previously-alive rows as the signal that this row predates tracking.
	if _, err := d.db.Exec(`
		UPDATE proxies
		SET check_count   = 1,
		    success_count = 1
		WHERE check_count = 0 AND alive = 1
	`); err != nil {
		return fmt.Errorf("backfilling check counters: %w", err)
	}

	return nil
}

// UpsertProxy inserts or updates a proxy record. If the proxy already exists
// (same ip, port, protocol), it updates the fields and treats this as a
// successful check: status flips to active, consecutive_failures resets to 0,
// and check/success counters increment.
//
// This is the path used by the candidate validator for newly discovered proxies.
// For background revalidation, the revalidator uses RecordCheckSuccess /
// RecordCheckFailure directly so we don't have to round-trip the full struct.
func (d *DB) UpsertProxy(p *proxy.Proxy) error {
	now := time.Now().UTC()
	_, err := d.db.Exec(`
		INSERT INTO proxies (
			ip, port, protocol, anonymity, country, city, asn, asn_org, exit_ip,
			latency_ms, supports_connect, tls_insecure, blocklisted, blocklists,
			last_seen, first_seen, alive,
			last_checked_at, last_ok_at, consecutive_failures, check_count, success_count, status
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 1, 1, ?)
		ON CONFLICT(ip, port, protocol) DO UPDATE SET
			anonymity            = excluded.anonymity,
			country              = excluded.country,
			city                 = excluded.city,
			asn                  = excluded.asn,
			asn_org              = excluded.asn_org,
			exit_ip              = excluded.exit_ip,
			latency_ms           = excluded.latency_ms,
			supports_connect     = excluded.supports_connect,
			tls_insecure         = excluded.tls_insecure,
			blocklisted          = excluded.blocklisted,
			blocklists           = excluded.blocklists,
			last_seen            = excluded.last_seen,
			alive                = excluded.alive,
			last_checked_at      = excluded.last_checked_at,
			last_ok_at           = excluded.last_ok_at,
			consecutive_failures = 0,
			check_count          = check_count + 1,
			success_count        = success_count + 1,
			status               = ?
	`, p.IP, p.Port, string(p.Protocol), string(p.Anonymity),
		p.Country, p.City, p.ASN, p.ASNOrg, p.ExitIP, p.LatencyMs,
		p.SupportsConnect, p.TLSInsecure, p.Blocklisted, p.Blocklists,
		now, now, p.Alive,
		now, now, proxy.ProxyStatusActive,
		proxy.ProxyStatusActive,
	)
	if err != nil {
		return fmt.Errorf("upserting proxy %s:%d: %w", p.IP, p.Port, err)
	}
	return nil
}

// CheckSuccessUpdate carries the volatile fields refreshed on a successful
// recheck. Only non-zero values overwrite existing data; this lets the caller
// skip blocklist or geoip lookups without clobbering previously stored values.
type CheckSuccessUpdate struct {
	LatencyMs       int
	Anonymity       proxy.Anonymity
	ExitIP          string
	SupportsConnect bool
	TLSInsecure     bool
	// SetBlocklist controls whether Blocklisted/Blocklists are written.
	// When false, the existing values are preserved.
	SetBlocklist bool
	Blocklisted  bool
	Blocklists   string
}

// RecordCheckSuccess marks a proxy as successfully validated. It updates the
// volatile fields (latency, anonymity, exit IP, etc.), bumps last_seen,
// last_checked_at, and last_ok_at to now, resets consecutive_failures, and
// increments the check/success counters. Status is forced back to 'active'
// so previously stale proxies recover automatically.
func (d *DB) RecordCheckSuccess(id int64, u CheckSuccessUpdate) error {
	now := time.Now().UTC()
	if u.SetBlocklist {
		_, err := d.db.Exec(`
			UPDATE proxies SET
				latency_ms           = ?,
				anonymity            = ?,
				exit_ip              = ?,
				supports_connect     = ?,
				tls_insecure         = ?,
				blocklisted          = ?,
				blocklists           = ?,
				last_seen            = ?,
				last_checked_at      = ?,
				last_ok_at           = ?,
				consecutive_failures = 0,
				check_count          = check_count + 1,
				success_count        = success_count + 1,
				status               = ?,
				alive                = TRUE
			WHERE id = ?
		`, u.LatencyMs, string(u.Anonymity), u.ExitIP, u.SupportsConnect, u.TLSInsecure,
			u.Blocklisted, u.Blocklists, now, now, now, proxy.ProxyStatusActive, id)
		if err != nil {
			return fmt.Errorf("recording check success for id %d: %w", id, err)
		}
		return nil
	}
	_, err := d.db.Exec(`
		UPDATE proxies SET
			latency_ms           = ?,
			anonymity            = ?,
			exit_ip              = ?,
			supports_connect     = ?,
			tls_insecure         = ?,
			last_seen            = ?,
			last_checked_at      = ?,
			last_ok_at           = ?,
			consecutive_failures = 0,
			check_count          = check_count + 1,
			success_count        = success_count + 1,
			status               = ?,
			alive                = TRUE
		WHERE id = ?
	`, u.LatencyMs, string(u.Anonymity), u.ExitIP, u.SupportsConnect, u.TLSInsecure,
		now, now, now, proxy.ProxyStatusActive, id)
	if err != nil {
		return fmt.Errorf("recording check success for id %d: %w", id, err)
	}
	return nil
}

// RecordCheckFailure marks a proxy as having failed a check. It bumps
// last_checked_at, increments check_count and consecutive_failures. If
// consecutive_failures reaches failureThreshold, the proxy is marked stale
// (and alive=false for legacy compatibility).
func (d *DB) RecordCheckFailure(id int64, failureThreshold int) error {
	now := time.Now().UTC()
	_, err := d.db.Exec(`
		UPDATE proxies SET
			last_checked_at      = ?,
			consecutive_failures = consecutive_failures + 1,
			check_count          = check_count + 1,
			status               = CASE
			                           WHEN consecutive_failures + 1 >= ? THEN ?
			                           ELSE status
			                       END,
			alive                = CASE
			                           WHEN consecutive_failures + 1 >= ? THEN FALSE
			                           ELSE alive
			                       END
		WHERE id = ?
	`, now, failureThreshold, proxy.ProxyStatusStale, failureThreshold, id)
	if err != nil {
		return fmt.Errorf("recording check failure for id %d: %w", id, err)
	}
	return nil
}

// ListProxiesForRecheck returns up to `limit` proxies that haven't been
// checked within the last minAge duration, ordered by last_checked_at ascending
// (NULLs first so never-checked rows are picked up immediately). Includes both
// active and stale proxies — stale ones get a chance to come back.
func (d *DB) ListProxiesForRecheck(limit int, minAge time.Duration) ([]proxy.Proxy, error) {
	cutoff := time.Now().UTC().Add(-minAge)
	rows, err := d.db.Query(`
		SELECT id, ip, port, protocol, anonymity, country, city, asn, asn_org, exit_ip,
		       latency_ms, supports_connect, tls_insecure, blocklisted, blocklists,
		       last_seen, first_seen, alive,
		       last_checked_at, last_ok_at, consecutive_failures, check_count, success_count, status
		FROM proxies
		WHERE last_checked_at IS NULL OR last_checked_at < ?
		ORDER BY last_checked_at IS NULL DESC, last_checked_at ASC
		LIMIT ?
	`, cutoff, limit)
	if err != nil {
		return nil, fmt.Errorf("listing proxies for recheck: %w", err)
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

// EvictDeadProxies deletes proxies that have failed at least failureThreshold
// consecutive checks and whose last successful check was more than maxAge ago
// (or never succeeded and were first seen longer ago than maxAge).
// Returns the number of rows deleted.
func (d *DB) EvictDeadProxies(failureThreshold int, maxAge time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-maxAge)
	result, err := d.db.Exec(`
		DELETE FROM proxies
		WHERE consecutive_failures >= ?
		  AND COALESCE(last_ok_at, first_seen) < ?
	`, failureThreshold, cutoff)
	if err != nil {
		return 0, fmt.Errorf("evicting dead proxies: %w", err)
	}
	return result.RowsAffected()
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

// proxyColumns is the canonical column list used by every proxy SELECT query.
const proxyColumns = `id, ip, port, protocol, anonymity, country, city, asn, asn_org, exit_ip,
		latency_ms, supports_connect, tls_insecure, blocklisted, blocklists,
		last_seen, first_seen, alive,
		last_checked_at, last_ok_at, consecutive_failures, check_count, success_count, status`

// GetProxy returns a single proxy by ID.
func (d *DB) GetProxy(id int64) (*proxy.Proxy, error) {
	row := d.db.QueryRow("SELECT "+proxyColumns+" FROM proxies WHERE id = ?", id)
	return scanProxy(row)
}

// ListProxies returns proxies matching the given filter.
func (d *DB) ListProxies(f proxy.ProxyFilter) ([]proxy.Proxy, error) {
	query := "SELECT " + proxyColumns + " FROM proxies"
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
	query := "SELECT " + proxyColumns + " FROM proxies"
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
	var blocklists, status sql.NullString
	var lastCheckedAt, lastOkAt sql.NullTime
	var consecutiveFailures, checkCount, successCount sql.NullInt64
	err := s.Scan(
		&p.ID, &p.IP, &p.Port, &protocol, &anonymity,
		&country, &city, &asn, &asnOrg, &exitIP, &latencyMs,
		&supportsConnect, &tlsInsecure, &blocklisted, &blocklists,
		&p.LastSeen, &p.FirstSeen, &alive,
		&lastCheckedAt, &lastOkAt, &consecutiveFailures, &checkCount, &successCount, &status,
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
	if lastCheckedAt.Valid {
		t := lastCheckedAt.Time
		p.LastCheckedAt = &t
	}
	if lastOkAt.Valid {
		t := lastOkAt.Time
		p.LastOkAt = &t
	}
	if consecutiveFailures.Valid {
		p.ConsecutiveFailures = int(consecutiveFailures.Int64)
	}
	if checkCount.Valid {
		p.CheckCount = int(checkCount.Int64)
	}
	if successCount.Valid {
		p.SuccessCount = int(successCount.Int64)
	}
	if status.Valid && status.String != "" {
		p.Status = status.String
	} else if p.Alive {
		p.Status = proxy.ProxyStatusActive
	} else {
		p.Status = proxy.ProxyStatusStale
	}
	return &p, nil
}

func scanProxyRows(rows *sql.Rows) (*proxy.Proxy, error) {
	return scanProxy(rows)
}
