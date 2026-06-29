package store

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	KindWhitelist = 0
	KindBanlist   = 1
)

var ErrEmailTaken = errors.New("email already registered")

type User struct {
	ID        int64
	UUID      string
	Email     string
	PassHash  string
	Banned    bool
	CreatedAt int64
}

type Store struct {
	db *sql.DB

	aclMu       sync.RWMutex
	banned      map[string]bool
	whitelisted map[string]bool
}

func Open(path string) (*Store, error) {
	dsn := path + "?" + strings.Join([]string{
		"_journal_mode=WAL",
		"_synchronous=NORMAL",
		"_busy_timeout=5000",
		"_foreign_keys=ON",
		"_cache_size=-2000",
		"_temp_store=MEMORY",
	}, "&")

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	for _, p := range []string{
		"PRAGMA mmap_size=33554432",
		"PRAGMA wal_autocheckpoint=256",
	} {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("pragma %q: %w", p, err)
		}
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.loadACL(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) loadACL() error {
	rows, err := s.db.Query("SELECT ip, kind FROM ip_acl")
	if err != nil {
		return err
	}
	defer rows.Close()
	banned := make(map[string]bool)
	whitelisted := make(map[string]bool)
	for rows.Next() {
		var ip string
		var kind int
		if err := rows.Scan(&ip, &kind); err != nil {
			return err
		}
		switch kind {
		case KindBanlist:
			banned[ip] = true
		case KindWhitelist:
			whitelisted[ip] = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	s.aclMu.Lock()
	s.banned, s.whitelisted = banned, whitelisted
	s.aclMu.Unlock()
	return nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS users (
  id         INTEGER PRIMARY KEY,
  uuid       TEXT NOT NULL,
  email      TEXT NOT NULL,
  pass_hash  TEXT NOT NULL,
  banned     INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email COLLATE NOCASE);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_uuid ON users(uuid);

CREATE TABLE IF NOT EXISTS ip_acl (
  ip   TEXT PRIMARY KEY,
  kind INTEGER NOT NULL
);

DROP TABLE IF EXISTS files;`
	_, err := s.db.Exec(schema)
	return err
}

func newUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func (s *Store) CreateUser(email, passHash string) (*User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	uuid, err := newUUID()
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	res, err := s.db.Exec(
		"INSERT INTO users(uuid, email, pass_hash, banned, created_at) VALUES(?,?,?,0,?)",
		uuid, email, passHash, now,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, ErrEmailTaken
		}
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return &User{ID: id, UUID: uuid, Email: email, PassHash: passHash, CreatedAt: now}, nil
}

func scanUser(row *sql.Row) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.UUID, &u.Email, &u.PassHash, &u.Banned, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

const userCols = "id, uuid, email, pass_hash, banned, created_at"

func (s *Store) UserByEmail(email string) (*User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	return scanUser(s.db.QueryRow(
		"SELECT "+userCols+" FROM users WHERE email = ? COLLATE NOCASE", email))
}

func (s *Store) UserByID(id int64) (*User, error) {
	return scanUser(s.db.QueryRow("SELECT "+userCols+" FROM users WHERE id = ?", id))
}

func (s *Store) SetBan(id int64, banned bool) error {
	_, err := s.db.Exec("UPDATE users SET banned = ? WHERE id = ?", banned, id)
	return err
}

func (s *Store) UsersCreatedBefore(cutoff int64) ([]User, error) {
	rows, err := s.db.Query(
		"SELECT "+userCols+" FROM users WHERE created_at < ?", cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.UUID, &u.Email, &u.PassHash, &u.Banned, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *Store) DeleteUser(id int64) error {
	_, err := s.db.Exec("DELETE FROM users WHERE id = ?", id)
	return err
}

func (s *Store) IsWhitelisted(ip string) bool {
	s.aclMu.RLock()
	defer s.aclMu.RUnlock()
	return s.whitelisted[ip]
}

func (s *Store) IsBanned(ip string) bool {
	s.aclMu.RLock()
	defer s.aclMu.RUnlock()
	return s.banned[ip]
}

func (s *Store) AddIP(ip string, kind int) error {
	if _, err := s.db.Exec("INSERT OR REPLACE INTO ip_acl(ip, kind) VALUES(?,?)", strings.TrimSpace(ip), kind); err != nil {
		return err
	}
	return s.loadACL()
}

func (s *Store) RemoveIP(ip string) error {
	if _, err := s.db.Exec("DELETE FROM ip_acl WHERE ip = ?", strings.TrimSpace(ip)); err != nil {
		return err
	}
	return s.loadACL()
}
