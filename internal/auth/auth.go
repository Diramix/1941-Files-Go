package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Diramix/1941-files/internal/store"
	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookie   = "session"
	csrfCookie      = "csrf_token"
	sessionMaxAge   = 7 * 24 * time.Hour
	privateTokenTTL = 24 * time.Hour
)

type Manager struct {
	store      *store.Store
	secret     []byte
	trustProxy bool
	logins     *rateLimiter
}

func New(st *store.Store, secretPath string, trustProxy bool) (*Manager, error) {
	secret, err := loadOrCreateSecret(secretPath)
	if err != nil {
		return nil, err
	}
	return &Manager{
		store:      st,
		secret:     secret,
		trustProxy: trustProxy,
		logins:     newRateLimiter(10, 5*time.Minute),
	}, nil
}

func loadOrCreateSecret(path string) ([]byte, error) {
	if data, err := os.ReadFile(path); err == nil && len(data) >= 32 {
		return data, nil
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, secret, 0o600); err != nil {
		return nil, err
	}
	return secret, nil
}

func (m *Manager) IsWhitelisted(ip string) bool { return m.store.IsWhitelisted(ip) }
func (m *Manager) IsBannedIP(ip string) bool    { return m.store.IsBanned(ip) }

func HashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(h), err
}

var dummyHash []byte

func init() {
	dummyHash, _ = bcrypt.GenerateFromPassword([]byte("not-a-real-password"), bcrypt.DefaultCost)
}

func VerifyPassword(stored, password string) bool {
	if strings.HasPrefix(stored, "$2a$") || strings.HasPrefix(stored, "$2b$") || strings.HasPrefix(stored, "$2y$") {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(password)) == nil
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(password)) == 1
}

func DummyVerify(password string) {
	_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
}

func (m *Manager) AllowLogin(ip string) bool { return m.logins.allow(ip) }

func (m *Manager) ClientIP(r *http.Request) string {
	if m.trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func IsLAN(ip string) bool {
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast()
}

func (m *Manager) sign(value string) string {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (m *Manager) signedToken(payload string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + m.sign(payload)
}

func (m *Manager) verifyToken(value string) (string, bool) {
	parts := strings.SplitN(value, ".", 2)
	if len(parts) != 2 {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	payload := string(raw)
	if !hmac.Equal([]byte(m.sign(payload)), []byte(parts[1])) {
		return "", false
	}
	return payload, true
}

func (m *Manager) SetSession(w http.ResponseWriter, r *http.Request, userID int64) {
	exp := time.Now().Add(sessionMaxAge).Unix()
	payload := fmt.Sprintf("%d|%d", userID, exp)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    m.signedToken(payload),
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(sessionMaxAge),
		MaxAge:   int(sessionMaxAge.Seconds()),
	})
}

func (m *Manager) UserID(r *http.Request) int64 {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return 0
	}
	payload, ok := m.verifyToken(c.Value)
	if !ok {
		return 0
	}
	fields := strings.SplitN(payload, "|", 2)
	if len(fields) != 2 {
		return 0
	}
	id, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return 0
	}
	exp, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return 0
	}
	return id
}

func (m *Manager) ClearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}

func (m *Manager) PrivateToken(path string) string {
	exp := time.Now().Add(privateTokenTTL).Unix()
	return m.signedToken(fmt.Sprintf("t:%d|%s", exp, path))
}

func (m *Manager) VerifyPrivateToken(tok string) (string, bool) {
	payload, ok := m.verifyToken(tok)
	if !ok || !strings.HasPrefix(payload, "t:") {
		return "", false
	}
	fields := strings.SplitN(strings.TrimPrefix(payload, "t:"), "|", 2)
	if len(fields) != 2 {
		return "", false
	}
	exp, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", false
	}
	return fields[1], true
}

func (m *Manager) CSRFToken(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookie); err == nil && c.Value != "" {
		return c.Value
	}
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	token := base64.RawURLEncoding.EncodeToString(buf)
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
	return token
}

func (m *Manager) CheckCSRF(r *http.Request, submitted string) bool {
	c, err := r.Cookie(csrfCookie)
	if err != nil || c.Value == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(submitted)) == 1
}

type rateLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string]*window
}

type window struct {
	count int
	reset time.Time
}

func newRateLimiter(max int, w time.Duration) *rateLimiter {
	return &rateLimiter{max: max, window: w, hits: make(map[string]*window)}
}

func (rl *rateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	w := rl.hits[key]
	if w == nil || now.After(w.reset) {
		if len(rl.hits) > 1024 {
			for k, v := range rl.hits {
				if now.After(v.reset) {
					delete(rl.hits, k)
				}
			}
		}
		rl.hits[key] = &window{count: 1, reset: now.Add(rl.window)}
		return true
	}
	if w.count >= rl.max {
		return false
	}
	w.count++
	return true
}
