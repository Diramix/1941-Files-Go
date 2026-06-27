package auth

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookie = "session"
	csrfCookie    = "csrf_token"
	sessionMaxAge = 7 * 24 * time.Hour
)

type User struct {
	Password string `json:"password"`
	Ban      bool   `json:"ban"`
}

type Manager struct {
	usersPath     string
	whitelistPath string
	banlistPath   string
	secret        []byte
	trustProxy    bool
}

func New(usersPath, whitelistPath, banlistPath, secretPath string, trustProxy bool) (*Manager, error) {
	secret, err := loadOrCreateSecret(secretPath)
	if err != nil {
		return nil, err
	}
	return &Manager{
		usersPath:     usersPath,
		whitelistPath: whitelistPath,
		banlistPath:   banlistPath,
		secret:        secret,
		trustProxy:    trustProxy,
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

func (m *Manager) LoadUsers() (map[string]User, error) {
	data, err := os.ReadFile(m.usersPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]User{}, nil
		}
		return nil, err
	}
	users := map[string]User{}
	if err := json.Unmarshal(data, &users); err != nil {
		return nil, err
	}
	return users, nil
}

func loadLines(path string) map[string]struct{} {
	set := map[string]struct{}{}
	f, err := os.Open(path)
	if err != nil {
		return set
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			set[line] = struct{}{}
		}
	}
	return set
}

func (m *Manager) IsWhitelisted(ip string) bool {
	_, ok := loadLines(m.whitelistPath)[ip]
	return ok
}

func (m *Manager) IsBannedIP(ip string) bool {
	_, ok := loadLines(m.banlistPath)[ip]
	return ok
}

func VerifyPassword(stored, password string) bool {
	if strings.HasPrefix(stored, "$2a$") || strings.HasPrefix(stored, "$2b$") || strings.HasPrefix(stored, "$2y$") {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(password)) == nil
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(password)) == 1
}

func (m *Manager) ClientIP(r *http.Request) string {
	if m.trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.Split(xff, ",")[0])
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

func (m *Manager) SetSession(w http.ResponseWriter, r *http.Request, username string) {
	exp := time.Now().Add(sessionMaxAge).Unix()
	payload := fmt.Sprintf("%s|%d", username, exp)
	value := base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + m.sign(payload)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(sessionMaxAge),
		MaxAge:   int(sessionMaxAge.Seconds()),
	})
}

func (m *Manager) Username(r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	parts := strings.SplitN(c.Value, ".", 2)
	if len(parts) != 2 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ""
	}
	payload := string(raw)
	if !hmac.Equal([]byte(m.sign(payload)), []byte(parts[1])) {
		return ""
	}
	fields := strings.SplitN(payload, "|", 2)
	if len(fields) != 2 {
		return ""
	}
	exp, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return ""
	}
	return fields[0]
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
