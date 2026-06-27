package auth

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Diramix/1941-files/internal/store"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	m, err := New(st, t.TempDir()+"/secret.key", true)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

func TestPrivateTokenScopedToFile(t *testing.T) {
	m := newTestManager(t)
	path := "a1e9bdcf-52d5-4644-9be9-504aa064fb22/secret.txt"
	tok := m.PrivateToken(path)

	if got, ok := m.VerifyPrivateToken(tok); !ok || got != path {
		t.Fatalf("VerifyPrivateToken = (%q, %v), want (%q, true)", got, ok, path)
	}
	if got, _ := m.VerifyPrivateToken(tok); got == "a1e9bdcf-52d5-4644-9be9-504aa064fb22/other.txt" {
		t.Fatalf("token for %q matched a different file", path)
	}
	if _, ok := m.VerifyPrivateToken(tok + "tampered"); ok {
		t.Fatalf("tampered token accepted")
	}
}

func TestClientIPRightmostXFF(t *testing.T) {
	m := newTestManager(t)
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8, 9.9.9.9")
	if got := m.ClientIP(r); got != "9.9.9.9" {
		t.Fatalf("ClientIP = %q, want rightmost 9.9.9.9", got)
	}
}

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !rl.allow("ip") {
			t.Fatalf("attempt %d should be allowed", i)
		}
	}
	if rl.allow("ip") {
		t.Fatalf("4th attempt should be blocked")
	}
	if !rl.allow("other") {
		t.Fatalf("different key should have its own window")
	}
}
