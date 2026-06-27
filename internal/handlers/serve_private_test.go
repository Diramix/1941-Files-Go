package handlers

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Diramix/1941-files/internal/auth"
	"github.com/Diramix/1941-files/internal/store"
)

func TestPrivateFileRequiresTokenForAnonymous(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "files.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	am, err := auth.New(st, filepath.Join(dir, "secret.key"), false)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}

	u, err := st.CreateUser("owner@example.com", "x")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	udir := filepath.Join(dir, "files", u.UUID)
	if err := os.MkdirAll(udir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(udir, "secret.txt"), []byte("top secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := &Server{Auth: am, Store: st, Dir: dir}
	urlPath := "/f/" + u.UUID + "/secret.txt"

	r := httptest.NewRequest("GET", urlPath, nil)
	w := httptest.NewRecorder()
	s.serveFile(w, r)
	if w.Code != 404 {
		t.Fatalf("anonymous no-token access = %d, want 404 (body=%q)", w.Code, w.Body.String())
	}

	tok := am.PrivateToken(u.UUID + "/secret.txt")
	r2 := httptest.NewRequest("GET", urlPath+"?t="+tok, nil)
	w2 := httptest.NewRecorder()
	s.serveFile(w2, r2)
	if w2.Code != 200 {
		t.Fatalf("valid token access = %d, want 200", w2.Code)
	}

	other := am.PrivateToken(u.UUID + "/other.txt")
	r3 := httptest.NewRequest("GET", urlPath+"?t="+other, nil)
	w3 := httptest.NewRecorder()
	s.serveFile(w3, r3)
	if w3.Code != 404 {
		t.Fatalf("cross-file token access = %d, want 404", w3.Code)
	}
}
