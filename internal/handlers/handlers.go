package handlers

import (
	"encoding/json"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Diramix/1941-files/internal/auth"
	"github.com/Diramix/1941-files/internal/config"
)

type Server struct {
	Cfg       *config.Config
	Auth      *auth.Manager
	Dir       string
	Templates map[string]*template.Template
	Version   string
}

func (s *Server) Routes(static http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/static/", static)
	mux.HandleFunc("/upload", s.requireLogin(s.upload))
	mux.HandleFunc("/login", s.login)
	mux.HandleFunc("/logout", s.logout)
	mux.HandleFunc("/banned", s.banned)
	mux.HandleFunc("/", s.root)
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireLogin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Cfg.NoSecure {
			next(w, r)
			return
		}
		ip := s.Auth.ClientIP(r)
		if s.Auth.IsBannedIP(ip) {
			http.Redirect(w, r, "/banned", http.StatusFound)
			return
		}
		if s.Auth.IsWhitelisted(ip) {
			next(w, r)
			return
		}
		username := s.Auth.Username(r)
		if username == "" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		users, err := s.Auth.LoadUsers()
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		if u, ok := users[username]; ok && u.Ban {
			http.Redirect(w, r, "/banned", http.StatusFound)
			return
		}
		next(w, r)
	}
}

func (s *Server) root(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		s.requireLogin(s.list)(w, r)
		return
	}
	s.requireLogin(s.serveFile)(w, r)
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		http.Error(w, "cannot read directory", http.StatusInternalServerError)
		return
	}
	var files []string
	for _, e := range entries {
		if e.Type().IsRegular() {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	s.render(w, r, "files.html", map[string]any{
		"Files":   files,
		"CSRF":    s.Auth.CSRFToken(w, r),
		"Version": s.Version,
	})
}

func (s *Server) safeJoin(name string) (string, bool) {
	base := filepath.Base(strings.TrimPrefix(name, "/"))
	if base == "" || base == "." || base == ".." {
		return "", false
	}
	full := filepath.Join(s.Dir, base)
	rel, err := filepath.Rel(s.Dir, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || strings.Contains(rel, string(os.PathSeparator)) {
		return "", false
	}
	return full, true
}

func (s *Server) serveFile(w http.ResponseWriter, r *http.Request) {
	full, ok := s.safeJoin(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	info, err := os.Stat(full)
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, full)
}

func (s *Server) upload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !auth.IsLAN(s.Auth.ClientIP(r)) {
		r.Body = http.MaxBytesReader(w, r.Body, s.Cfg.MaxUploadMB<<20)
	}
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"success": false, "message": "File too large"})
		return
	}

	if !s.Cfg.NoSecure && !s.Auth.CheckCSRF(r, r.FormValue("csrf_token")) {
		writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "Invalid CSRF token"})
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "File not found"})
		return
	}
	defer file.Close()
	if header.Filename == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "No file to upload"})
		return
	}

	full, ok := s.safeJoin(header.Filename)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "Invalid file name"})
		return
	}
	if _, err := os.Stat(full); err == nil {
		writeJSON(w, http.StatusConflict, map[string]any{"success": false, "message": "A file with this name already exists"})
		return
	}

	tmp, err := os.CreateTemp(s.Dir, ".upload-*")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": "Cannot save file"})
		return
	}
	tmpName := tmp.Name()
	if _, err := io.Copy(tmp, file); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": "Cannot save file"})
		return
	}
	tmp.Close()
	if err := os.Rename(tmpName, full); err != nil {
		os.Remove(tmpName)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": "Cannot save file"})
		return
	}
	_ = os.Chmod(full, 0o644)
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if s.Cfg.NoSecure || s.Auth.Username(r) != "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	ip := s.Auth.ClientIP(r)
	if s.Auth.IsBannedIP(ip) {
		http.Redirect(w, r, "/banned", http.StatusFound)
		return
	}

	if r.Method == http.MethodPost {
		if !s.Auth.CheckCSRF(r, r.FormValue("csrf_token")) {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
		username := r.FormValue("username")
		password := r.FormValue("password")
		users, err := s.Auth.LoadUsers()
		if err != nil {
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		if u, ok := users[username]; ok {
			if u.Ban {
				s.Auth.SetSession(w, r, username)
				http.Redirect(w, r, "/banned", http.StatusFound)
				return
			}
			if auth.VerifyPassword(u.Password, password) {
				s.Auth.SetSession(w, r, username)
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
		}
		http.Error(w, "Invalid credentials, please try again.", http.StatusForbidden)
		return
	}

	s.render(w, r, "login.html", map[string]any{"CSRF": s.Auth.CSRFToken(w, r), "Version": s.Version})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	s.Auth.ClearSession(w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) banned(w http.ResponseWriter, r *http.Request) {
	if s.Cfg.NoSecure {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	ip := s.Auth.ClientIP(r)
	if s.Auth.IsBannedIP(ip) {
		s.render(w, r, "ban.html", map[string]any{"Version": s.Version})
		return
	}
	if username := s.Auth.Username(r); username != "" {
		users, _ := s.Auth.LoadUsers()
		if u, ok := users[username]; ok && u.Ban {
			s.render(w, r, "ban.html", map[string]any{"Version": s.Version})
			return
		}
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t, ok := s.Templates[name]
	if !ok {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

func writeJSON(w http.ResponseWriter, status int, v map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
