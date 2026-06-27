package handlers

import (
	"encoding/json"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Diramix/1941-files/internal/auth"
	"github.com/Diramix/1941-files/internal/config"
	"github.com/Diramix/1941-files/internal/store"
)

type Server struct {
	Cfg       *config.Config
	Auth      *auth.Manager
	Store     *store.Store
	Dir       string
	Templates map[string]*template.Template
	Version   string
}

func (s *Server) Routes(static http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/static/", static)
	mux.HandleFunc("/register", s.register)
	mux.HandleFunc("/login", s.login)
	mux.HandleFunc("/logout", s.logout)
	mux.HandleFunc("/upload", s.upload)
	mux.HandleFunc("/f/", s.serveFile)
	mux.HandleFunc("/api/public", s.apiPublic)
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

func (s *Server) filesRoot() string { return filepath.Join(s.Dir, "files") }
func (s *Server) publicDir() string { return filepath.Join(s.filesRoot(), "public") }
func (s *Server) userDir(uuid string) string {
	return filepath.Join(s.filesRoot(), uuid)
}

func (s *Server) sessionUser(r *http.Request) *store.User {
	id := s.Auth.UserID(r)
	if id == 0 {
		return nil
	}
	u, err := s.Store.UserByID(id)
	if err != nil {
		return nil
	}
	return u
}

func (s *Server) currentUser(r *http.Request) *store.User {
	u := s.sessionUser(r)
	if u == nil || u.Banned {
		return nil
	}
	return u
}

func (s *Server) requireLogin(next func(http.ResponseWriter, *http.Request, *store.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Auth.IsBannedIP(s.Auth.ClientIP(r)) {
			http.Redirect(w, r, "/banned", http.StatusFound)
			return
		}
		u := s.sessionUser(r)
		switch {
		case u == nil:
			http.Redirect(w, r, "/login", http.StatusFound)
		case u.Banned:
			http.Redirect(w, r, "/banned", http.StatusFound)
		default:
			next(w, r, u)
		}
	}
}

func (s *Server) root(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if s.Auth.IsBannedIP(s.Auth.ClientIP(r)) {
		http.Redirect(w, r, "/banned", http.StatusFound)
		return
	}
	u := s.sessionUser(r)
	if u != nil && u.Banned {
		http.Redirect(w, r, "/banned", http.StatusFound)
		return
	}
	s.list(w, r, u)
}

const publicPageSize = 50

type fileView struct {
	Name string
	URL  string
}

func publicURL(name string) string {
	return "/f/" + url.PathEscape(name)
}

func (s *Server) privateURL(uuid, name string) string {
	tok := s.Auth.PrivateToken(uuid + "/" + name)
	return "/f/" + url.PathEscape(uuid) + "/" + url.PathEscape(name) + "?t=" + url.QueryEscape(tok)
}

func (s *Server) list(w http.ResponseWriter, r *http.Request, u *store.User) {
	publicAll, err := scanDir(s.publicDir())
	if err != nil {
		http.Error(w, "cannot read files", http.StatusInternalServerError)
		return
	}
	public, hasMore := pageOf(publicAll, publicPageSize, 0)

	data := map[string]any{
		"LoggedIn":      u != nil,
		"CSRF":          s.Auth.CSRFToken(w, r),
		"Version":       s.Version,
		"PublicHasMore": hasMore,
	}

	publicViews := make([]fileView, 0, len(public))
	for _, f := range public {
		publicViews = append(publicViews, fileView{Name: f.Name, URL: publicURL(f.Name)})
	}
	data["PublicFiles"] = publicViews

	if u != nil {
		private, err := scanDir(s.userDir(u.UUID))
		if err != nil {
			http.Error(w, "cannot read files", http.StatusInternalServerError)
			return
		}
		privateViews := make([]fileView, 0, len(private))
		for _, f := range private {
			privateViews = append(privateViews, fileView{
				Name: f.Name, URL: s.privateURL(u.UUID, f.Name),
			})
		}
		data["PrivateFiles"] = privateViews
		data["Email"] = u.Email
	}

	s.render(w, r, "files.html", data)
}

func (s *Server) apiPublic(w http.ResponseWriter, r *http.Request) {
	if s.Auth.IsBannedIP(s.Auth.ClientIP(r)) {
		writeJSON(w, http.StatusForbidden, apiResp{Message: "Forbidden"})
		return
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}
	all, err := scanDir(s.publicDir())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiResp{Message: "Cannot read files"})
		return
	}
	files, hasMore := pageOf(all, publicPageSize, offset)
	type item struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	out := struct {
		Files   []item `json:"files"`
		HasMore bool   `json:"has_more"`
	}{Files: make([]item, 0, len(files)), HasMore: hasMore}
	for _, f := range files {
		out.Files = append(out.Files, item{Name: f.Name, URL: publicURL(f.Name)})
	}
	writeJSON(w, http.StatusOK, out)
}

func safeBase(name string) (string, bool) {
	base := filepath.Base(strings.TrimPrefix(name, "/"))
	if base == "" || base == "." || base == ".." || strings.ContainsRune(base, os.PathSeparator) {
		return "", false
	}
	return base, true
}

func (s *Server) serveFile(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/f/"), "/")
	parts := strings.Split(rest, "/")

	var full string
	switch len(parts) {
	case 1: // public
		name, ok := safeBase(parts[0])
		if !ok {
			http.NotFound(w, r)
			return
		}
		full = filepath.Join(s.publicDir(), name)

	case 2: // private: <uuid>/<name>
		uuid, ok := safeBase(parts[0])
		if !ok {
			http.NotFound(w, r)
			return
		}
		name, ok := safeBase(parts[1])
		if !ok {
			http.NotFound(w, r)
			return
		}
		if !s.privateAllowed(r, uuid, name) {
			http.NotFound(w, r)
			return
		}
		full = filepath.Join(s.userDir(uuid), name)

	default:
		http.NotFound(w, r)
		return
	}

	info, err := os.Stat(full)
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Disposition", contentDisposition(filepath.Base(full)))
	http.ServeFile(w, r, full)
}

func (s *Server) privateAllowed(r *http.Request, uuid, name string) bool {
	if u := s.currentUser(r); u != nil && u.UUID == uuid {
		return true
	}
	if tok := r.URL.Query().Get("t"); tok != "" {
		if path, ok := s.Auth.VerifyPrivateToken(tok); ok && path == uuid+"/"+name {
			return true
		}
	}
	return false
}

var inlineExts = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true,
	".bmp": true, ".ico": true, ".pdf": true, ".mp4": true, ".webm": true,
	".mp3": true, ".ogg": true, ".wav": true, ".txt": true,
}

func contentDisposition(origName string) string {
	disp := "attachment"
	if inlineExts[strings.ToLower(filepath.Ext(origName))] {
		disp = "inline"
	}
	ascii := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\\' {
			return '_'
		}
		if r > 0x7f {
			return -1
		}
		return r
	}, origName)
	if ascii == "" {
		ascii = "download"
	}
	return disp + `; filename="` + ascii + `"; filename*=UTF-8''` + url.PathEscape(origName)
}

func (s *Server) upload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := s.Auth.ClientIP(r)
	if s.Auth.IsBannedIP(ip) {
		writeJSON(w, http.StatusForbidden, apiResp{Message: "Forbidden"})
		return
	}
	u := s.currentUser(r) // nil for anonymous uploaders
	if !auth.IsLAN(ip) {
		r.Body = http.MaxBytesReader(w, r.Body, s.Cfg.MaxUploadMB<<20)
	}
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, apiResp{Message: "File too large"})
		return
	}

	if !s.Auth.CheckCSRF(r, r.FormValue("csrf_token")) {
		writeJSON(w, http.StatusForbidden, apiResp{Message: "Invalid CSRF token"})
		return
	}

	v := r.FormValue("is_public")
	isPublic := v == "on" || v == "true" || v == "1"
	if u == nil {
		isPublic = true
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiResp{Message: "File not found"})
		return
	}
	defer file.Close()

	base, ok := safeBase(header.Filename)
	if !ok {
		writeJSON(w, http.StatusBadRequest, apiResp{Message: "Invalid file name"})
		return
	}

	dir := s.publicDir()
	if !isPublic {
		dir = s.userDir(u.UUID)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiResp{Message: "Cannot save file"})
		return
	}
	full := filepath.Join(dir, base)

	if _, err := os.Stat(full); err == nil {
		writeJSON(w, http.StatusConflict, apiResp{Message: "A file with this name already exists"})
		return
	}

	tmp, err := os.CreateTemp(dir, ".upload-*")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiResp{Message: "Cannot save file"})
		return
	}
	tmpName := tmp.Name()
	_, err = io.Copy(tmp, file)
	if err != nil {
		tmp.Close()
		os.Remove(tmpName)
		writeJSON(w, http.StatusInternalServerError, apiResp{Message: "Cannot save file"})
		return
	}
	tmp.Close()
	if err := os.Rename(tmpName, full); err != nil {
		os.Remove(tmpName)
		writeJSON(w, http.StatusInternalServerError, apiResp{Message: "Cannot save file"})
		return
	}
	_ = os.Chmod(full, 0o644)

	writeJSON(w, http.StatusOK, apiResp{Success: true})
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if s.currentUser(r) != nil {
		writeJSON(w, http.StatusOK, apiResp{Success: true})
		return
	}
	if !s.Auth.CheckCSRF(r, r.FormValue("csrf_token")) {
		writeJSON(w, http.StatusForbidden, apiResp{Message: "Invalid CSRF token"})
		return
	}
	if !s.Auth.AllowLogin(s.Auth.ClientIP(r)) {
		writeJSON(w, http.StatusTooManyRequests, apiResp{Message: "Too many attempts, try again later."})
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	if !validEmail(email) || len(password) < 6 {
		writeJSON(w, http.StatusBadRequest, apiResp{Message: "Enter a valid email and a password of at least 6 characters."})
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiResp{Message: "Server error"})
		return
	}
	u, err := s.Store.CreateUser(email, hash)
	if err == store.ErrEmailTaken {
		writeJSON(w, http.StatusConflict, apiResp{Message: "An account with this email already exists."})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiResp{Message: "Server error"})
		return
	}
	s.Auth.SetSession(w, r, u.ID)
	writeJSON(w, http.StatusOK, apiResp{Success: true})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if s.currentUser(r) != nil {
		writeJSON(w, http.StatusOK, apiResp{Success: true})
		return
	}
	ip := s.Auth.ClientIP(r)
	if s.Auth.IsBannedIP(ip) {
		writeJSON(w, http.StatusForbidden, apiResp{Message: "Forbidden", Redirect: "/banned"})
		return
	}
	if !s.Auth.CheckCSRF(r, r.FormValue("csrf_token")) {
		writeJSON(w, http.StatusForbidden, apiResp{Message: "Invalid CSRF token"})
		return
	}
	if !s.Auth.AllowLogin(ip) {
		writeJSON(w, http.StatusTooManyRequests, apiResp{Message: "Too many attempts, try again later."})
		return
	}
	email := r.FormValue("email")
	password := r.FormValue("password")
	u, err := s.Store.UserByEmail(email)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiResp{Message: "Server error"})
		return
	}
	if u == nil {
		auth.DummyVerify(password)
	}
	if u != nil && auth.VerifyPassword(u.PassHash, password) {
		s.Auth.SetSession(w, r, u.ID)
		if u.Banned {
			writeJSON(w, http.StatusOK, apiResp{Success: true, Redirect: "/banned"})
			return
		}
		writeJSON(w, http.StatusOK, apiResp{Success: true})
		return
	}
	writeJSON(w, http.StatusUnauthorized, apiResp{Message: "Invalid credentials, please try again."})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	s.Auth.ClearSession(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) banned(w http.ResponseWriter, r *http.Request) {
	ip := s.Auth.ClientIP(r)
	if s.Auth.IsBannedIP(ip) {
		s.render(w, r, "ban.html", map[string]any{"Version": s.Version})
		return
	}
	if id := s.Auth.UserID(r); id != 0 {
		if u, _ := s.Store.UserByID(id); u != nil && u.Banned {
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

type apiResp struct {
	Success  bool   `json:"success"`
	Message  string `json:"message,omitempty"`
	Redirect string `json:"redirect,omitempty"`
}

func validEmail(email string) bool {
	at := strings.IndexByte(email, '@')
	if at <= 0 {
		return false
	}
	domain := email[at+1:]
	dot := strings.IndexByte(domain, '.')
	return dot > 0 && dot < len(domain)-1
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
