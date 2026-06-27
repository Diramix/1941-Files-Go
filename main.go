package main

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"syscall"
	"time"

	"github.com/Diramix/1941-files/internal/auth"
	"github.com/Diramix/1941-files/internal/config"
	"github.com/Diramix/1941-files/internal/handlers"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

// version is set at build time via -ldflags "-X main.version=...".
// When unset (e.g. `go run .` during development), it falls back to the
// VCS commit recorded by the Go toolchain.
var version = "dev"

// resolveVersion returns the build-time version, or "dev-<short commit>" when
// running an unversioned build and the commit hash is available.
func resolveVersion() string {
	if version != "dev" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return version
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && s.Value != "" {
			rev := s.Value
			if len(rev) > 7 {
				rev = rev[:7]
			}
			return "dev-" + rev
		}
	}
	return version
}

func main() {
	version = resolveVersion()

	for _, arg := range os.Args[1:] {
		if arg == "--version" || arg == "-v" {
			fmt.Println(version)
			return
		}
	}

	exe, err := os.Executable()
	if err != nil {
		log.Fatalf("cannot locate executable: %v", err)
	}
	baseDir := filepath.Dir(exe)
	if _, err := os.Stat(filepath.Join(baseDir, "control", "config.json")); err != nil {
		if wd, e := os.Getwd(); e == nil {
			baseDir = wd
		}
	}

	controlDir := filepath.Join(baseDir, "control")
	cfg, err := config.Load(filepath.Join(controlDir, "config.json"))
	if err != nil {
		log.Fatalf("cannot load config: %v", err)
	}

	dir, err := config.ResolveDirectory(cfg.Directory)
	if err != nil {
		log.Fatalf("cannot resolve directory: %v", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatalf("cannot create directory: %v", err)
	}

	authMgr, err := auth.New(
		filepath.Join(controlDir, "users.json"),
		filepath.Join(controlDir, "ip-whitelist.txt"),
		filepath.Join(controlDir, "ip-banlist.txt"),
		filepath.Join(controlDir, "secret.key"),
		cfg.TrustProxy,
	)
	if err != nil {
		log.Fatalf("cannot init auth: %v", err)
	}

	// Each page is parsed together with the shared layout into its own
	// template set, so pages can redefine the same block names without
	// colliding. Rendering executes the "layout" entry point.
	pages := []string{"login.html", "files.html", "ban.html"}
	tmpls := make(map[string]*template.Template, len(pages))
	for _, page := range pages {
		t, err := template.ParseFS(templatesFS, "templates/layout.html", "templates/"+page)
		if err != nil {
			log.Fatalf("cannot parse template %s: %v", page, err)
		}
		tmpls[page] = t
	}

	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("cannot mount static: %v", err)
	}
	staticHandler := http.StripPrefix("/static/", http.FileServer(http.FS(staticSub)))

	srv := &handlers.Server{Cfg: cfg, Auth: authMgr, Dir: dir, Templates: tmpls, Version: version}

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           srv.Routes(staticHandler),
		ReadHeaderTimeout: 10 * time.Second,
	}

	fmt.Printf("1941-files %s\n", version)
	fmt.Printf("Serving files from: %s\n", dir)
	fmt.Printf("Serving at http://%s\n", addr)

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(ctx)
}
