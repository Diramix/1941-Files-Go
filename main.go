package main

import (
	"bufio"
	"context"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Diramix/1941-files/internal/auth"
	"github.com/Diramix/1941-files/internal/config"
	"github.com/Diramix/1941-files/internal/handlers"
	"github.com/Diramix/1941-files/internal/store"
)

var version = "dev"

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

func hasFlag(names ...string) bool {
	for _, a := range os.Args[1:] {
		for _, n := range names {
			if a == n {
				return true
			}
		}
	}
	return false
}

func offerLegacyMigration(dir, publicDir string, autoYes bool) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var stray []string
	for _, e := range entries {
		name := e.Name()
		if name == "db" || name == "files" {
			continue
		}
		if e.Type().IsRegular() {
			stray = append(stray, name)
		}
	}
	if len(stray) == 0 {
		return nil
	}

	fmt.Printf("\nFound %d file(s) from an old version in %s:\n", len(stray), dir)
	for _, n := range stray {
		fmt.Printf("  - %s\n", n)
	}

	if !autoYes && !confirm("Migrate these files into the public folder? [y/N]: ") {
		fmt.Println("Migration skipped. Re-run with --migrate to migrate later.")
		return nil
	}

	migrated := 0
	for _, name := range stray {
		src := filepath.Join(dir, name)
		dst := filepath.Join(publicDir, name)
		if _, err := os.Stat(dst); err == nil {
			log.Printf("legacy migration: %q already exists in public, skipping", name)
			continue
		}
		if err := os.Rename(src, dst); err != nil {
			log.Printf("legacy migration: cannot move %q: %v", name, err)
			continue
		}
		migrated++
	}
	fmt.Printf("Migrated %d file(s) into the public folder.\n", migrated)
	return nil
}

func confirm(prompt string) bool {
	if fi, err := os.Stdin.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	fmt.Print(prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
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
	dbDir := filepath.Join(dir, "db")
	filesDir := filepath.Join(dir, "files")
	publicDir := filepath.Join(filesDir, "public")
	for _, d := range []string{dir, dbDir, filesDir, publicDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			log.Fatalf("cannot create directory %s: %v", d, err)
		}
	}

	st, err := store.Open(filepath.Join(dbDir, "files.db"))
	if err != nil {
		log.Fatalf("cannot open database: %v", err)
	}
	defer st.Close()

	autoMigrate := hasFlag("--migrate", "-m")
	if err := offerLegacyMigration(dir, publicDir, autoMigrate); err != nil {
		log.Printf("legacy migration: %v", err)
	}

	authMgr, err := auth.New(st, filepath.Join(controlDir, "secret.key"), cfg.TrustProxy)
	if err != nil {
		log.Fatalf("cannot init auth: %v", err)
	}

	templatesDir := filepath.Join(baseDir, "templates")
	staticDir := filepath.Join(baseDir, "static")
	if _, err := os.Stat(templatesDir); err != nil {
		log.Fatalf("cannot find templates directory next to the executable (%s): %v", templatesDir, err)
	}
	if _, err := os.Stat(staticDir); err != nil {
		log.Fatalf("cannot find static directory next to the executable (%s): %v", staticDir, err)
	}

	pages := []string{"files.html", "ban.html"}
	tmpls := make(map[string]*template.Template, len(pages))
	for _, page := range pages {
		t, err := template.ParseFiles(filepath.Join(templatesDir, "layout.html"), filepath.Join(templatesDir, page))
		if err != nil {
			log.Fatalf("cannot parse template %s: %v", page, err)
		}
		tmpls[page] = t
	}

	staticHandler := http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir)))

	srv := &handlers.Server{Cfg: cfg, Auth: authMgr, Store: st, Dir: dir, Templates: tmpls, Version: version}

	go func() {
		purge := func() {
			cutoff := time.Now().Add(-14 * 24 * time.Hour).Unix()
			if n, err := srv.PurgeEmptyOldAccounts(cutoff); err != nil {
				log.Printf("account cleanup error: %v", err)
			} else if n > 0 {
				log.Printf("account cleanup: removed %d empty account(s)", n)
			}
		}
		purge()
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			purge()
		}
	}()

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
