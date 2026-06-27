package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const FilesFolderName = "1941 Files"

type Config struct {
	NoSecure    bool   `json:"nosecure"`
	Port        int    `json:"port"`
	Directory   string `json:"directory"`
	Host        string `json:"host"`
	MaxUploadMB int64  `json:"max_upload_mb"`
	TrustProxy  bool   `json:"trust_proxy"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		Port:        1941,
		Directory:   "{home}",
		Host:        "0.0.0.0",
		MaxUploadMB: 1024,
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	if cfg.Port == 0 {
		cfg.Port = 1941
	}
	if strings.TrimSpace(cfg.Directory) == "" {
		cfg.Directory = "{home}"
	}
	if strings.TrimSpace(cfg.Host) == "" {
		cfg.Host = "0.0.0.0"
	}
	if cfg.MaxUploadMB <= 0 {
		cfg.MaxUploadMB = 1024
	}
	return cfg, nil
}

func ResolveDirectory(raw string) (string, error) {
	if strings.TrimSpace(raw) == "{home}" {
		base, err := userDataDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(base, FilesFolderName), nil
	}
	return filepath.Abs(filepath.Clean(os.ExpandEnv(raw)))
}

func userDataDir() (string, error) {
	switch runtime.GOOS {
	case "windows":
		if dir, err := os.UserConfigDir(); err == nil {
			return dir, nil
		}
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "Library", "Application Support"), nil
	default:
		if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
			return xdg, nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".local", "share"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return home, nil
}
