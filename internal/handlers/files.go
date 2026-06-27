package handlers

import (
	"os"
	"sort"
	"strings"
	"time"
)

type diskFile struct {
	Name    string
	Size    int64
	ModTime time.Time
}

func scanDir(dir string) ([]diskFile, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := make([]diskFile, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, diskFile{Name: name, Size: info.Size(), ModTime: info.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].ModTime.Equal(out[j].ModTime) {
			return out[i].ModTime.After(out[j].ModTime)
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func (s *Server) PurgeEmptyOldAccounts(cutoff int64) (int, error) {
	users, err := s.Store.UsersCreatedBefore(cutoff)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, u := range users {
		files, err := scanDir(s.userDir(u.UUID))
		if err != nil || len(files) > 0 {
			continue
		}
		if err := s.Store.DeleteUser(u.ID); err != nil {
			continue
		}
		_ = os.RemoveAll(s.userDir(u.UUID))
		removed++
	}
	return removed, nil
}

func pageOf(files []diskFile, limit, offset int) ([]diskFile, bool) {
	if offset < 0 {
		offset = 0
	}
	if offset >= len(files) {
		return nil, false
	}
	end := offset + limit
	hasMore := end < len(files)
	if end > len(files) {
		end = len(files)
	}
	return files[offset:end], hasMore
}
