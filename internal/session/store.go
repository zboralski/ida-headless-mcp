package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Metadata captures the persisted fields for a session.
type Metadata struct {
	ID            string        `json:"id"`
	BinaryPath    string        `json:"binary_path"`
	CreatedAt     time.Time     `json:"created_at"`
	LastActivity  time.Time     `json:"last_activity"`
	Timeout       time.Duration `json:"timeout"`
	HasDecompiler bool          `json:"has_decompiler"`
}

// Store persists session metadata so the server can recover after restarts.
type Store struct {
	dir string
	mu  sync.Mutex
}

// NewStore creates a session store under the provided directory.
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create session store dir: %w", err)
	}
	return &Store{dir: dir}, nil
}

// Save writes the session metadata to disk.
func (s *Store) Save(sess *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(sess.Metadata(), "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.dir, sess.ID+".json.tmp")
	target := filepath.Join(s.dir, sess.ID+".json")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, target)
}

// Delete removes the session metadata file.
func (s *Store) Delete(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := filepath.Join(s.dir, sessionID+".json")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Load returns all sessions saved on disk.
func (s *Store) Load() ([]Metadata, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}

	var metas []Metadata
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(s.dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var meta Metadata
		if err := json.Unmarshal(data, &meta); err != nil {
			return nil, fmt.Errorf("decode %s: %w", path, err)
		}
		metas = append(metas, meta)
	}
	return metas, nil
}
