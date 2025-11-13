package session

import (
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Session represents an active IDA analysis session
type Session struct {
	ID           string
	BinaryPath   string
	CreatedAt    time.Time
	LastActivity time.Time
	Timeout      time.Duration
	SocketPath   string
	WorkerPID    int

	mu sync.RWMutex
}

// Touch updates last activity timestamp
func (s *Session) Touch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastActivity = time.Now()
}

// IsExpired checks if session exceeded timeout
func (s *Session) IsExpired() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.LastActivity) > s.Timeout
}

// Metadata returns the persisted metadata for this session.
func (s *Session) Metadata() Metadata {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Metadata{
		ID:           s.ID,
		BinaryPath:   s.BinaryPath,
		CreatedAt:    s.CreatedAt,
		LastActivity: s.LastActivity,
		Timeout:      s.Timeout,
	}
}

// Registry manages active sessions
type Registry struct {
	sessions    map[string]*Session
	binaryIndex map[string]*Session
	mu          sync.RWMutex
	maxSessions int
}

// NewRegistry creates session registry
func NewRegistry(maxSessions int) *Registry {
	return &Registry{
		sessions:    make(map[string]*Session),
		binaryIndex: make(map[string]*Session),
		maxSessions: maxSessions,
	}
}

// Create adds new session
func (r *Registry) Create(binaryPath string, timeout time.Duration) (*Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.sessions) >= r.maxSessions {
		return nil, fmt.Errorf("max sessions (%d) reached", r.maxSessions)
	}

	normPath := filepath.Clean(binaryPath)

	session := &Session{
		ID:           uuid.New().String()[:8],
		BinaryPath:   normPath,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		Timeout:      timeout,
		SocketPath:   fmt.Sprintf("/tmp/ida-worker-%s.sock", uuid.New().String()[:8]),
	}

	r.sessions[session.ID] = session
	r.binaryIndex[normPath] = session
	return session, nil
}

// Restore inserts an existing session into the registry (used on server restart).
func (r *Registry) Restore(meta Metadata) (*Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.sessions) >= r.maxSessions {
		return nil, fmt.Errorf("max sessions (%d) reached", r.maxSessions)
	}
	if _, exists := r.sessions[meta.ID]; exists {
		return nil, fmt.Errorf("session %s already exists", meta.ID)
	}

	normPath := filepath.Clean(meta.BinaryPath)
	session := &Session{
		ID:           meta.ID,
		BinaryPath:   normPath,
		CreatedAt:    meta.CreatedAt,
		LastActivity: meta.LastActivity,
		Timeout:      meta.Timeout,
		SocketPath:   fmt.Sprintf("/tmp/ida-worker-%s.sock", uuid.New().String()[:8]),
	}
	r.sessions[session.ID] = session
	r.binaryIndex[normPath] = session
	return session, nil
}

// FindByBinaryPath returns the session currently handling the given binary path.
func (r *Registry) FindByBinaryPath(path string) (*Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	sess, ok := r.binaryIndex[filepath.Clean(path)]
	return sess, ok
}

// Get retrieves session by ID
func (r *Registry) Get(id string) (*Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	session, ok := r.sessions[id]
	return session, ok
}

// Delete removes session
func (r *Registry) Delete(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if sess, ok := r.sessions[id]; ok {
		delete(r.binaryIndex, sess.BinaryPath)
		delete(r.sessions, id)
	}
}

// List returns all sessions
func (r *Registry) List() []*Session {
	r.mu.RLock()
	defer r.mu.RUnlock()

	sessions := make([]*Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		sessions = append(sessions, s)
	}
	return sessions
}

// Expired returns expired sessions
func (r *Registry) Expired() []*Session {
	r.mu.RLock()
	defer r.mu.RUnlock()

	expired := make([]*Session, 0)
	for _, s := range r.sessions {
		if s.IsExpired() {
			expired = append(expired, s)
		}
	}
	return expired
}
