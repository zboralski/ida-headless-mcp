package worker

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/zboralski/ida-headless-mcp/internal/session"
	pb "github.com/zboralski/ida-headless-mcp/ida/worker/v1"
	"github.com/zboralski/ida-headless-mcp/ida/worker/v1/workerconnect"
)

// Manager handles Python worker processes
type Manager struct {
	pythonScript string
	sessions     map[string]*WorkerClient
	logger       *log.Logger
	mu           sync.RWMutex
}

// WorkerClient wraps Connect clients for a session
type WorkerClient struct {
	SessionCtrl *workerconnect.SessionControlClient
	Analysis    *workerconnect.AnalysisToolsClient
	Health      *workerconnect.HealthcheckClient
	cmd         *exec.Cmd
	cancel      context.CancelFunc
	ctx         context.Context
	session     *session.Session
	binaryPath  string
}

// Controller captures the worker operations required by the server.
type Controller interface {
	Start(ctx context.Context, sess *session.Session, binaryPath string) error
	Stop(sessionID string) error
	GetClient(sessionID string) (*WorkerClient, error)
}

// NewManager creates worker manager
func NewManager(pythonScript string, logger *log.Logger) *Manager {
	return &Manager{
		pythonScript: pythonScript,
		sessions:     make(map[string]*WorkerClient),
		logger:       logger,
	}
}

// Start spawns Python worker for session
func (m *Manager) Start(ctx context.Context, sess *session.Session, binaryPath string) error {
	// Create Unix domain socket
	if err := os.RemoveAll(sess.SocketPath); err != nil {
		return fmt.Errorf("failed to remove old socket: %w", err)
	}

	// Start Python worker with independent lifecycle from HTTP request
	// Workers outlive the request that spawned them
	workerCtx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(workerCtx, "python3", m.pythonScript,
		"--socket", sess.SocketPath,
		"--binary", binaryPath,
		"--session-id", sess.ID)

	// In tests, discard output to prevent "Test I/O incomplete" errors
	// In production, inherit parent process output
	if flag.Lookup("test.v") != nil {
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
	} else {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("failed to start worker: %w", err)
	}

	sess.WorkerPID = cmd.Process.Pid
	m.logger.Printf("[Worker] Started PID %d for session %s", sess.WorkerPID, sess.ID)

	// Wait for socket to be ready
	if err := m.waitForSocket(sess.SocketPath, 10*time.Second); err != nil {
		cancel()
		// Kill and wait to avoid zombie process
		if killErr := cmd.Process.Kill(); killErr != nil {
			m.logger.Printf("[Worker] Failed to kill PID %d: %v", cmd.Process.Pid, killErr)
		}
		// Wait for process to exit and be reaped
		if waitErr := cmd.Wait(); waitErr != nil && !errors.Is(waitErr, os.ErrProcessDone) {
			m.logger.Printf("[Worker] Failed to wait for PID %d: %v", cmd.Process.Pid, waitErr)
		}
		return fmt.Errorf("worker socket not ready: %w", err)
	}

	// Create Connect clients over Unix socket
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", sess.SocketPath)
			},
		},
	}

	baseURL := "http://unix"
	sessionClient := workerconnect.NewSessionControlClient(httpClient, baseURL)
	analysisClient := workerconnect.NewAnalysisToolsClient(httpClient, baseURL)
	healthClient := workerconnect.NewHealthcheckClient(httpClient, baseURL)

	worker := &WorkerClient{
		SessionCtrl: &sessionClient,
		Analysis:    &analysisClient,
		Health:      &healthClient,
		cmd:         cmd,
		cancel:      cancel,
		ctx:         workerCtx,
		session:     sess,
		binaryPath:  binaryPath,
	}

	m.mu.Lock()
	m.sessions[sess.ID] = worker
	m.mu.Unlock()

	go m.monitorWorker(sess.ID, worker)

	return nil
}

func (m *Manager) monitorWorker(sessionID string, worker *WorkerClient) {
	err := worker.cmd.Wait()
	if err != nil && worker.ctx.Err() == nil {
		m.logger.Printf("[Worker] Process %d exited with error for session %s: %v", worker.session.WorkerPID, sessionID, err)
	} else {
		m.logger.Printf("[Worker] Process %d exited for session %s", worker.session.WorkerPID, sessionID)
	}

	m.mu.Lock()
	delete(m.sessions, sessionID)
	m.mu.Unlock()
}

// Stop terminates worker for session
func (m *Manager) Stop(sessionID string) error {
	m.mu.RLock()
	worker, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("no worker for session %s", sessionID)
	}

	m.logger.Printf("[Worker] Stopping session %s PID %d", sessionID, worker.cmd.Process.Pid)

	// Close session gracefully
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if worker.SessionCtrl != nil {
		(*worker.SessionCtrl).CloseSession(ctx, connect.NewRequest(&pb.CloseSessionRequest{Save: true}))
	}

	// Cancel context and kill process
	worker.cancel()
	var killErr error
	if worker.cmd.Process != nil {
		killErr = worker.cmd.Process.Kill()
		if killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
			m.logger.Printf("[Worker] Failed to kill PID %d: %v", worker.cmd.Process.Pid, killErr)
		}
	}

	// Wait for process to exit and be reaped - prevent zombie
	// The monitorWorker goroutine will also call Wait(), but that's safe
	// (subsequent Wait() calls return the cached result)
	if waitErr := worker.cmd.Wait(); waitErr != nil && !errors.Is(waitErr, os.ErrProcessDone) {
		m.logger.Printf("[Worker] Process %d wait error: %v", worker.cmd.Process.Pid, waitErr)
	}

	m.mu.Lock()
	delete(m.sessions, sessionID)
	m.mu.Unlock()

	if killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
		return fmt.Errorf("failed to kill worker: %w", killErr)
	}
	return nil
}

// GetClient returns Connect clients for session
func (m *Manager) GetClient(sessionID string) (*WorkerClient, error) {
	m.mu.RLock()
	worker, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no worker for session %s", sessionID)
	}
	return worker, nil
}

// waitForSocket polls until socket exists
func (m *Manager) waitForSocket(socketPath string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			// Try to connect
			conn, err := net.Dial("unix", socketPath)
			if err == nil {
				conn.Close()
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for socket %s", socketPath)
}
