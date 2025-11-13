package worker

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/zboralski/ida-headless-mcp/internal/session"
)

func TestManagerWorkerHasIndependentLifecycle(t *testing.T) {
	scriptPath := writeFakeWorker(t)
	logger := log.New(io.Discard, "", 0)
	mgr := NewManager(scriptPath, logger)

	sess := &session.Session{
		ID:         "test-session",
		SocketPath: filepath.Join(os.TempDir(), fmt.Sprintf("ida-worker-test-%d.sock", time.Now().UnixNano())),
	}

	// Workers have independent lifecycle - they survive request cancellation
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // simulate request finishing immediately

	if err := mgr.Start(ctx, sess, "/bin/ls"); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	t.Cleanup(func() {
		_ = os.Remove(sess.SocketPath)
		_ = mgr.Stop(sess.ID)
	})

	// Worker should still be running despite cancelled request context
	time.Sleep(200 * time.Millisecond)
	if !processAlive(sess.WorkerPID) {
		t.Fatalf("worker process %d exited after parent context cancelled", sess.WorkerPID)
	}

	// Should be able to fetch the client
	if _, err := mgr.GetClient(sess.ID); err != nil {
		t.Fatalf("GetClient failed: %v", err)
	}
}

func writeFakeWorker(t *testing.T) string {
	t.Helper()
	script := `#!/usr/bin/env python3
import argparse, os, socket, time, signal, sys
parser = argparse.ArgumentParser()
parser.add_argument("--socket", required=True)
parser.add_argument("--binary", required=True)
parser.add_argument("--session-id", required=True)
args = parser.parse_args()
if os.path.exists(args.socket):
    os.remove(args.socket)
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.bind(args.socket)
sock.listen(1)
def handle_signal(signum, frame):
    sys.exit(0)
signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)
while True:
    try:
        conn, _ = sock.accept()
        conn.close()
    except Exception:
        time.sleep(0.1)
`
	path := filepath.Join(t.TempDir(), "fake_worker.py")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("failed to write fake worker: %v", err)
	}
	return path
}

func processAlive(pid int) bool {
	if pid == 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil
}
