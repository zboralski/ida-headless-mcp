package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/zboralski/ida-headless-mcp/internal/server"
	"github.com/zboralski/ida-headless-mcp/internal/session"
	"github.com/zboralski/ida-headless-mcp/internal/worker"
)

var (
	configPath   = flag.String("config", "config.json", "Path to server config")
	portFlag     = flag.Int("port", 0, "HTTP port (overrides config)")
	pythonWorker = flag.String("worker", "", "Python worker script (overrides config)")
	maxSessions  = flag.Int("max-sessions", 0, "Max concurrent sessions (overrides config)")
	timeoutFlag  = flag.Duration("session-timeout", 0, "Session idle timeout (overrides config)")
	debugFlag    = flag.Bool("debug", false, "Enable verbose debug logging")
)

func main() {
	flag.Parse()

	logger := log.New(os.Stdout, "[MCP] ", log.LstdFlags)
	logger.Printf("Starting IDA Headless MCP Server")
	cfg, err := server.LoadConfig(*configPath)
	if err != nil {
		logger.Fatalf("failed to load config: %v", err)
	}

	server.ApplyEnvOverrides(&cfg)

	if *portFlag > 0 {
		cfg.Port = *portFlag
	}
	if *pythonWorker != "" {
		cfg.PythonWorkerPath = *pythonWorker
	}
	if *maxSessions > 0 {
		cfg.MaxConcurrentSession = *maxSessions
	}

	sessionTimeout := time.Duration(cfg.SessionTimeoutMin) * time.Minute
	if *timeoutFlag > 0 {
		sessionTimeout = *timeoutFlag
	}

	if *debugFlag {
		cfg.Debug = true
	}

	// Validate configuration before starting server
	if err := validateConfig(&cfg); err != nil {
		logger.Fatalf("invalid configuration: %v", err)
	}

	registry := session.NewRegistry(cfg.MaxConcurrentSession)
	workers := worker.NewManager(cfg.PythonWorkerPath, logger)
	stateDir := filepath.Join(cfg.DatabaseDirectory, "sessions")
	store, err := session.NewStore(stateDir)
	if err != nil {
		logger.Fatalf("failed to initialize session store: %v", err)
	}

	srv := server.New(registry, workers, logger, sessionTimeout, cfg.Debug, store)

	srv.RestoreSessions()

	go srv.Watchdog()

	mcpServer := mcp.NewServer(&mcp.Implementation{
		Name:    "ida-headless",
		Version: "0.1.0",
	}, nil)

	srv.RegisterTools(mcpServer)

	addr := fmt.Sprintf(":%d", cfg.Port)
	mux := srv.HTTPMux(mcpServer)

	httpServer := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	logger.Printf("Listening on %s", addr)
	logger.Printf("HTTP transport at http://localhost:%d/", cfg.Port)
	logger.Printf("SSE transport at http://localhost:%d/sse", cfg.Port)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		logger.Println("Shutting down gracefully...")

		// Give HTTP server 10 seconds to finish in-flight requests
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Printf("HTTP server shutdown error: %v", err)
		}

		// Stop all workers and log any errors
		for _, sess := range registry.List() {
			if err := workers.Stop(sess.ID); err != nil {
				logger.Printf("Failed to stop worker %s: %v", sess.ID, err)
			}
		}

		logger.Println("Shutdown complete")
		os.Exit(0)
	}()

	if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
		logger.Fatal(err)
	}
}

func validateConfig(cfg *server.Config) error {
	// Validate MaxConcurrentSession
	if cfg.MaxConcurrentSession <= 0 {
		return fmt.Errorf("max_concurrent_sessions must be positive, got %d (use a reasonable limit like 10)", cfg.MaxConcurrentSession)
	}

	// Validate PythonWorkerPath exists and is executable
	if cfg.PythonWorkerPath == "" {
		return fmt.Errorf("python_worker_path is required")
	}

	// Make path absolute for clarity in error messages
	absPath, err := filepath.Abs(cfg.PythonWorkerPath)
	if err != nil {
		return fmt.Errorf("invalid python_worker_path %q: %w", cfg.PythonWorkerPath, err)
	}
	cfg.PythonWorkerPath = absPath

	// Check file exists
	info, err := os.Stat(cfg.PythonWorkerPath)
	if err != nil {
		return fmt.Errorf("python_worker_path %q not found: %w", cfg.PythonWorkerPath, err)
	}

	// Check it's a file, not a directory
	if info.IsDir() {
		return fmt.Errorf("python_worker_path %q is a directory, expected a Python script", cfg.PythonWorkerPath)
	}

	// Check it's executable (Unix-like systems)
	if info.Mode()&0111 == 0 {
		return fmt.Errorf("python_worker_path %q is not executable (try: chmod +x %s)", cfg.PythonWorkerPath, cfg.PythonWorkerPath)
	}

	return nil
}
