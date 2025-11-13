
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/zboralski/ida-headless-mcp/internal/session"
	"github.com/zboralski/ida-headless-mcp/internal/worker"
)

const (
	entryPointAddr      = 4294969696 // ls_arm64e entry point (start function)
	humanizeNumberAddr  = 4295000064 // _humanize_number_ptr global (has data refs)
)

var (
	updateGoldens = flag.Bool("update", false, "update golden golden files")
)

// TestMCPToolGoldens tests all MCP tools against a real server with ls_arm64e
// and compares responses against golden golden files.
//
// The test starts its own server on a random port with real IDA workers.
// Run with -update to regenerate golden.
//
// Usage:
//
//	go test -v -run TestMCPToolGoldens
//	go test -v -run TestMCPToolGoldens -update
func TestMCPToolGoldens(t *testing.T) {

	// Setup test environment
	conn, sid := setupGoldenTest(t)
	ctx := context.Background()

	// Test cases - tools excluded from golden:
	// - Dynamic data: list_sessions, get_session_progress (timestamps)
	// - Plain text: get_disasm, get_decompiled_func (not JSON)
	// - Empty results: get_comment, get_func_comment (no comments set)
	tests := []struct {
		name string
		tool string
		args map[string]any
	}{
		// Basic info
		{"entry_point", "get_entry_point", map[string]any{"session_id": sid}},
		{"segments", "get_segments", map[string]any{"session_id": sid}},

		// Functions
		{"functions_limit_10", "get_functions", map[string]any{"session_id": sid, "limit": 10}},
		{"functions_regex_sort", "get_functions", map[string]any{"session_id": sid, "regex": ".*sort.*", "case_sensitive": false}},
		{"function_name_entry", "get_function_name", map[string]any{"session_id": sid, "address": entryPointAddr}},
		{"function_info_entry", "get_function_info", map[string]any{"session_id": sid, "address": entryPointAddr}},
		{"function_disasm_entry", "get_function_disasm", map[string]any{"session_id": sid, "address": entryPointAddr}},

		// Strings
		{"strings_limit_10", "get_strings", map[string]any{"session_id": sid, "limit": 10}},
		{"strings_regex_error", "get_strings", map[string]any{"session_id": sid, "regex": "error", "case_sensitive": false, "limit": 5}},

		// Imports/Exports
		{"imports_limit_10", "get_imports", map[string]any{"session_id": sid, "limit": 10}},
		{"exports_limit_10", "get_exports", map[string]any{"session_id": sid, "limit": 10}},

		// Cross-references
		{"xrefs_to_entry", "get_xrefs_to", map[string]any{"session_id": sid, "address": entryPointAddr}},
		{"xrefs_from_entry", "get_xrefs_from", map[string]any{"session_id": sid, "address": entryPointAddr}},
		{"data_refs_humanize_number", "get_data_refs", map[string]any{"session_id": sid, "address": humanizeNumberAddr}},
		{"bytes_entry_16", "get_bytes", map[string]any{"session_id": sid, "address": entryPointAddr, "size": 16}},

		// Read operations
		{"dword_at_entry", "get_dword_at", map[string]any{"session_id": sid, "address": entryPointAddr}},
		{"qword_at_entry", "get_qword_at", map[string]any{"session_id": sid, "address": entryPointAddr}},
		{"instruction_length_entry", "get_instruction_length", map[string]any{"session_id": sid, "address": entryPointAddr}},

		// Type information
		{"type_at_entry", "get_type_at", map[string]any{"session_id": sid, "address": entryPointAddr}},
		// Note: list_structs and list_enums excluded - IDA assigns non-deterministic type IDs

		// Globals
		{"globals_regex_sort", "get_globals", map[string]any{"session_id": sid, "regex": ".*sort.*"}},

		// Names
		{"name_entry", "get_name", map[string]any{"session_id": sid, "address": entryPointAddr}},
	}

	goldenDir := filepath.Join("testdata", "golden")
	if err := os.MkdirAll(goldenDir, 0o755); err != nil {
		t.Fatalf("create golden dir: %v", err)
	}

	for _, tt := range tests {
		tt := tt // Capture range variable
		t.Run(tt.name, func(t *testing.T) {
			result, err := conn.CallTool(ctx, &mcp.CallToolParams{
				Name:      tt.tool,
				Arguments: tt.args,
			})
			if err != nil {
				t.Fatalf("call %s: %v", tt.tool, err)
			}

			payload := decodeToolResult(t, result)
			got, err := json.MarshalIndent(payload, "", "  ")
			if err != nil {
				t.Fatalf("marshal result: %v", err)
			}

			goldenPath := filepath.Join(goldenDir, tt.name+".json")

			if *updateGoldens {
				if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
					t.Fatalf("write golden: %v", err)
				}
				t.Logf("updated golden: %s", goldenPath)
			} else {
				want, err := os.ReadFile(goldenPath)
				if err != nil {
					if os.IsNotExist(err) {
						t.Fatalf("golden missing (run with -update): %s", goldenPath)
					}
					t.Fatalf("read golden: %v", err)
				}

				if !bytes.Equal(got, want) {
					t.Errorf("golden mismatch\nRun with -update to accept changes\n\nGot:\n%s\n\nWant:\n%s",
						string(got), string(want))
				}
			}
		})
	}
}

// setupGoldenTest creates a test server with ls_arm64e loaded and analyzed
func setupGoldenTest(t *testing.T) (*mcp.ClientSession, string) {
	t.Helper()

	origBinaryPath, err := filepath.Abs(filepath.Join("..", "..", "..", "samples", "ls_arm64e"))
	if err != nil {
		t.Fatalf("resolve sample path: %v", err)
	}
	if _, err := os.Stat(origBinaryPath); os.IsNotExist(err) {
		t.Skipf("sample binary not found: %s", origBinaryPath)
	}

	// Copy binary to temp dir to avoid database file conflicts
	testDir := t.TempDir()
	samplePath := filepath.Join(testDir, "ls_arm64e")
	data, err := os.ReadFile(origBinaryPath)
	if err != nil {
		t.Fatalf("read sample binary: %v", err)
	}
	if err := os.WriteFile(samplePath, data, 0755); err != nil {
		t.Fatalf("copy sample binary: %v", err)
	}

	workerScript, err := filepath.Abs(filepath.Join("..", "..", "python", "worker", "server.py"))
	if err != nil {
		t.Fatalf("resolve worker script: %v", err)
	}

	// Create test server
	logger := log.New(io.Discard, "", 0)
	if testing.Verbose() {
		logger = log.New(os.Stderr, "[test] ", log.LstdFlags)
	}
	registry := session.NewRegistry(4)
	workerMgr := worker.NewManager(workerScript, logger)
	store, err := session.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("create session store: %v", err)
	}

	srv := &Server{
		registry:       registry,
		workers:        workerMgr,
		logger:         logger,
		sessionTimeout: 30 * time.Minute,
		debug:          testing.Verbose(),
		store:          store,
	}

	mcpServer := mcp.NewServer(&mcp.Implementation{
		Name:    "ida-headless-golden-test",
		Version: "0.0.1",
	}, nil)

	srv.RegisterTools(mcpServer)
	handler := srv.HTTPMux(mcpServer)
	httpServer := newIPv4HTTPServer(t, handler)
	t.Cleanup(httpServer.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)

	// Connect client
	client := mcp.NewClient(&mcp.Implementation{
		Name:    "golden-test",
		Version: "1.0.0",
	}, nil)

	transport := &mcp.StreamableClientTransport{Endpoint: httpServer.URL}
	conn, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("connect to server: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	// Open binary and analyze
	resp, err := conn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "open_binary",
		Arguments: map[string]any{"path": samplePath},
	})
	if err != nil {
		t.Fatalf("open binary: %v", err)
	}

	payload := decodeToolResult(t, resp)
	sid, ok := payload["session_id"].(string)
	if !ok || sid == "" {
		t.Fatalf("invalid session_id in response: %v", payload)
	}

	if _, err := conn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "run_auto_analysis",
		Arguments: map[string]any{"session_id": sid},
	}); err != nil {
		t.Fatalf("run auto analysis: %v", err)
	}

	// Cleanup: save database and close session
	t.Cleanup(func() {
		ctx := context.Background()
		conn.CallTool(ctx, &mcp.CallToolParams{
			Name:      "save_database",
			Arguments: map[string]any{"session_id": sid},
		})
		conn.CallTool(ctx, &mcp.CallToolParams{
			Name:      "close_session",
			Arguments: map[string]any{"session_id": sid, "save": true},
		})
	})

	t.Logf("test server ready: session=%s binary=%s", sid, filepath.Base(samplePath))
	return conn, sid
}

func decodeToolResult(t *testing.T, result *mcp.CallToolResult) map[string]any {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("empty content in tool result")
	}
	textContent, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("unexpected content type: %T", result.Content[0])
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(textContent.Text), &payload); err != nil {
		t.Fatalf("unmarshal result: %v (text: %s)", err, textContent.Text)
	}
	return payload
}
