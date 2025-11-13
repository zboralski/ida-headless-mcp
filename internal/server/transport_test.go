
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/zboralski/ida-headless-mcp/internal/session"
	"github.com/zboralski/ida-headless-mcp/internal/worker"
	pb "github.com/zboralski/ida-headless-mcp/ida/worker/v1"
	"github.com/zboralski/ida-headless-mcp/ida/worker/v1/workerconnect"
)

func TestStreamableHTTPTransportLifecycle(t *testing.T) {
	t.Parallel()
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	transport := &mcp.StreamableClientTransport{Endpoint: httpServer.URL}
	runLifecycleScenario(t, transport)
}

func TestSSETransportLifecycle(t *testing.T) {
	t.Parallel()
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	transport := &mcp.SSEClientTransport{Endpoint: httpServer.URL + "/sse"}
	runLifecycleScenario(t, transport)
}

func TestOpenBinaryReusesActiveSession(t *testing.T) {
	t.Parallel()
	httpServer, workers := setupTestMCPServer(t)
	defer httpServer.Close()

	testBinary := filepath.Join(t.TempDir(), "reuse-test.bin")
	sessionConn, sessionID1 := openTestSession(t, httpServer.URL, testBinary)
	ctx := context.Background()
	result2, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "open_binary",
		Arguments: map[string]any{"path": testBinary},
	})
	if err != nil {
		t.Fatalf("open_binary (2): %v", err)
	}
	payload2 := decodeContent(t, result2)
	sessionID2, _ := payload2["session_id"].(string)
	if sessionID2 != sessionID1 {
		t.Fatalf("expected same session id, got %s and %s", sessionID1, sessionID2)
	}
	if reused, _ := payload2["reused"].(bool); !reused {
		t.Fatalf("expected reused flag to be true: %v", payload2)
	}
	if workers.StartCount(testBinary) != 1 {
		t.Fatalf("expected worker to start once for binary, got %d", workers.StartCount(testBinary))
	}
}

func TestGetStringsRegexFiltering(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	testBinary := filepath.Join(t.TempDir(), "strings.bin")
	sessionConn, sessionID := openTestSession(t, httpServer.URL, testBinary)
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name: "get_strings",
		Arguments: map[string]any{
			"session_id":     sessionID,
			"regex":          "alpha",
			"limit":          10,
			"case_sensitive": false,
		},
	})
	if err != nil {
		t.Fatalf("get_strings: %v", err)
	}
	payload := decodeContent(t, resp)
	if count, _ := payload["count"].(float64); count != 1 {
		t.Fatalf("expected 1 filtered string, got %v", payload)
	}
}

func TestGetImportsFilters(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	testBinary := filepath.Join(t.TempDir(), "imports.bin")
	sessionConn, sessionID := openTestSession(t, httpServer.URL, testBinary)
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name: "get_imports",
		Arguments: map[string]any{
			"session_id":     sessionID,
			"module":         "libalpha",
			"regex":          "Helper",
			"case_sensitive": false,
		},
	})
	if err != nil {
		t.Fatalf("get_imports: %v", err)
	}
	payload := decodeContent(t, resp)
	if count, _ := payload["count"].(float64); count != 1 {
		t.Fatalf("expected filtered import count 1, got %v", payload)
	}
}

func TestGetFunctionsRegexFiltering(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	testBinary := filepath.Join(t.TempDir(), "functions.bin")
	sessionConn, sessionID := openTestSession(t, httpServer.URL, testBinary)
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name: "get_functions",
		Arguments: map[string]any{
			"session_id":     sessionID,
			"regex":          "helper",
			"case_sensitive": false,
		},
	})
	if err != nil {
		t.Fatalf("get_functions regex: %v", err)
	}
	payload := decodeContent(t, resp)
	if count, _ := payload["count"].(float64); count != 1 {
		t.Fatalf("expected filtered functions count 1, got %v", payload)
	}
}

func TestCrossReferenceTools(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	samplePath := filepath.Join("..", "samples", "test_xrefs_arm64")
	sessionConn, sessionID := openTestSession(t, httpServer.URL, samplePath)
	ctx := context.Background()

	if _, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "run_auto_analysis",
		Arguments: map[string]any{"session_id": sessionID},
	}); err != nil {
		t.Fatalf("run_auto_analysis: %v", err)
	}

	call := func(name string, addr uint64) map[string]any {
		resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
			Name:      name,
			Arguments: map[string]any{"session_id": sessionID, "address": addr},
		})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return decodeContent(t, resp)
	}

	if payload := call("get_xrefs_to", 0x1000); payload["count"].(float64) == 0 {
		t.Fatalf("expected xrefs_to count > 0, got %v", payload)
	}
	if payload := call("get_xrefs_from", 0x1000); payload["count"].(float64) == 0 {
		t.Fatalf("expected xrefs_from count > 0, got %v", payload)
	}
	if payload := call("get_data_refs", 0x1000); payload["count"].(float64) == 0 {
		t.Fatalf("expected data_refs count > 0, got %v", payload)
	}
	if payload := call("get_string_xrefs", 0x2000); payload["count"].(float64) == 0 {
		t.Fatalf("expected string_xrefs count > 0, got %v", payload)
	}
}

func TestRunAutoAnalysisInvalidatesFunctionCache(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	testBinary := filepath.Join(t.TempDir(), "cache.bin")
	sessionConn, sessionID := openTestSession(t, httpServer.URL, testBinary)
	ctx := context.Background()

	// Initial call before analysis should return the small function set.
	beforeResp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name: "get_functions",
		Arguments: map[string]any{
			"session_id": sessionID,
			"limit":      10,
		},
	})
	if err != nil {
		t.Fatalf("get_functions before analysis: %v", err)
	}
	beforePayload := decodeContent(t, beforeResp)
	if total, _ := beforePayload["total"].(float64); total != 2 {
		t.Fatalf("expected 2 functions before analysis, got %v", beforePayload)
	}

	// Run auto analysis (plan_and_wait) which should invalidate caches.
	if _, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name: "run_auto_analysis",
		Arguments: map[string]any{
			"session_id": sessionID,
		},
	}); err != nil {
		t.Fatalf("run_auto_analysis: %v", err)
	}

	// Subsequent call should see the expanded function set.
	afterResp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name: "get_functions",
		Arguments: map[string]any{
			"session_id": sessionID,
			"limit":      10,
		},
	})
	if err != nil {
		t.Fatalf("get_functions after analysis: %v", err)
	}
	afterPayload := decodeContent(t, afterResp)
	if total, _ := afterPayload["total"].(float64); total != 4 {
		t.Fatalf("expected 4 functions after analysis, got %v", afterPayload)
	}
}

func TestSetFunctionTypeTool(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	testBinary := filepath.Join(t.TempDir(), "prototype.bin")
	sessionConn, sessionID := openTestSession(t, httpServer.URL, testBinary)
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name: "set_function_type",
		Arguments: map[string]any{
			"session_id": sessionID,
			"address":    0x1234,
			"prototype":  "int __fastcall foo(int a, int b)",
		},
	})
	if err != nil {
		t.Fatalf("set_function_type: %v", err)
	}
	payload := decodeContent(t, resp)
	if success, _ := payload["success"].(bool); !success {
		t.Fatalf("expected success response, got %v", payload)
	}
}

func TestSetLvarTypeTool(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	sessionConn, sessionID := openTestSession(t, httpServer.URL, filepath.Join(t.TempDir(), "lvar.bin"))
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name: "set_lvar_type",
		Arguments: map[string]any{
			"session_id":       sessionID,
			"function_address": 0x2000,
			"lvar_name":        "v1",
			"lvar_type":        "int",
		},
	})
	if err != nil {
		t.Fatalf("set_lvar_type: %v", err)
	}
	payload := decodeContent(t, resp)
	if success, _ := payload["success"].(bool); !success {
		t.Fatalf("expected success response, got %v", payload)
	}
}

func TestRenameLvarTool(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	sessionConn, sessionID := openTestSession(t, httpServer.URL, filepath.Join(t.TempDir(), "rename.bin"))
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name: "rename_lvar",
		Arguments: map[string]any{
			"session_id":       sessionID,
			"function_address": 0x2000,
			"lvar_name":        "v1",
			"new_name":         "score",
		},
	})
	if err != nil {
		t.Fatalf("rename_lvar: %v", err)
	}
	payload := decodeContent(t, resp)
	if success, _ := payload["success"].(bool); !success {
		t.Fatalf("expected success response, got %v", payload)
	}
}

func TestSetDecompilerCommentTool(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	sessionConn, sessionID := openTestSession(t, httpServer.URL, filepath.Join(t.TempDir(), "decomp.bin"))
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name: "set_decompiler_comment",
		Arguments: map[string]any{
			"session_id":       sessionID,
			"function_address": 0x3000,
			"address":          0x3004,
			"comment":          "TODO: check bounds",
		},
	})
	if err != nil {
		t.Fatalf("set_decompiler_comment: %v", err)
	}
	if success, _ := decodeContent(t, resp)["success"].(bool); !success {
		t.Fatalf("expected success response")
	}
}

func TestGetGlobalsTool(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	sessionConn, sessionID := openTestSession(t, httpServer.URL, filepath.Join(t.TempDir(), "globals.bin"))
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_globals",
		Arguments: map[string]any{"session_id": sessionID},
	})
	if err != nil {
		t.Fatalf("get_globals: %v", err)
	}
	payload := decodeContent(t, resp)
	if payload["count"].(float64) != 2 {
		t.Fatalf("expected 2 globals, got %v", payload)
	}
}

func TestSetGlobalTypeTool(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()
	sessionConn, sessionID := openTestSession(t, httpServer.URL, filepath.Join(t.TempDir(), "gtype.bin"))
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "set_global_type",
		Arguments: map[string]any{"session_id": sessionID, "address": 0x6000, "type": "int"},
	})
	if err != nil {
		t.Fatalf("set_global_type: %v", err)
	}
	if success, _ := decodeContent(t, resp)["success"].(bool); !success {
		t.Fatalf("expected success response")
	}
}

func TestRenameGlobalTool(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()
	sessionConn, sessionID := openTestSession(t, httpServer.URL, filepath.Join(t.TempDir(), "gname.bin"))
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "rename_global",
		Arguments: map[string]any{"session_id": sessionID, "address": 0x6000, "new_name": "gScore"},
	})
	if err != nil {
		t.Fatalf("rename_global: %v", err)
	}
	if success, _ := decodeContent(t, resp)["success"].(bool); !success {
		t.Fatalf("expected success response")
	}
}

func TestDataReadStringTool(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()
	sessionConn, sessionID := openTestSession(t, httpServer.URL, filepath.Join(t.TempDir(), "str.bin"))
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "data_read_string",
		Arguments: map[string]any{"session_id": sessionID, "address": 0x7000, "max_length": 32},
	})
	if err != nil {
		t.Fatalf("data_read_string: %v", err)
	}
	payload := decodeContent(t, resp)
	if payload["value"].(string) == "" {
		t.Fatalf("expected string value, got %v", payload)
	}
}

func TestDataReadByteTool(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()
	sessionConn, sessionID := openTestSession(t, httpServer.URL, filepath.Join(t.TempDir(), "byte.bin"))
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "data_read_byte",
		Arguments: map[string]any{"session_id": sessionID, "address": 0x8000},
	})
	if err != nil {
		t.Fatalf("data_read_byte: %v", err)
	}
	payload := decodeContent(t, resp)
	if _, ok := payload["value"].(float64); !ok {
		t.Fatalf("expected numeric value, got %v", payload)
	}
}

func TestListStructsTool(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()
	sessionConn, sessionID := openTestSession(t, httpServer.URL, filepath.Join(t.TempDir(), "structs.bin"))
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_structs",
		Arguments: map[string]any{"session_id": sessionID},
	})
	if err != nil {
		t.Fatalf("list_structs: %v", err)
	}
	payload := decodeContent(t, resp)
	if payload["count"].(float64) != 2 {
		t.Fatalf("expected 2 structs, got %v", payload)
	}
}

func TestGetStructTool(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()
	sessionConn, sessionID := openTestSession(t, httpServer.URL, filepath.Join(t.TempDir(), "struct-detail.bin"))
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name: "get_struct",
		Arguments: map[string]any{
			"session_id": sessionID,
			"name":       "Vector3",
		},
	})
	if err != nil {
		t.Fatalf("get_struct: %v", err)
	}
	payload := decodeContent(t, resp)
	if payload["name"].(string) != "Vector3" {
		t.Fatalf("expected Vector3 struct, got %v", payload)
	}
	if members, ok := payload["members"].([]any); !ok || len(members) == 0 {
		t.Fatalf("expected members in payload, got %v", payload)
	}
}

func TestFindBinaryTool(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()
	sessionConn, sessionID := openTestSession(t, httpServer.URL, filepath.Join(t.TempDir(), "findbin.bin"))
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "find_binary",
		Arguments: map[string]any{"session_id": sessionID, "start": 0x1000, "end": 0, "pattern": "90 90"},
	})
	if err != nil {
		t.Fatalf("find_binary: %v", err)
	}
	payload := decodeContent(t, resp)
	if payload["addresses"] == nil {
		t.Fatalf("expected addresses array, got %v", payload)
	}
}

func TestFindTextTool(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()
	sessionConn, sessionID := openTestSession(t, httpServer.URL, filepath.Join(t.TempDir(), "findtext.bin"))
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "find_text",
		Arguments: map[string]any{"session_id": sessionID, "start": 0x1000, "end": 0, "needle": "HTTP"},
	})
	if err != nil {
		t.Fatalf("find_text: %v", err)
	}
	payload := decodeContent(t, resp)
	if payload["addresses"] == nil {
		t.Fatalf("expected addresses array, got %v", payload)
	}
}

func TestGetFunctionDisasmTool(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	sessionConn, sessionID := openTestSession(t, httpServer.URL, filepath.Join(t.TempDir(), "funcdis.bin"))
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name: "get_function_disasm",
		Arguments: map[string]any{
			"session_id": sessionID,
			"address":    0xdeadbeef,
		},
	})
	if err != nil {
		t.Fatalf("get_function_disasm: %v", err)
	}
	payload := decodeContent(t, resp)
	if payload["disassembly"] == nil {
		t.Fatalf("expected disassembly field, got %v", payload)
	}
}

func TestImportIl2cppTool(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	sessionConn, sessionID := openTestSession(t, httpServer.URL, filepath.Join(t.TempDir(), "il2cpp.bin"))
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "script.json")
	if err := os.WriteFile(scriptPath, []byte(`{"ScriptMethod":[]}`), 0o600); err != nil {
		t.Fatalf("write script.json: %v", err)
	}
	headerPath := filepath.Join(tmpDir, "il2cpp.h")
	if err := os.WriteFile(headerPath, []byte("struct Foo { int a; };"), 0o600); err != nil {
		t.Fatalf("write il2cpp.h: %v", err)
	}
	ctx := context.Background()
	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name: "import_il2cpp",
		Arguments: map[string]any{
			"session_id":  sessionID,
			"script_path": scriptPath,
			"il2cpp_path": headerPath,
			"fields":      []string{"ScriptMethod"},
		},
	})
	if err != nil {
		t.Fatalf("import_il2cpp: %v", err)
	}
	payload := decodeContent(t, resp)
	if success, _ := payload["success"].(bool); !success {
		t.Fatalf("expected success response, got %v", payload)
	}
	if _, ok := payload["functions_named"]; !ok {
		t.Fatalf("expected functions_named field, got %v", payload)
	}
}

func TestGetSegments(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	testBinary := filepath.Join(t.TempDir(), "segments.bin")
	sessionConn, sessionID := openTestSession(t, httpServer.URL, testBinary)
	ctx := context.Background()

	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_segments",
		Arguments: map[string]any{"session_id": sessionID},
	})
	if err != nil {
		t.Fatalf("get_segments: %v", err)
	}

	payload := decodeContent(t, resp)
	count, _ := payload["count"].(float64)
	if count != 2 {
		t.Fatalf("expected 2 segments, got %v", payload)
	}

	segments, ok := payload["segments"].([]interface{})
	if !ok || len(segments) != 2 {
		t.Fatalf("expected 2 segments array, got %v", payload["segments"])
	}

	seg0 := segments[0].(map[string]interface{})
	if seg0["name"] != ".text" {
		t.Fatalf("expected first segment name .text, got %v", seg0["name"])
	}
}

func TestGetFunctionName(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	testBinary := filepath.Join(t.TempDir(), "funcname.bin")
	sessionConn, sessionID := openTestSession(t, httpServer.URL, testBinary)
	ctx := context.Background()

	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_function_name",
		Arguments: map[string]any{"session_id": sessionID, "address": 0x1234},
	})
	if err != nil {
		t.Fatalf("get_function_name: %v", err)
	}

	payload := decodeContent(t, resp)
	name, ok := payload["name"].(string)
	if !ok || name != "func_1234" {
		t.Fatalf("expected name func_1234, got %v", payload)
	}
}

func TestGetEntryPoint(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	testBinary := filepath.Join(t.TempDir(), "entrypoint.bin")
	sessionConn, sessionID := openTestSession(t, httpServer.URL, testBinary)
	ctx := context.Background()

	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_entry_point",
		Arguments: map[string]any{"session_id": sessionID},
	})
	if err != nil {
		t.Fatalf("get_entry_point: %v", err)
	}

	payload := decodeContent(t, resp)
	address, ok := payload["address"].(float64)
	if !ok || address != 0x100000 {
		t.Fatalf("expected address 0x100000, got %v", payload)
	}
}

func TestMakeFunction(t *testing.T) {
	httpServer, _ := setupTestMCPServer(t)
	defer httpServer.Close()

	testBinary := filepath.Join(t.TempDir(), "makefunc.bin")
	sessionConn, sessionID := openTestSession(t, httpServer.URL, testBinary)
	ctx := context.Background()

	resp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "make_function",
		Arguments: map[string]any{"session_id": sessionID, "address": 0x1000},
	})
	if err != nil {
		t.Fatalf("make_function: %v", err)
	}

	payload := decodeContent(t, resp)
	success, ok := payload["success"].(bool)
	if !ok || !success {
		t.Fatalf("expected success true, got %v", payload)
	}
}

func setupTestMCPServer(t *testing.T) (*httptest.Server, *fakeWorkerManager) {
	t.Helper()

	logger := log.New(io.Discard, "", 0)
	registry := session.NewRegistry(4)
	workers := newFakeWorkerManager(t)
	store, err := session.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create session store: %v", err)
	}

	srv := &Server{
		registry:       registry,
		workers:        workers,
		logger:         logger,
		sessionTimeout: time.Minute,
		debug:          true,
		store:          store,
	}

	mcpServer := mcp.NewServer(&mcp.Implementation{
		Name:    "ida-headless-test",
		Version: "0.0.1",
	}, nil)

	srv.RegisterTools(mcpServer)
	handler := srv.HTTPMux(mcpServer)
	return newIPv4HTTPServer(t, handler), workers
}

func runLifecycleScenario(t *testing.T, transport mcp.Transport) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{
		Name:    "integration-client",
		Version: "0.0.1",
	}, nil)

	sessionConn, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer sessionConn.Close()

	listResp, err := sessionConn.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(listResp.Tools) == 0 {
		t.Fatal("expected at least one tool registered")
	}

	binaryPath := filepath.Join(t.TempDir(), "lifecycle.bin")
	open, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "open_binary",
		Arguments: map[string]any{"path": binaryPath},
	})
	if err != nil {
		t.Fatalf("open_binary: %v", err)
	}
	openPayload := decodeContent(t, open)
	sessionID, ok := openPayload["session_id"].(string)
	if !ok || sessionID == "" {
		t.Fatalf("expected session_id in open_binary result, got %v", openPayload)
	}

	funcs, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_functions",
		Arguments: map[string]any{"session_id": sessionID},
	})
	if err != nil {
		t.Fatalf("get_functions: %v", err)
	}
	funcPayload := decodeContent(t, funcs)
	if count, ok := funcPayload["count"].(float64); !ok || count == 0 {
		t.Fatalf("expected functions count > 0, got %v", funcPayload)
	}

	paged, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_functions",
		Arguments: map[string]any{"session_id": sessionID, "limit": 1},
	})
	if err != nil {
		t.Fatalf("get_functions pagination: %v", err)
	}
	pagedPayload := decodeContent(t, paged)
	if count, ok := pagedPayload["count"].(float64); !ok || count != 1 {
		t.Fatalf("expected paged count 1, got %v", pagedPayload)
	}
	funcsValue, ok := pagedPayload["functions"].([]interface{})
	if !ok || len(funcsValue) != 1 {
		t.Fatalf("expected single function entry, got %v", pagedPayload["functions"])
	}

	sessionsResp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_sessions",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("list_sessions: %v", err)
	}
	sessionsPayload := decodeContent(t, sessionsResp)
	if count, ok := sessionsPayload["count"].(float64); !ok || count != 1 {
		t.Fatalf("expected 1 active session, got %v", sessionsPayload)
	}

	closeResp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "close_binary",
		Arguments: map[string]any{"session_id": sessionID},
	})
	if err != nil {
		t.Fatalf("close_binary: %v", err)
	}
	closePayload := decodeContent(t, closeResp)
	if success, ok := closePayload["success"].(bool); !ok || !success {
		t.Fatalf("expected success on close_binary, got %v", closePayload)
	}
}

func decodeContent(t *testing.T, result *mcp.CallToolResult) map[string]any {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("missing content in response")
	}
	textContent, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("unexpected content type %T", result.Content[0])
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(textContent.Text), &payload); err != nil {
		t.Fatalf("decode content: %v", err)
	}
	return payload
}

func openTestSession(t *testing.T, endpoint, binaryPath string) (*mcp.ClientSession, string) {
	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	sessionConn, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { sessionConn.Close() })
	openResp, err := sessionConn.CallTool(ctx, &mcp.CallToolParams{
		Name:      "open_binary",
		Arguments: map[string]any{"path": binaryPath},
	})
	if err != nil {
		t.Fatalf("open_binary: %v", err)
	}
	payload := decodeContent(t, openResp)
	sessionID, _ := payload["session_id"].(string)
	if sessionID == "" {
		t.Fatalf("missing session id in response: %v", payload)
	}
	return sessionConn, sessionID
}

func newIPv4HTTPServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("tcp4 listen not permitted: %v", err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener = ln
	server.Start()
	return server
}

type fakeWorkerManager struct {
	t        *testing.T
	mu       sync.Mutex
	sessions map[string]*fakeWorker
	starts   map[string]int
}

func newFakeWorkerManager(t *testing.T) *fakeWorkerManager {
	return &fakeWorkerManager{
		t:        t,
		sessions: make(map[string]*fakeWorker),
		starts:   make(map[string]int),
	}
}

type fakeWorker struct {
	sessionID string
	server    *httptest.Server
	client    *worker.WorkerClient

	mu         sync.Mutex
	binaryPath string
	closed     bool
	analyzed   bool
}

func (f *fakeWorkerManager) Start(_ context.Context, sess *session.Session, binaryPath string) error {
	fake := &fakeWorker{sessionID: sess.ID, binaryPath: binaryPath}

	sessionSvc := &fakeSessionControlServer{worker: fake}
	analysisSvc := &fakeAnalysisServer{worker: fake}
	healthSvc := &fakeHealthServer{}

	// Create Connect RPC handlers without options. Do not pass nil as the
	// second argument - when nil is passed to a variadic parameter and
	// unpacked with ..., it causes a nil pointer dereference.
	mux := http.NewServeMux()
	mux.Handle(workerconnect.NewSessionControlHandler(sessionSvc))
	mux.Handle(workerconnect.NewAnalysisToolsHandler(analysisSvc))
	mux.Handle(workerconnect.NewHealthcheckHandler(healthSvc))

	server := newIPv4HTTPServer(f.t, mux)

	httpClient := server.Client()
	baseURL := server.URL
	sessionClient := workerconnect.NewSessionControlClient(httpClient, baseURL)
	analysisClient := workerconnect.NewAnalysisToolsClient(httpClient, baseURL)
	healthClient := workerconnect.NewHealthcheckClient(httpClient, baseURL)

	fake.server = server
	fake.client = &worker.WorkerClient{
		SessionCtrl: &sessionClient,
		Analysis:    &analysisClient,
		Health:      &healthClient,
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.sessions[sess.ID] = fake
	f.starts[binaryPath]++
	return nil
}

func (f *fakeWorkerManager) Stop(sessionID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	fake, ok := f.sessions[sessionID]
	if !ok {
		return fmt.Errorf("no worker for session %s", sessionID)
	}
	fake.server.Close()
	delete(f.sessions, sessionID)
	return nil
}

func (f *fakeWorkerManager) GetClient(sessionID string) (*worker.WorkerClient, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fake, ok := f.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("no worker for session %s", sessionID)
	}
	return fake.client, nil
}

func (f *fakeWorkerManager) StartCount(binaryPath string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.starts[binaryPath]
}

type fakeSessionControlServer struct {
	worker *fakeWorker
}

func (f *fakeSessionControlServer) OpenBinary(_ context.Context, req *connect.Request[pb.OpenBinaryRequest]) (*connect.Response[pb.OpenBinaryResponse], error) {
	f.worker.mu.Lock()
	f.worker.binaryPath = req.Msg.GetBinaryPath()
	f.worker.closed = false
	f.worker.mu.Unlock()
	return connect.NewResponse(&pb.OpenBinaryResponse{
		Success:       true,
		HasDecompiler: true,
		BinaryPath:    req.Msg.GetBinaryPath(),
	}), nil
}

func (f *fakeSessionControlServer) CloseSession(_ context.Context, _ *connect.Request[pb.CloseSessionRequest]) (*connect.Response[pb.CloseSessionResponse], error) {
	f.worker.mu.Lock()
	f.worker.closed = true
	f.worker.mu.Unlock()
	return connect.NewResponse(&pb.CloseSessionResponse{Success: true}), nil
}

func (f *fakeSessionControlServer) PlanAndWait(_ context.Context, _ *connect.Request[pb.PlanAndWaitRequest]) (*connect.Response[pb.PlanAndWaitResponse], error) {
	f.worker.mu.Lock()
	f.worker.analyzed = true
	f.worker.mu.Unlock()
	return connect.NewResponse(&pb.PlanAndWaitResponse{
		Success:         true,
		DurationSeconds: 0.1,
	}), nil
}

func (f *fakeSessionControlServer) SaveDatabase(_ context.Context, _ *connect.Request[pb.SaveDatabaseRequest]) (*connect.Response[pb.SaveDatabaseResponse], error) {
	return connect.NewResponse(&pb.SaveDatabaseResponse{
		Success:   true,
		Timestamp: time.Now().Unix(),
		Dirty:     false,
	}), nil
}

func (f *fakeSessionControlServer) GetSessionInfo(_ context.Context, _ *connect.Request[pb.GetSessionInfoRequest]) (*connect.Response[pb.GetSessionInfoResponse], error) {
	f.worker.mu.Lock()
	defer f.worker.mu.Unlock()
	return connect.NewResponse(&pb.GetSessionInfoResponse{
		BinaryPath:    f.worker.binaryPath,
		OpenedAt:      time.Now().Add(-time.Minute).Unix(),
		LastActivity:  time.Now().Unix(),
		HasDecompiler: true,
	}), nil
}

type fakeAnalysisServer struct {
	workerconnect.UnimplementedAnalysisToolsHandler
	worker *fakeWorker
}

func (f *fakeAnalysisServer) GetFunctions(_ context.Context, _ *connect.Request[pb.GetFunctionsRequest]) (*connect.Response[pb.GetFunctionsResponse], error) {
	f.worker.mu.Lock()
	defer f.worker.mu.Unlock()

	functions := []*pb.Function{
		{Address: 0x1000, Name: fmt.Sprintf("%s_start", f.worker.sessionID)},
		{Address: 0x2000, Name: fmt.Sprintf("%s_helper", f.worker.sessionID)},
	}
	if f.worker.analyzed {
		functions = append(functions,
			&pb.Function{Address: 0x3000, Name: fmt.Sprintf("%s_alpha", f.worker.sessionID)},
			&pb.Function{Address: 0x4000, Name: fmt.Sprintf("%s_beta", f.worker.sessionID)},
		)
	}

	return connect.NewResponse(&pb.GetFunctionsResponse{
		Functions: functions,
	}), nil
}

func (f *fakeAnalysisServer) GetBytes(context.Context, *connect.Request[pb.GetBytesRequest]) (*connect.Response[pb.GetBytesResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}

func (f *fakeAnalysisServer) GetDisasm(context.Context, *connect.Request[pb.GetDisasmRequest]) (*connect.Response[pb.GetDisasmResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}

func (f *fakeAnalysisServer) GetFunctionDisasm(context.Context, *connect.Request[pb.GetFunctionDisasmRequest]) (*connect.Response[pb.GetFunctionDisasmResponse], error) {
	return connect.NewResponse(&pb.GetFunctionDisasmResponse{Disassembly: "deadbeef: mov x0, x0"}), nil
}

func (f *fakeAnalysisServer) GetDecompiled(context.Context, *connect.Request[pb.GetDecompiledRequest]) (*connect.Response[pb.GetDecompiledResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}

func (f *fakeAnalysisServer) SetName(context.Context, *connect.Request[pb.SetNameRequest]) (*connect.Response[pb.SetNameResponse], error) {
	resp := &pb.SetNameResponse{Success: true}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) SetFunctionType(context.Context, *connect.Request[pb.SetFunctionTypeRequest]) (*connect.Response[pb.SetFunctionTypeResponse], error) {
	resp := &pb.SetFunctionTypeResponse{Success: true}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) SetLvarType(context.Context, *connect.Request[pb.SetLvarTypeRequest]) (*connect.Response[pb.SetLvarTypeResponse], error) {
	resp := &pb.SetLvarTypeResponse{Success: true}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) RenameLvar(context.Context, *connect.Request[pb.RenameLvarRequest]) (*connect.Response[pb.RenameLvarResponse], error) {
	resp := &pb.RenameLvarResponse{Success: true}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) SetDecompilerComment(context.Context, *connect.Request[pb.SetDecompilerCommentRequest]) (*connect.Response[pb.SetDecompilerCommentResponse], error) {
	resp := &pb.SetDecompilerCommentResponse{Success: true}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) GetFunctionName(_ context.Context, req *connect.Request[pb.GetFunctionNameRequest]) (*connect.Response[pb.GetFunctionNameResponse], error) {
	name := fmt.Sprintf("func_%x", req.Msg.GetAddress())
	return connect.NewResponse(&pb.GetFunctionNameResponse{Name: name}), nil
}

func (f *fakeAnalysisServer) GetSegments(context.Context, *connect.Request[pb.GetSegmentsRequest]) (*connect.Response[pb.GetSegmentsResponse], error) {
	segments := []*pb.Segment{
		{Start: 0x100000, End: 0x101000, Name: ".text", SegClass: "CODE", Permissions: 5, Bitness: 64},
		{Start: 0x101000, End: 0x102000, Name: ".data", SegClass: "DATA", Permissions: 6, Bitness: 64},
	}
	return connect.NewResponse(&pb.GetSegmentsResponse{Segments: segments}), nil
}

func (f *fakeAnalysisServer) GetXRefsTo(_ context.Context, req *connect.Request[pb.GetXRefsToRequest]) (*connect.Response[pb.GetXRefsToResponse], error) {
	resp := &pb.GetXRefsToResponse{
		Xrefs: []*pb.XRef{{From: 0x1000, To: req.Msg.GetAddress(), Type: 1}},
	}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) GetXRefsFrom(_ context.Context, req *connect.Request[pb.GetXRefsFromRequest]) (*connect.Response[pb.GetXRefsFromResponse], error) {
	resp := &pb.GetXRefsFromResponse{
		Xrefs: []*pb.XRef{{From: req.Msg.GetAddress(), To: 0x2000, Type: 2}},
	}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) GetDataRefs(context.Context, *connect.Request[pb.GetDataRefsRequest]) (*connect.Response[pb.GetDataRefsResponse], error) {
	resp := &pb.GetDataRefsResponse{
		Refs: []*pb.DataRef{{From: 0x3000, Type: 3}},
	}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) GetStringXRefs(context.Context, *connect.Request[pb.GetStringXRefsRequest]) (*connect.Response[pb.GetStringXRefsResponse], error) {
	resp := &pb.GetStringXRefsResponse{
		Refs: []*pb.StringXRef{{Address: 0x4000, FunctionAddress: 0x5000, FunctionName: "string_user"}},
	}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) ImportIl2Cpp(context.Context, *connect.Request[pb.ImportIl2CppRequest]) (*connect.Response[pb.ImportIl2CppResponse], error) {
	resp := &pb.ImportIl2CppResponse{
		Success:           true,
		DurationSeconds:   1.0,
		FunctionsDefined:  2,
		FunctionsNamed:    3,
		StringsNamed:      4,
		MetadataNamed:     5,
		MetadataMethods:   6,
		SignaturesApplied: 7,
	}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) GetGlobals(context.Context, *connect.Request[pb.GetGlobalsRequest]) (*connect.Response[pb.GetGlobalsResponse], error) {
	resp := &pb.GetGlobalsResponse{Globals: []*pb.GlobalVariable{
		{Address: 0x6000, Name: "gAlpha", Type: "int"},
		{Address: 0x6008, Name: "gBeta", Type: "char *"},
	}}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) SetGlobalType(context.Context, *connect.Request[pb.SetGlobalTypeRequest]) (*connect.Response[pb.SetGlobalTypeResponse], error) {
	resp := &pb.SetGlobalTypeResponse{Success: true}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) RenameGlobal(context.Context, *connect.Request[pb.RenameGlobalRequest]) (*connect.Response[pb.RenameGlobalResponse], error) {
	resp := &pb.RenameGlobalResponse{Success: true}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) DataReadString(context.Context, *connect.Request[pb.DataReadStringRequest]) (*connect.Response[pb.DataReadStringResponse], error) {
	resp := &pb.DataReadStringResponse{Value: "global_name"}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) DataReadByte(context.Context, *connect.Request[pb.DataReadByteRequest]) (*connect.Response[pb.DataReadByteResponse], error) {
	resp := &pb.DataReadByteResponse{Value: 42}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) FindBinary(context.Context, *connect.Request[pb.FindBinaryRequest]) (*connect.Response[pb.FindBinaryResponse], error) {
	resp := &pb.FindBinaryResponse{Addresses: []uint64{0xdeadbeef, 0xdeadbabe}}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) FindText(context.Context, *connect.Request[pb.FindTextRequest]) (*connect.Response[pb.FindTextResponse], error) {
	resp := &pb.FindTextResponse{Addresses: []uint64{0xfeedface}}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) ListStructs(context.Context, *connect.Request[pb.ListStructsRequest]) (*connect.Response[pb.ListStructsResponse], error) {
	resp := &pb.ListStructsResponse{Structs: []*pb.StructSummary{
		{Name: "Vector3", Id: 1, Size: 12},
		{Name: "InventoryItem", Id: 2, Size: 48},
	}}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) GetStruct(_ context.Context, req *connect.Request[pb.GetStructRequest]) (*connect.Response[pb.GetStructResponse], error) {
	name := req.Msg.GetName()
	if name == "" {
		name = "Unnamed"
	}
	resp := &pb.GetStructResponse{
		Name: name,
		Id:   0x1234,
		Size: 48,
		Members: []*pb.StructMember{
			{Name: "x", Offset: 0, Size: 8, Type: "double"},
			{Name: "y", Offset: 8, Size: 8, Type: "double"},
			{Name: "z", Offset: 16, Size: 8, Type: "double"},
		},
	}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) GetImports(context.Context, *connect.Request[pb.GetImportsRequest]) (*connect.Response[pb.GetImportsResponse], error) {
	imports := []*pb.Import{
		{Module: "libalpha", Address: 0x4010, Name: "AlphaInit", Ordinal: 1},
		{Module: "libbeta", Address: 0x4020, Name: "BetaLoop", Ordinal: 2},
		{Module: "libalpha", Address: 0x4030, Name: "AlphaHelper", Ordinal: 3},
	}
	return connect.NewResponse(&pb.GetImportsResponse{Imports: imports}), nil
}

func (f *fakeAnalysisServer) GetExports(context.Context, *connect.Request[pb.GetExportsRequest]) (*connect.Response[pb.GetExportsResponse], error) {
	exports := []*pb.Export{
		{Index: 1, Ordinal: 10, Address: 0x5000, Name: "ExportAlpha"},
		{Index: 2, Ordinal: 11, Address: 0x6000, Name: "ExportBeta"},
	}
	return connect.NewResponse(&pb.GetExportsResponse{Exports: exports}), nil
}

func (f *fakeAnalysisServer) GetEntryPoint(context.Context, *connect.Request[pb.GetEntryPointRequest]) (*connect.Response[pb.GetEntryPointResponse], error) {
	return connect.NewResponse(&pb.GetEntryPointResponse{Address: 0x100000}), nil
}

func (f *fakeAnalysisServer) GetStrings(_ context.Context, req *connect.Request[pb.GetStringsRequest]) (*connect.Response[pb.GetStringsResponse], error) {
	data := []*pb.StringItem{
		{Address: 0x100, Value: "alpha_http"},
		{Address: 0x200, Value: "beta"},
		{Address: 0x300, Value: "gamma"},
	}
	total := len(data)
	start := int(req.Msg.GetOffset())
	if start > total {
		start = total
	}
	limit := int(req.Msg.GetLimit())
	if limit <= 0 || start+limit > total {
		limit = total - start
	}
	if limit < 0 {
		limit = 0
	}
	selection := data[start : start+limit]
	resp := &pb.GetStringsResponse{
		Strings: selection,
		Total:   int32(total),
		Offset:  int32(start),
		Count:   int32(len(selection)),
	}
	return connect.NewResponse(resp), nil
}

func (f *fakeAnalysisServer) MakeFunction(_ context.Context, req *connect.Request[pb.MakeFunctionRequest]) (*connect.Response[pb.MakeFunctionResponse], error) {
	// Simulate successful function creation
	return connect.NewResponse(&pb.MakeFunctionResponse{Success: true}), nil
}

func (f *fakeAnalysisServer) GetDwordAt(context.Context, *connect.Request[pb.GetDwordAtRequest]) (*connect.Response[pb.GetDwordAtResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}

func (f *fakeAnalysisServer) GetQwordAt(context.Context, *connect.Request[pb.GetQwordAtRequest]) (*connect.Response[pb.GetQwordAtResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}

func (f *fakeAnalysisServer) GetInstructionLength(context.Context, *connect.Request[pb.GetInstructionLengthRequest]) (*connect.Response[pb.GetInstructionLengthResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}

func (f *fakeAnalysisServer) DeleteName(context.Context, *connect.Request[pb.DeleteNameRequest]) (*connect.Response[pb.DeleteNameResponse], error) {
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("not implemented"))
}

type fakeHealthServer struct{}

func (f *fakeHealthServer) Ping(context.Context, *connect.Request[pb.PingRequest]) (*connect.Response[pb.PingResponse], error) {
	return connect.NewResponse(&pb.PingResponse{Alive: true}), nil
}

func (f *fakeHealthServer) StatusStream(_ context.Context, _ *connect.Request[pb.StatusStreamRequest], stream *connect.ServerStream[pb.WorkerStatus]) error {
	return stream.Send(&pb.WorkerStatus{
		Timestamp:       time.Now().Unix(),
		MemoryBytes:     42,
		Dirty:           false,
		LastActivity:    time.Now().Unix(),
		PendingRequests: 0,
	})
}
