package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	pb "github.com/zboralski/ida-headless-mcp/ida/worker/v1"
	"github.com/zboralski/ida-headless-mcp/internal/session"
	"github.com/zboralski/ida-headless-mcp/internal/worker"
)

const (
	DefaultPort              = 17300
	defaultSessionTimeoutMin = 240 // 4 hours - long enough for extended RE work
	defaultAutoSaveMin       = 5
	defaultMaxSessions       = 10
	defaultWorkerPath        = "python/worker/server.py"
	defaultPageLimit         = 1000
	maxPageLimit             = 10000
)

type Config struct {
	Port                 int    `json:"port"`
	SessionTimeoutMin    int    `json:"session_timeout_minutes"`
	AutoSaveIntervalMin  int    `json:"auto_save_interval_minutes"`
	MaxConcurrentSession int    `json:"max_concurrent_sessions"`
	DatabaseDirectory    string `json:"database_directory"`
	PythonWorkerPath     string `json:"python_worker_path"`
	Debug                bool   `json:"debug"`
}

type Server struct {
	registry                              *session.Registry
	workers                               worker.Controller
	logger                                *log.Logger
	sessionTimeout                        time.Duration
	debug                                 bool
	store                                 *session.Store
	cacheMu                               sync.Mutex
	cache                                 map[string]*sessionCache
	progressMu                            sync.Mutex
	progress                              map[string]*sessionProgress
	webSocketManagerForActiveConnections  *WebSocketConnectionManager
}

func New(registry *session.Registry, workers worker.Controller, logger *log.Logger, sessionTimeout time.Duration, debug bool, store *session.Store) *Server {
	return &Server{
		registry:                              registry,
		workers:                               workers,
		logger:                                logger,
		sessionTimeout:                        sessionTimeout,
		debug:                                 debug,
		store:                                 store,
		cache:                                 make(map[string]*sessionCache),
		progress:                              make(map[string]*sessionProgress),
		webSocketManagerForActiveConnections:  nil,
	}
}

func GetDefaultDBDir() string {
	if xdgData := os.Getenv("XDG_DATA_HOME"); xdgData != "" {
		return filepath.Join(xdgData, "ida-mcp", "sessions")
	}
	if home := os.Getenv("HOME"); home != "" {
		return filepath.Join(home, ".local", "share", "ida-mcp", "sessions")
	}
	return "/tmp/ida_sessions"
}

func LoadConfig(path string) (Config, error) {
	cfg := Config{
		Port:                 DefaultPort,
		SessionTimeoutMin:    defaultSessionTimeoutMin,
		AutoSaveIntervalMin:  defaultAutoSaveMin,
		MaxConcurrentSession: defaultMaxSessions,
		DatabaseDirectory:    GetDefaultDBDir(),
		PythonWorkerPath:     defaultWorkerPath,
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, err
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	ensureConfigDefaults(&cfg)
	return cfg, nil
}

func ensureConfigDefaults(cfg *Config) {
	if cfg.Port == 0 {
		cfg.Port = DefaultPort
	}
	if cfg.SessionTimeoutMin == 0 {
		cfg.SessionTimeoutMin = defaultSessionTimeoutMin
	}
	if cfg.AutoSaveIntervalMin == 0 {
		cfg.AutoSaveIntervalMin = defaultAutoSaveMin
	}
	if cfg.MaxConcurrentSession == 0 {
		cfg.MaxConcurrentSession = defaultMaxSessions
	}
	if cfg.PythonWorkerPath == "" {
		cfg.PythonWorkerPath = defaultWorkerPath
	}
	if cfg.DatabaseDirectory == "" {
		cfg.DatabaseDirectory = GetDefaultDBDir()
	}
}

func ApplyEnvOverrides(cfg *Config) {
	if val := os.Getenv("IDA_MCP_PORT"); val != "" {
		if p, err := strconv.Atoi(val); err == nil {
			cfg.Port = p
		}
	}
	if val := os.Getenv("IDA_MCP_SESSION_TIMEOUT_MIN"); val != "" {
		if mins, err := strconv.Atoi(val); err == nil {
			cfg.SessionTimeoutMin = mins
		}
	}
	if val := os.Getenv("IDA_MCP_MAX_SESSIONS"); val != "" {
		if n, err := strconv.Atoi(val); err == nil {
			cfg.MaxConcurrentSession = n
		}
	}
	if val := os.Getenv("IDA_MCP_WORKER"); val != "" {
		cfg.PythonWorkerPath = val
	}
	if val := os.Getenv("IDA_MCP_DEBUG"); val != "" {
		if parsed, ok := parseBool(val); ok {
			cfg.Debug = parsed
		}
	}
}

func (s *Server) RegisterTools(mcpServer *mcp.Server) {
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "open_binary",
		Description: "Open binary file for analysis",
	}, s.openBinary)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "close_binary",
		Description: "Close analysis session",
	}, s.closeBinary)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "list_sessions",
		Description: "List active analysis sessions",
	}, s.listSessions)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "save_database",
		Description: "Save IDA database",
	}, s.saveDatabase)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_bytes",
		Description: "Read bytes at address",
	}, s.getBytes)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_disasm",
		Description: "Get disassembly at address",
	}, s.getDisasm)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_function_disasm",
		Description: "Get full disassembly for a function",
	}, s.getFunctionDisasm)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_decompiled_func",
		Description: "Get decompiled pseudocode",
	}, s.getDecompiled)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_functions",
		Description: "List all functions",
	}, s.getFunctions)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_imports",
		Description: "Get import table",
	}, s.getImports)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_exports",
		Description: "Get export table",
	}, s.getExports)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_strings",
		Description: "Get all strings",
	}, s.getStrings)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_xrefs_to",
		Description: "List cross references to an address",
	}, s.getXRefsTo)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_xrefs_from",
		Description: "List cross references originating from an address",
	}, s.getXRefsFrom)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_data_refs",
		Description: "List data references to an address",
	}, s.getDataRefs)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_string_xrefs",
		Description: "List functions referencing a string address",
	}, s.getStringXRefs)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_session_progress",
		Description: "Fetch latest server-side progress snapshot for a session",
	}, s.getSessionProgress)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "run_auto_analysis",
		Description: "Force IDA auto-analysis to finish (plan_and_wait)",
	}, s.runAutoAnalysis)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "watch_auto_analysis",
		Description: "Stream IDA auto-analysis state until completion",
	}, s.watchAutoAnalysis)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "set_comment",
		Description: "Set comment at address",
	}, s.setComment)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_comment",
		Description: "Get comment at address",
	}, s.getComment)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "set_func_comment",
		Description: "Set function comment",
	}, s.setFuncComment)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "set_decompiler_comment",
		Description: "Attach a Hex-Rays pseudocode comment",
	}, s.setDecompilerComment)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_func_comment",
		Description: "Get function comment",
	}, s.getFuncComment)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "set_lvar_type",
		Description: "Apply a Hex-Rays local variable type",
	}, s.setLvarType)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "rename_lvar",
		Description: "Rename a Hex-Rays local variable",
	}, s.renameLvar)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_globals",
		Description: "List global variables",
	}, s.getGlobals)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "set_global_type",
		Description: "Apply a type to a global variable",
	}, s.setGlobalType)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "rename_global",
		Description: "Rename a global variable",
	}, s.renameGlobal)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "data_read_string",
		Description: "Read an ASCII string from memory",
	}, s.dataReadString)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "data_read_byte",
		Description: "Read a byte from memory",
	}, s.dataReadByte)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "find_binary",
		Description: "Search for a binary pattern",
	}, s.findBinary)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "find_text",
		Description: "Search for ASCII/UTF-8 text",
	}, s.findText)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "list_structs",
		Description: "Enumerate structure definitions",
	}, s.listStructs)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_struct",
		Description: "Fetch metadata for a structure",
	}, s.getStruct)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "list_enums",
		Description: "Enumerate enumeration definitions",
	}, s.listEnums)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_enum",
		Description: "Fetch metadata for an enumeration",
	}, s.getEnum)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_function_info",
		Description: "Get comprehensive function metadata including bounds, flags, and calling convention",
	}, s.getFunctionInfo)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_type_at",
		Description: "Get type information at address",
	}, s.getTypeAt)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "set_name",
		Description: "Set name at address",
	}, s.setName)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "set_function_type",
		Description: "Apply a function prototype at an address",
	}, s.setFunctionType)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_name",
		Description: "Get name at address",
	}, s.getName)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "delete_name",
		Description: "Delete name at address",
	}, s.deleteName)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "import_il2cpp",
		Description: "Import Il2CppDumper metadata into the current session",
	}, s.importIl2cpp)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "import_flutter",
		Description: "Import Blutter/Dart metadata into the current session",
	}, s.importFlutter)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_segments",
		Description: "Get all memory segments with permissions and metadata",
	}, s.getSegments)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_function_name",
		Description: "Get function name at address",
	}, s.getFunctionName)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_entry_point",
		Description: "Get binary entry point address",
	}, s.getEntryPoint)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_dword_at",
		Description: "Read 32-bit value at address",
	}, s.getDwordAt)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_qword_at",
		Description: "Read 64-bit value at address",
	}, s.getQwordAt)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "get_instruction_length",
		Description: "Get instruction size at address",
	}, s.getInstructionLength)

	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "make_function",
		Description: "Create function at address",
	}, s.makeFunction)
}

func normalizePagination(offset, limit int) (int, int, error) {
	if offset < 0 {
		return 0, 0, fmt.Errorf("offset must be >= 0")
	}
	if limit <= 0 {
		limit = defaultPageLimit
	}
	if limit > maxPageLimit {
		return 0, 0, fmt.Errorf("limit must be <= %d", maxPageLimit)
	}
	return offset, limit, nil
}

func compileRegex(expr string, caseSensitive bool) (*regexp.Regexp, error) {
	if expr == "" {
		return nil, nil
	}
	if caseSensitive {
		return regexp.Compile(expr)
	}
	return regexp.Compile("(?i)" + expr)
}

func mapStringItems(items []*pb.StringItem) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(items))
	for _, item := range items {
		result = append(result, map[string]interface{}{
			"address": item.Address,
			"value":   item.Value,
		})
	}
	return result
}

func mapFunctionItems(items []*pb.Function) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(items))
	for _, fn := range items {
		result = append(result, map[string]interface{}{
			"address": fn.Address,
			"name":    fn.Name,
		})
	}
	return result
}

func mapImportItems(items []*pb.Import) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(items))
	for _, imp := range items {
		result = append(result, map[string]interface{}{
			"module":  imp.Module,
			"address": imp.Address,
			"name":    imp.Name,
			"ordinal": imp.Ordinal,
		})
	}
	return result
}

func mapExportItems(items []*pb.Export) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(items))
	for _, exp := range items {
		result = append(result, map[string]interface{}{
			"index":   exp.Index,
			"ordinal": exp.Ordinal,
			"address": exp.Address,
			"name":    exp.Name,
		})
	}
	return result
}

func matchModule(module, filter string, caseSensitive bool) bool {
	if filter == "" {
		return true
	}
	if caseSensitive {
		return strings.Contains(module, filter)
	}
	return strings.Contains(strings.ToLower(module), strings.ToLower(filter))
}

func parseBool(val string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "1", "true", "t", "yes", "y", "on":
		return true, true
	case "0", "false", "f", "no", "n", "off":
		return false, true
	default:
		return false, false
	}
}
