package server

// Parameter types for all MCP tool implementations

type OpenBinaryRequest struct {
	Path string `json:"path" mcp:"path to binary file"`
}

type CloseBinaryRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
}

type ListSessionsRequest struct{}

type SaveDatabaseRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
}

type GetSessionProgressRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
}

type RunAutoAnalysisRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
}

type WatchAutoAnalysisRequest struct {
	SessionID   string `json:"session_id" mcp:"session identifier"`
	IntervalMs  int    `json:"interval_ms,omitempty" mcp:"poll interval in milliseconds (default 1000)"`
	TimeoutSecs int    `json:"timeout_seconds,omitempty" mcp:"optional timeout in seconds"`
}

type GetBytesRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
	Address   uint64 `json:"address" mcp:"memory address"`
	Size      uint32 `json:"size" mcp:"number of bytes"`
}

type GetDisasmRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
	Address   uint64 `json:"address" mcp:"memory address"`
}

type GetFunctionDisasmRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
	Address   uint64 `json:"address" mcp:"function address"`
}

type GetDecompiledRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
	Address   uint64 `json:"address" mcp:"function address"`
}

type GetFunctionsRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
	Offset    int    `json:"offset,omitempty" mcp:"result offset"`
	Limit     int    `json:"limit,omitempty" mcp:"page size (default 1000)"`
	Regex     string `json:"regex,omitempty" mcp:"regular expression filter"`
	CaseSens  bool   `json:"case_sensitive,omitempty" mcp:"case sensitive regex"`
}

type GetImportsRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
	Offset    int    `json:"offset,omitempty" mcp:"result offset"`
	Limit     int    `json:"limit,omitempty" mcp:"page size (default 1000)"`
	Module    string `json:"module,omitempty" mcp:"module filter"`
	Regex     string `json:"regex,omitempty" mcp:"regular expression filter (name)"`
	CaseSens  bool   `json:"case_sensitive,omitempty" mcp:"case sensitive regex"`
}

type GetExportsRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
	Offset    int    `json:"offset,omitempty" mcp:"result offset"`
	Limit     int    `json:"limit,omitempty" mcp:"page size (default 1000)"`
	Regex     string `json:"regex,omitempty" mcp:"regular expression filter"`
	CaseSens  bool   `json:"case_sensitive,omitempty" mcp:"case sensitive regex"`
}

type GetStringsRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
	Offset    int    `json:"offset,omitempty" mcp:"result offset"`
	Limit     int    `json:"limit,omitempty" mcp:"page size (default 1000)"`
	Regex     string `json:"regex,omitempty" mcp:"regular expression filter"`
	CaseSens  bool   `json:"case_sensitive,omitempty" mcp:"case sensitive regex"`
}

type GetCommentRequest struct {
	SessionID  string `json:"session_id" mcp:"session identifier"`
	Address    uint64 `json:"address" mcp:"address"`
	Repeatable bool   `json:"repeatable,omitempty" mcp:"get repeatable comment (default false)"`
}

type GetFuncCommentRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
	Address   uint64 `json:"address" mcp:"function address"`
}

type GetNameRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
	Address   uint64 `json:"address" mcp:"address"`
}

type GetFunctionInfoRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
	Address   uint64 `json:"address" mcp:"function address"`
}

type GetDwordAtRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
	Address   uint64 `json:"address" mcp:"address to read from"`
}

type GetQwordAtRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
	Address   uint64 `json:"address" mcp:"address to read from"`
}

type GetInstructionLengthRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
	Address   uint64 `json:"address" mcp:"instruction address"`
}

type GetSegmentsRequest struct {
	SessionID string `json:"session_id" mcp:"session ID"`
}

type GetFunctionNameRequest struct {
	SessionID string `json:"session_id" mcp:"session ID"`
	Address   uint64 `json:"address" mcp:"address to query"`
}

type GetEntryPointRequest struct {
	SessionID string `json:"session_id" mcp:"session ID"`
}

type SetCommentRequest struct {
	SessionID  string `json:"session_id" mcp:"session identifier"`
	Address    uint64 `json:"address" mcp:"address"`
	Comment    string `json:"comment" mcp:"comment text"`
	Repeatable bool   `json:"repeatable,omitempty" mcp:"repeatable comment (default false)"`
}

type SetFuncCommentRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
	Address   uint64 `json:"address" mcp:"function address"`
	Comment   string `json:"comment" mcp:"function comment text"`
}

type SetDecompilerCommentRequest struct {
	SessionID       string `json:"session_id" mcp:"session identifier"`
	FunctionAddress uint64 `json:"function_address" mcp:"function address"`
	Address         uint64 `json:"address" mcp:"pseudocode address"`
	Comment         string `json:"comment" mcp:"comment text"`
}

type SetNameRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
	Address   uint64 `json:"address" mcp:"address"`
	Name      string `json:"name" mcp:"new name"`
}

type DeleteNameRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
	Address   uint64 `json:"address" mcp:"address"`
}

type SetLvarTypeRequest struct {
	SessionID       string `json:"session_id" mcp:"session identifier"`
	FunctionAddress uint64 `json:"function_address" mcp:"function address"`
	LvarName        string `json:"lvar_name" mcp:"local variable name"`
	LvarType        string `json:"lvar_type" mcp:"C-style type declaration"`
}

type RenameLvarRequest struct {
	SessionID       string `json:"session_id" mcp:"session identifier"`
	FunctionAddress uint64 `json:"function_address" mcp:"function address"`
	LvarName        string `json:"lvar_name" mcp:"current local variable name"`
	NewName         string `json:"new_name" mcp:"new local variable name"`
}

type SetGlobalTypeRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
	Address   uint64 `json:"address" mcp:"global address"`
	Type      string `json:"type" mcp:"C-style type declaration"`
}

type RenameGlobalRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
	Address   uint64 `json:"address" mcp:"global address"`
	NewName   string `json:"new_name" mcp:"new global name"`
}

type SetFunctionTypeRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
	Address   uint64 `json:"address" mcp:"function address"`
	Prototype string `json:"prototype" mcp:"C-style function prototype"`
}

type MakeFunctionRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
	Address   uint64 `json:"address" mcp:"function start address"`
}

type GetGlobalsRequest struct {
	SessionID     string `json:"session_id" mcp:"session identifier"`
	Regex         string `json:"regex,omitempty" mcp:"optional regex filter"`
	CaseSensitive bool   `json:"case_sensitive,omitempty" mcp:"case sensitive regex"`
}

type ListStructsRequest struct {
	SessionID     string `json:"session_id" mcp:"session identifier"`
	Regex         string `json:"regex,omitempty" mcp:"optional regex filter"`
	CaseSensitive bool   `json:"case_sensitive,omitempty" mcp:"case sensitive regex"`
}

type GetStructRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
	Name      string `json:"name" mcp:"structure name"`
}

type ListEnumsRequest struct {
	SessionID     string `json:"session_id" mcp:"session identifier"`
	Regex         string `json:"regex,omitempty" mcp:"optional regex filter"`
	CaseSensitive bool   `json:"case_sensitive,omitempty" mcp:"case sensitive regex"`
}

type GetEnumRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
	Name      string `json:"name" mcp:"enumeration name"`
}

type GetTypeAtRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
	Address   uint64 `json:"address" mcp:"address to query type"`
}

type DataReadStringRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
	Address   uint64 `json:"address" mcp:"memory address"`
	MaxLength int    `json:"max_length,omitempty" mcp:"optional max length (default 256)"`
}

type DataReadByteRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
	Address   uint64 `json:"address" mcp:"memory address"`
}

type FindBinaryRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
	Start     uint64 `json:"start" mcp:"start address (0 for image base)"`
	End       uint64 `json:"end" mcp:"end address (0 for BADADDR)"`
	Pattern   string `json:"pattern" mcp:"IDA-style binary pattern"`
	SearchUp  bool   `json:"search_up,omitempty" mcp:"search upward"`
}

type FindTextRequest struct {
	SessionID     string `json:"session_id" mcp:"session identifier"`
	Start         uint64 `json:"start" mcp:"start address (0 for image base)"`
	End           uint64 `json:"end" mcp:"end address (0 for BADADDR)"`
	Needle        string `json:"needle" mcp:"text to search"`
	CaseSensitive bool   `json:"case_sensitive,omitempty"`
	Unicode       bool   `json:"unicode,omitempty"`
}

type ImportIl2cppRequest struct {
	SessionID  string   `json:"session_id" mcp:"session identifier"`
	ScriptPath string   `json:"script_path" mcp:"path to Il2CppDumper script.json"`
	Il2cppPath string   `json:"il2cpp_path" mcp:"path to il2cpp.h"`
	Fields     []string `json:"fields,omitempty" mcp:"optional list of sections to import (default: all)"`
}

type ImportFlutterRequest struct {
	SessionID    string `json:"session_id" mcp:"session identifier"`
	MetaJsonPath string `json:"meta_json_path" mcp:"path to flutter_meta.json produced by unflutter"`
}

type XRefRequest struct{
	SessionID string `json:"session_id" mcp:"session identifier"`
	Address   uint64 `json:"address" mcp:"address"`
}

type DataRefRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
	Address   uint64 `json:"address" mcp:"address"`
}

type StringXRefRequest struct {
	SessionID string `json:"session_id" mcp:"session identifier"`
	Address   uint64 `json:"address" mcp:"string address"`
}
