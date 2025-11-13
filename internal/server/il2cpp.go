package server

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	pb "github.com/zboralski/ida-headless-mcp/ida/worker/v1"
)



func (s *Server) importIl2cpp(ctx context.Context, req *mcp.CallToolRequest, args ImportIl2cppRequest) (*mcp.CallToolResult, any, error) {
	payloadInfo := map[string]any{
		"fields": len(args.Fields),
	}
	s.logToolInvocation("import_il2cpp", args.SessionID, payloadInfo)
	if args.ScriptPath == "" {
		return nil, errors.New("script_path is required"), nil
	}
	if args.Il2cppPath == "" {
		return nil, errors.New("il2cpp_path is required"), nil
	}

	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("import_il2cpp worker client", err), nil
	}
	resp, err := (*client.Analysis).ImportIl2Cpp(ctx, connect.NewRequest(&pb.ImportIl2CppRequest{
		ScriptPath: args.ScriptPath,
		Il2CppPath: args.Il2cppPath,
		Fields:     args.Fields,
	}))
	if err != nil {
		return nil, s.logAndSanitizeError("import_il2cpp RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" && !resp.Msg.GetSuccess() {
		return nil, s.logAndSanitizeError("import_il2cpp IDA operation", errors.New(msgErr)), nil
	}
	result := map[string]any{
		"success":            resp.Msg.GetSuccess(),
		"duration_seconds":   resp.Msg.GetDurationSeconds(),
		"functions_defined":  resp.Msg.GetFunctionsDefined(),
		"functions_named":    resp.Msg.GetFunctionsNamed(),
		"strings_named":      resp.Msg.GetStringsNamed(),
		"metadata_named":     resp.Msg.GetMetadataNamed(),
		"metadata_methods":   resp.Msg.GetMetadataMethods(),
		"signatures_applied": resp.Msg.GetSignaturesApplied(),
		"analysis_tip":       "Run run_auto_analysis after import to refresh cross references and caches.",
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		result["warning"] = msgErr
	}
	jsonResult, _ := s.marshalJSON(result)
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(jsonResult)},
		},
	}, nil, nil
}
