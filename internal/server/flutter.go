package server

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	pb "github.com/zboralski/ida-headless-mcp/ida/worker/v1"
)

func (s *Server) importFlutter(ctx context.Context, req *mcp.CallToolRequest, args ImportFlutterRequest) (*mcp.CallToolResult, any, error) {
	payloadInfo := map[string]any{
		"meta_json_path": args.MetaJsonPath,
	}
	s.logToolInvocation("import_flutter", args.SessionID, payloadInfo)
	if args.MetaJsonPath == "" {
		return nil, errors.New("meta_json_path is required"), nil
	}

	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("import_flutter worker client", err), nil
	}
	resp, err := (*client.Analysis).ImportFlutter(ctx, connect.NewRequest(&pb.ImportFlutterRequest{
		MetaJsonPath: args.MetaJsonPath,
	}))
	if err != nil {
		return nil, s.logAndSanitizeError("import_flutter RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" && !resp.Msg.GetSuccess() {
		return nil, s.logAndSanitizeError("import_flutter IDA operation", errors.New(msgErr)), nil
	}
	result := map[string]any{
		"success":            resp.Msg.GetSuccess(),
		"duration_seconds":   resp.Msg.GetDurationSeconds(),
		"functions_created":  resp.Msg.GetFunctionsCreated(),
		"functions_named":    resp.Msg.GetFunctionsNamed(),
		"structs_created":    resp.Msg.GetStructsCreated(),
		"signatures_applied": resp.Msg.GetSignaturesApplied(),
		"comments_set":       resp.Msg.GetCommentsSet(),
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
