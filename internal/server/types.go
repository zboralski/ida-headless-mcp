package server

import (
	"context"

	"errors"
	"fmt"
	"strings"


	"connectrpc.com/connect"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	pb "github.com/zboralski/ida-headless-mcp/ida/worker/v1"
)








func (s *Server) getGlobals(ctx context.Context, req *mcp.CallToolRequest, args GetGlobalsRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_globals", args.SessionID, map[string]any{"regex": args.Regex})
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Session not found: %s", args.SessionID)}}}, nil, nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("get_globals worker client", err), nil
	}
	resp, err := (*client.Analysis).GetGlobals(ctx, connect.NewRequest(&pb.GetGlobalsRequest{Regex: args.Regex, CaseSensitive: args.CaseSensitive}))
	if err != nil {
		return nil, s.logAndSanitizeError("get_globals RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("get_globals IDA operation", errors.New(msgErr)), nil
	}
	items := make([]map[string]any, 0, len(resp.Msg.GetGlobals()))
	for _, g := range resp.Msg.GetGlobals() {
		items = append(items, map[string]any{
			"address": g.GetAddress(),
			"name":    g.GetName(),
			"type":    g.GetType(),
		})
	}
	result, _ := s.marshalJSON(map[string]any{
		"count":   len(items),
		"globals": items,
	})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}

func (s *Server) listStructs(ctx context.Context, req *mcp.CallToolRequest, args ListStructsRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("list_structs", args.SessionID, map[string]any{"regex": args.Regex})
	if strings.TrimSpace(args.SessionID) == "" {
		return nil, errors.New("session_id is required"), nil
	}
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Session not found: %s", args.SessionID)}}}, nil, nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("list_structs worker client", err), nil
	}
	resp, err := (*client.Analysis).ListStructs(ctx, connect.NewRequest(&pb.ListStructsRequest{
		Regex:         args.Regex,
		CaseSensitive: args.CaseSensitive,
	}))
	if err != nil {
		return nil, s.logAndSanitizeError("list_structs RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("list_structs IDA operation", errors.New(msgErr)), nil
	}
	items := make([]map[string]any, 0, len(resp.Msg.GetStructs()))
	for _, st := range resp.Msg.GetStructs() {
		items = append(items, map[string]any{
			"name": st.GetName(),
			"id":   st.GetId(),
			"size": st.GetSize(),
		})
	}
	body, _ := s.marshalJSON(map[string]any{
		"count":   len(items),
		"structs": items,
	})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}, nil, nil
}

func (s *Server) getStruct(ctx context.Context, req *mcp.CallToolRequest, args GetStructRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_struct", args.SessionID, map[string]any{"name": args.Name})
	if strings.TrimSpace(args.Name) == "" {
		return nil, errors.New("name is required"), nil
	}
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Session not found: %s", args.SessionID)}}}, nil, nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("get_struct worker client", err), nil
	}
	resp, err := (*client.Analysis).GetStruct(ctx, connect.NewRequest(&pb.GetStructRequest{Name: args.Name}))
	if err != nil {
		return nil, s.logAndSanitizeError("get_struct RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("get_struct IDA operation", errors.New(msgErr)), nil
	}
	members := make([]map[string]any, 0, len(resp.Msg.GetMembers()))
	for _, m := range resp.Msg.GetMembers() {
		members = append(members, map[string]any{
			"name":   m.GetName(),
			"offset": m.GetOffset(),
			"size":   m.GetSize(),
			"type":   m.GetType(),
		})
	}
	body, _ := s.marshalJSON(map[string]any{
		"name":    resp.Msg.GetName(),
		"id":      resp.Msg.GetId(),
		"size":    resp.Msg.GetSize(),
		"members": members,
	})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}, nil, nil
}

func (s *Server) listEnums(ctx context.Context, req *mcp.CallToolRequest, args ListEnumsRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("list_enums", args.SessionID, map[string]any{"regex": args.Regex})
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Session not found: %s", args.SessionID)}}}, nil, nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("list_enums worker client", err), nil
	}
	resp, err := (*client.Analysis).ListEnums(ctx, connect.NewRequest(&pb.ListEnumsRequest{Regex: args.Regex, CaseSensitive: args.CaseSensitive}))
	if err != nil {
		return nil, s.logAndSanitizeError("list_enums RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("list_enums IDA operation", errors.New(msgErr)), nil
	}
	enums := make([]map[string]any, 0, len(resp.Msg.GetEnums()))
	for _, e := range resp.Msg.GetEnums() {
		enums = append(enums, map[string]any{
			"name": e.GetName(),
			"id":   e.GetId(),
		})
	}
	body, _ := s.marshalJSON(map[string]any{
		"count": len(enums),
		"enums": enums,
	})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}, nil, nil
}

func (s *Server) getEnum(ctx context.Context, req *mcp.CallToolRequest, args GetEnumRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_enum", args.SessionID, map[string]any{"name": args.Name})
	if strings.TrimSpace(args.Name) == "" {
		return nil, errors.New("name is required"), nil
	}
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Session not found: %s", args.SessionID)}}}, nil, nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("get_enum worker client", err), nil
	}
	resp, err := (*client.Analysis).GetEnum(ctx, connect.NewRequest(&pb.GetEnumRequest{Name: args.Name}))
	if err != nil {
		return nil, s.logAndSanitizeError("get_enum RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("get_enum IDA operation", errors.New(msgErr)), nil
	}
	members := make([]map[string]any, 0, len(resp.Msg.GetMembers()))
	for _, m := range resp.Msg.GetMembers() {
		members = append(members, map[string]any{
			"name":  m.GetName(),
			"value": m.GetValue(),
		})
	}
	body, _ := s.marshalJSON(map[string]any{
		"name":    resp.Msg.GetName(),
		"id":      resp.Msg.GetId(),
		"members": members,
	})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}, nil, nil
}

func (s *Server) getTypeAt(ctx context.Context, req *mcp.CallToolRequest, args GetTypeAtRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_type_at", args.SessionID, map[string]any{"address": args.Address})
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Session not found: %s", args.SessionID)}}}, nil, nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("get_type_at worker client", err), nil
	}
	resp, err := (*client.Analysis).GetTypeAt(ctx, connect.NewRequest(&pb.GetTypeAtRequest{Address: args.Address}))
	if err != nil {
		return nil, s.logAndSanitizeError("get_type_at RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("get_type_at IDA operation", errors.New(msgErr)), nil
	}
	body, _ := s.marshalJSON(map[string]any{
		"address":   resp.Msg.GetAddress(),
		"type":      resp.Msg.GetType(),
		"size":      resp.Msg.GetSize(),
		"is_ptr":    resp.Msg.GetIsPtr(),
		"is_func":   resp.Msg.GetIsFunc(),
		"is_array":  resp.Msg.GetIsArray(),
		"is_struct": resp.Msg.GetIsStruct(),
		"is_union":  resp.Msg.GetIsUnion(),
		"is_enum":   resp.Msg.GetIsEnum(),
		"has_type":  resp.Msg.GetHasType(),
	})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}, nil, nil
}
