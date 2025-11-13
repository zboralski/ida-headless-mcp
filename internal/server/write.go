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












func (s *Server) setComment(ctx context.Context, req *mcp.CallToolRequest, args SetCommentRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("set_comment", args.SessionID, map[string]any{"address": args.Address, "repeatable": args.Repeatable})
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("set_comment worker client", err), nil
	}
	resp, err := (*client.Analysis).SetComment(ctx, connect.NewRequest(&pb.SetCommentRequest{
		Address:    args.Address,
		Comment:    args.Comment,
		Repeatable: args.Repeatable,
	}))
	if err != nil {
		return nil, s.logAndSanitizeError("set_comment RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("set_comment IDA operation", errors.New(msgErr)), nil
	}
	result, _ := s.marshalJSON(map[string]any{"success": resp.Msg.GetSuccess()})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}

func (s *Server) setFuncComment(ctx context.Context, req *mcp.CallToolRequest, args SetFuncCommentRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("set_func_comment", args.SessionID, map[string]any{"address": args.Address})
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("set_func_comment worker client", err), nil
	}
	resp, err := (*client.Analysis).SetFuncComment(ctx, connect.NewRequest(&pb.SetFuncCommentRequest{
		Address: args.Address,
		Comment: args.Comment,
	}))
	if err != nil {
		return nil, s.logAndSanitizeError("set_func_comment RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("set_func_comment IDA operation", errors.New(msgErr)), nil
	}
	result, _ := s.marshalJSON(map[string]any{"success": resp.Msg.GetSuccess()})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}

func (s *Server) setDecompilerComment(ctx context.Context, req *mcp.CallToolRequest, args SetDecompilerCommentRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("set_decompiler_comment", args.SessionID, map[string]any{"function_address": args.FunctionAddress, "address": args.Address})
	if strings.TrimSpace(args.Comment) == "" {
		return nil, errors.New("comment is required"), nil
	}
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("set_decompiler_comment worker client", err), nil
	}
	resp, err := (*client.Analysis).SetDecompilerComment(ctx, connect.NewRequest(&pb.SetDecompilerCommentRequest{
		FunctionAddress: args.FunctionAddress,
		Address:         args.Address,
		Comment:         args.Comment,
	}))
	if err != nil {
		return nil, s.logAndSanitizeError("set_decompiler_comment RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("set_decompiler_comment IDA operation", errors.New(msgErr)), nil
	}
	result, _ := s.marshalJSON(map[string]any{"success": resp.Msg.GetSuccess()})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}

func (s *Server) setName(ctx context.Context, req *mcp.CallToolRequest, args SetNameRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("set_name", args.SessionID, map[string]any{"address": args.Address, "name": args.Name})
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("set_name worker client", err), nil
	}
	resp, err := (*client.Analysis).SetName(ctx, connect.NewRequest(&pb.SetNameRequest{
		Address: args.Address,
		Name:    args.Name,
	}))
	if err != nil {
		return nil, s.logAndSanitizeError("set_name RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("set_name IDA operation", errors.New(msgErr)), nil
	}
	result, _ := s.marshalJSON(map[string]any{"success": resp.Msg.GetSuccess()})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}

func (s *Server) deleteName(ctx context.Context, req *mcp.CallToolRequest, args DeleteNameRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("delete_name", args.SessionID, map[string]any{"address": args.Address})
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("delete_name worker client", err), nil
	}
	resp, err := (*client.Analysis).DeleteName(ctx, connect.NewRequest(&pb.DeleteNameRequest{
		Address: args.Address,
	}))
	if err != nil {
		return nil, s.logAndSanitizeError("delete_name RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("delete_name IDA operation", errors.New(msgErr)), nil
	}
	result, _ := s.marshalJSON(map[string]any{"success": resp.Msg.GetSuccess()})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}

func (s *Server) setLvarType(ctx context.Context, req *mcp.CallToolRequest, args SetLvarTypeRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("set_lvar_type", args.SessionID, map[string]any{"function_address": args.FunctionAddress, "lvar": args.LvarName})
	if strings.TrimSpace(args.LvarType) == "" {
		return nil, errors.New("lvar_type is required"), nil
	}
	if args.FunctionAddress == 0 {
		return nil, errors.New("function_address is required"), nil
	}
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("set_lvar_type worker client", err), nil
	}
	resp, err := (*client.Analysis).SetLvarType(ctx, connect.NewRequest(&pb.SetLvarTypeRequest{
		FunctionAddress: args.FunctionAddress,
		LvarName:        args.LvarName,
		LvarType:        args.LvarType,
	}))
	if err != nil {
		return nil, s.logAndSanitizeError("set_lvar_type RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("set_lvar_type IDA operation", errors.New(msgErr)), nil
	}
	result, _ := s.marshalJSON(map[string]any{"success": resp.Msg.GetSuccess()})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}

func (s *Server) renameLvar(ctx context.Context, req *mcp.CallToolRequest, args RenameLvarRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("rename_lvar", args.SessionID, map[string]any{"function_address": args.FunctionAddress, "lvar": args.LvarName})
	if strings.TrimSpace(args.NewName) == "" {
		return nil, errors.New("new_name is required"), nil
	}
	if args.FunctionAddress == 0 {
		return nil, errors.New("function_address is required"), nil
	}
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("rename_lvar worker client", err), nil
	}
	resp, err := (*client.Analysis).RenameLvar(ctx, connect.NewRequest(&pb.RenameLvarRequest{
		FunctionAddress: args.FunctionAddress,
		LvarName:        args.LvarName,
		NewName:         args.NewName,
	}))
	if err != nil {
		return nil, s.logAndSanitizeError("rename_lvar RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("rename_lvar IDA operation", errors.New(msgErr)), nil
	}
	result, _ := s.marshalJSON(map[string]any{"success": resp.Msg.GetSuccess()})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}

func (s *Server) setGlobalType(ctx context.Context, req *mcp.CallToolRequest, args SetGlobalTypeRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("set_global_type", args.SessionID, map[string]any{"address": args.Address})
	if strings.TrimSpace(args.Type) == "" {
		return nil, errors.New("type is required"), nil
	}
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("set_global_type worker client", err), nil
	}
	resp, err := (*client.Analysis).SetGlobalType(ctx, connect.NewRequest(&pb.SetGlobalTypeRequest{Address: args.Address, Type: args.Type}))
	if err != nil {
		return nil, s.logAndSanitizeError("set_global_type RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("set_global_type IDA operation", errors.New(msgErr)), nil
	}
	result, _ := s.marshalJSON(map[string]any{"success": resp.Msg.GetSuccess()})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}

func (s *Server) renameGlobal(ctx context.Context, req *mcp.CallToolRequest, args RenameGlobalRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("rename_global", args.SessionID, map[string]any{"address": args.Address})
	if strings.TrimSpace(args.NewName) == "" {
		return nil, errors.New("new_name is required"), nil
	}
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("rename_global worker client", err), nil
	}
	resp, err := (*client.Analysis).RenameGlobal(ctx, connect.NewRequest(&pb.RenameGlobalRequest{Address: args.Address, NewName: args.NewName}))
	if err != nil {
		return nil, s.logAndSanitizeError("rename_global RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("rename_global IDA operation", errors.New(msgErr)), nil
	}
	result, _ := s.marshalJSON(map[string]any{"success": resp.Msg.GetSuccess()})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}

func (s *Server) setFunctionType(ctx context.Context, req *mcp.CallToolRequest, args SetFunctionTypeRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("set_function_type", args.SessionID, map[string]any{"address": args.Address})
	if strings.TrimSpace(args.Prototype) == "" {
		return nil, errors.New("prototype is required"), nil
	}
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("set_function_type worker client", err), nil
	}
	resp, err := (*client.Analysis).SetFunctionType(ctx, connect.NewRequest(&pb.SetFunctionTypeRequest{
		Address:   args.Address,
		Prototype: args.Prototype,
	}))
	if err != nil {
		return nil, s.logAndSanitizeError("set_function_type RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("set_function_type IDA operation", errors.New(msgErr)), nil
	}
	result, _ := s.marshalJSON(map[string]any{"success": resp.Msg.GetSuccess()})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}


func (s *Server) makeFunction(ctx context.Context, req *mcp.CallToolRequest, args MakeFunctionRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("make_function", args.SessionID, map[string]any{"address": args.Address})
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("make_function worker client", err), nil
	}
	resp, err := (*client.Analysis).MakeFunction(ctx, connect.NewRequest(&pb.MakeFunctionRequest{
		Address: args.Address,
	}))
	if err != nil {
		return nil, s.logAndSanitizeError("make_function RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("make_function IDA operation", errors.New(msgErr)), nil
	}

	if resp.Msg.GetSuccess() {
		s.deleteSessionCache(sess.ID)
	}
	result, _ := s.marshalJSON(map[string]any{"success": resp.Msg.GetSuccess()})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}
