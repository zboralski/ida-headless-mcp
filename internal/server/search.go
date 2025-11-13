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






func (s *Server) dataReadString(ctx context.Context, req *mcp.CallToolRequest, args DataReadStringRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("data_read_string", args.SessionID, map[string]any{"address": args.Address, "max_length": args.MaxLength})
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Session not found: %s", args.SessionID)}}}, nil, nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("data_read_string worker client", err), nil
	}
	maxLen := args.MaxLength
	if maxLen <= 0 {
		maxLen = 256
	}
	resp, err := (*client.Analysis).DataReadString(ctx, connect.NewRequest(&pb.DataReadStringRequest{Address: args.Address, MaxLength: uint32(maxLen)}))
	if err != nil {
		return nil, s.logAndSanitizeError("data_read_string RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("data_read_string IDA operation", errors.New(msgErr)), nil
	}
	result, _ := s.marshalJSON(map[string]any{"value": resp.Msg.GetValue()})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}

func (s *Server) dataReadByte(ctx context.Context, req *mcp.CallToolRequest, args DataReadByteRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("data_read_byte", args.SessionID, map[string]any{"address": args.Address})
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Session not found: %s", args.SessionID)}}}, nil, nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("data_read_byte worker client", err), nil
	}
	resp, err := (*client.Analysis).DataReadByte(ctx, connect.NewRequest(&pb.DataReadByteRequest{Address: args.Address}))
	if err != nil {
		return nil, s.logAndSanitizeError("data_read_byte RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("data_read_byte IDA operation", errors.New(msgErr)), nil
	}
	result, _ := s.marshalJSON(map[string]any{"value": resp.Msg.GetValue()})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}

func (s *Server) findBinary(ctx context.Context, req *mcp.CallToolRequest, args FindBinaryRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("find_binary", args.SessionID, map[string]any{"pattern": args.Pattern})
	if strings.TrimSpace(args.Pattern) == "" {
		return nil, errors.New("pattern is required"), nil
	}
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Session not found: %s", args.SessionID)}}}, nil, nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("find_binary worker client", err), nil
	}
	resp, err := (*client.Analysis).FindBinary(ctx, connect.NewRequest(&pb.FindBinaryRequest{
		Start:    args.Start,
		End:      args.End,
		Pattern:  args.Pattern,
		SearchUp: args.SearchUp,
	}))
	if err != nil {
		return nil, s.logAndSanitizeError("find_binary RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("find_binary IDA operation", errors.New(msgErr)), nil
	}
	result, _ := s.marshalJSON(map[string]any{"addresses": resp.Msg.GetAddresses()})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}

func (s *Server) findText(ctx context.Context, req *mcp.CallToolRequest, args FindTextRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("find_text", args.SessionID, map[string]any{"needle": args.Needle})
	if strings.TrimSpace(args.Needle) == "" {
		return nil, errors.New("needle is required"), nil
	}
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Session not found: %s", args.SessionID)}}}, nil, nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("find_text worker client", err), nil
	}
	resp, err := (*client.Analysis).FindText(ctx, connect.NewRequest(&pb.FindTextRequest{
		Start:         args.Start,
		End:           args.End,
		Needle:        args.Needle,
		CaseSensitive: args.CaseSensitive,
		Unicode:       args.Unicode,
	}))
	if err != nil {
		return nil, s.logAndSanitizeError("find_text RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("find_text IDA operation", errors.New(msgErr)), nil
	}
	result, _ := s.marshalJSON(map[string]any{"addresses": resp.Msg.GetAddresses()})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}
