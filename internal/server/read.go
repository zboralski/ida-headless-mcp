package server

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	pb "github.com/zboralski/ida-headless-mcp/ida/worker/v1"
)



func (s *Server) getBytes(ctx context.Context, req *mcp.CallToolRequest, args GetBytesRequest) (*mcp.CallToolResult, any, error) {
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: fmt.Sprintf("Session not found: %s", args.SessionID)},
			},
		}, nil, nil
	}

	sess.Touch()

	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("get_bytes worker client", err), nil
	}

	resp, err := (*client.Analysis).GetBytes(ctx, connect.NewRequest(&pb.GetBytesRequest{
		Address: args.Address,
		Size:    args.Size,
	}))
	if err != nil {
		return nil, s.logAndSanitizeError("get_bytes RPC call", err), nil
	}

	if resp.Msg.Error != "" {
		return nil, s.logAndSanitizeError("get_bytes IDA operation", errors.New(resp.Msg.Error)), nil
	}

	result, _ := s.marshalJSON(map[string]interface{}{
		"data": resp.Msg.Data,
	})

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(result)},
		},
	}, nil, nil
}



func (s *Server) getDisasm(ctx context.Context, req *mcp.CallToolRequest, args GetDisasmRequest) (*mcp.CallToolResult, any, error) {
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: fmt.Sprintf("Session not found: %s", args.SessionID)},
			},
		}, nil, nil
	}

	sess.Touch()

	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("get_disasm worker client", err), nil
	}

	resp, err := (*client.Analysis).GetDisasm(ctx, connect.NewRequest(&pb.GetDisasmRequest{
		Address: args.Address,
	}))
	if err != nil {
		return nil, s.logAndSanitizeError("get_disasm RPC call", err), nil
	}

	if resp.Msg.Error != "" {
		return nil, s.logAndSanitizeError("get_disasm IDA operation", errors.New(resp.Msg.Error)), nil
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: resp.Msg.Disasm},
		},
	}, nil, nil
}

func (s *Server) getFunctionDisasm(ctx context.Context, req *mcp.CallToolRequest, args GetFunctionDisasmRequest) (*mcp.CallToolResult, any, error) {
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: fmt.Sprintf("Session not found: %s", args.SessionID)},
			},
		}, nil, nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("get_function_disasm worker client", err), nil
	}
	resp, err := (*client.Analysis).GetFunctionDisasm(ctx, connect.NewRequest(&pb.GetFunctionDisasmRequest{
		Address: args.Address,
	}))
	if err != nil {
		return nil, s.logAndSanitizeError("get_function_disasm RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("get_function_disasm IDA operation", errors.New(msgErr)), nil
	}
	payload, _ := s.marshalJSON(map[string]any{"disassembly": resp.Msg.GetDisassembly()})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(payload)}}}, nil, nil
}


func (s *Server) getDecompiled(ctx context.Context, req *mcp.CallToolRequest, args GetDecompiledRequest) (*mcp.CallToolResult, any, error) {
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: fmt.Sprintf("Session not found: %s", args.SessionID)},
			},
		}, nil, nil
	}

	sess.Touch()

	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("get_decompiled worker client", err), nil
	}

	resp, err := (*client.Analysis).GetDecompiled(ctx, connect.NewRequest(&pb.GetDecompiledRequest{
		Address: args.Address,
	}))
	if err != nil {
		return nil, s.logAndSanitizeError("get_decompiled RPC call", err), nil
	}

	if resp.Msg.Error != "" {
		return nil, s.logAndSanitizeError("get_decompiled IDA operation", errors.New(resp.Msg.Error)), nil
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: resp.Msg.Code},
		},
	}, nil, nil
}


func (s *Server) getFunctions(ctx context.Context, req *mcp.CallToolRequest, args GetFunctionsRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_functions", args.SessionID, map[string]interface{}{
		"offset": args.Offset,
		"limit":  args.Limit,
		"regex":  args.Regex,
	})
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: fmt.Sprintf("Session not found: %s", args.SessionID)},
			},
		}, nil, nil
	}

	sess.Touch()

	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("get_functions worker client", err), nil
	}

	progress := s.progressReporter(ctx, req, sess.ID, "get_functions")
	cache := s.getSessionCache(sess.ID)
	functionsData, hit, err := cache.loadFunctions(sess.ID, s.logger, func() ([]*pb.Function, error) {
		return s.fetchAllFunctions(ctx, client, progress)
	})
	if err != nil {
		return nil, s.logAndSanitizeError("get_functions cache load", err), nil
	}
	if hit {
		s.emitProgress(progress, sess.ID, "get_functions", "Functions served from cache", 1, 1)
	}

	filtered := functionsData
	if args.Regex != "" {
		regex, err := compileRegex(args.Regex, args.CaseSens)
		if err != nil {
			return nil, err, nil
		}
		tmp := make([]*pb.Function, 0, len(filtered))
		for _, fn := range filtered {
			if regex.MatchString(fn.Name) {
				tmp = append(tmp, fn)
			}
		}
		filtered = tmp
	}

	totalFunctions := len(filtered)
	offset, limit, err := normalizePagination(args.Offset, args.Limit)
	if err != nil {
		return nil, err, nil
	}
	if offset > totalFunctions {
		offset = totalFunctions
	}
	end := offset + limit
	if end > totalFunctions {
		end = totalFunctions
	}

	functions := mapFunctionItems(filtered[offset:end])

	result, _ := s.marshalJSON(map[string]interface{}{
		"functions": functions,
		"total":     totalFunctions,
		"offset":    offset,
		"count":     len(functions),
		"limit":     limit,
		"regex":     args.Regex,
	})

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(result)},
		},
	}, nil, nil
}



func (s *Server) getImports(ctx context.Context, req *mcp.CallToolRequest, args GetImportsRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_imports", args.SessionID, map[string]interface{}{
		"offset": args.Offset,
		"limit":  args.Limit,
		"module": args.Module,
		"regex":  args.Regex,
	})
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: fmt.Sprintf("Session not found: %s", args.SessionID)},
			},
		}, nil, nil
	}

	sess.Touch()

	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("get_imports worker client", err), nil
	}

	progress := s.progressReporter(ctx, req, sess.ID, "get_imports")
	cache := s.getSessionCache(sess.ID)
	importsData, hit, err := cache.loadImports(sess.ID, s.logger, func() ([]*pb.Import, error) {
		return s.fetchAllImports(ctx, client, progress)
	})
	if err != nil {
		return nil, s.logAndSanitizeError("get_imports cache load", err), nil
	}
	if hit {
		s.emitProgress(progress, sess.ID, "get_imports", "Imports served from cache", 1, 1)
	}

	filtered := importsData
	if args.Module != "" {
		tmp := make([]*pb.Import, 0, len(filtered))
		for _, imp := range filtered {
			if matchModule(imp.Module, args.Module, args.CaseSens) {
				tmp = append(tmp, imp)
			}
		}
		filtered = tmp
	}
	if args.Regex != "" {
		regex, err := compileRegex(args.Regex, args.CaseSens)
		if err != nil {
			return nil, err, nil
		}
		tmp := make([]*pb.Import, 0, len(filtered))
		for _, imp := range filtered {
			if regex.MatchString(imp.Name) {
				tmp = append(tmp, imp)
			}
		}
		filtered = tmp
	}

	totalImports := len(filtered)
	offset, limit, err := normalizePagination(args.Offset, args.Limit)
	if err != nil {
		return nil, err, nil
	}
	if offset > totalImports {
		offset = totalImports
	}
	end := offset + limit
	if end > totalImports {
		end = totalImports
	}

	imports := mapImportItems(filtered[offset:end])

	result, _ := s.marshalJSON(map[string]interface{}{
		"imports": imports,
		"total":   totalImports,
		"offset":  offset,
		"count":   len(imports),
		"limit":   limit,
		"module":  args.Module,
		"regex":   args.Regex,
	})

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(result)},
		},
	}, nil, nil
}

func (s *Server) getExports(ctx context.Context, req *mcp.CallToolRequest, args GetExportsRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_exports", args.SessionID, map[string]interface{}{
		"offset": args.Offset,
		"limit":  args.Limit,
		"regex":  args.Regex,
	})
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: fmt.Sprintf("Session not found: %s", args.SessionID)},
			},
		}, nil, nil
	}

	sess.Touch()

	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("get_exports worker client", err), nil
	}

	progress := s.progressReporter(ctx, req, sess.ID, "get_exports")
	cache := s.getSessionCache(sess.ID)
	exportsData, hit, err := cache.loadExports(sess.ID, s.logger, func() ([]*pb.Export, error) {
		return s.fetchAllExports(ctx, client, progress)
	})
	if err != nil {
		return nil, s.logAndSanitizeError("get_exports cache load", err), nil
	}
	if hit {
		s.emitProgress(progress, sess.ID, "get_exports", "Exports served from cache", 1, 1)
	}

	filtered := exportsData
	if args.Regex != "" {
		regex, err := compileRegex(args.Regex, args.CaseSens)
		if err != nil {
			return nil, err, nil
		}
		tmp := make([]*pb.Export, 0, len(filtered))
		for _, exp := range filtered {
			if regex.MatchString(exp.Name) {
				tmp = append(tmp, exp)
			}
		}
		filtered = tmp
	}

	totalExports := len(filtered)
	offset, limit, err := normalizePagination(args.Offset, args.Limit)
	if err != nil {
		return nil, err, nil
	}
	if offset > totalExports {
		offset = totalExports
	}
	end := offset + limit
	if end > totalExports {
		end = totalExports
	}

	exports := mapExportItems(filtered[offset:end])

	result, _ := s.marshalJSON(map[string]interface{}{
		"exports": exports,
		"total":   totalExports,
		"offset":  offset,
		"count":   len(exports),
		"limit":   limit,
		"regex":   args.Regex,
	})

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(result)},
		},
	}, nil, nil
}









func (s *Server) getStrings(ctx context.Context, req *mcp.CallToolRequest, args GetStringsRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_strings", args.SessionID, map[string]interface{}{
		"offset": args.Offset,
		"limit":  args.Limit,
		"regex":  args.Regex,
	})
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: fmt.Sprintf("Session not found: %s", args.SessionID)},
			},
		}, nil, nil
	}

	sess.Touch()

	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("get_strings worker client", err), nil
	}

	progress := s.progressReporter(ctx, req, sess.ID, "get_strings")
	cache := s.getSessionCache(sess.ID)
	stringsData, hit, err := cache.loadStrings(sess.ID, s.logger, func() ([]*pb.StringItem, error) {
		return s.fetchAllStrings(ctx, client, progress)
	})
	if err != nil {
		return nil, s.logAndSanitizeError("get_strings cache load", err), nil
	}
	if hit {
		s.emitProgress(progress, sess.ID, "get_strings", "Strings served from cache", 1, 1)
	}

	filtered := stringsData
	if args.Regex != "" {
		regex, err := compileRegex(args.Regex, args.CaseSens)
		if err != nil {
			return nil, err, nil
		}
		tmp := make([]*pb.StringItem, 0, len(filtered))
		for _, item := range filtered {
			if regex.MatchString(item.Value) {
				tmp = append(tmp, item)
			}
		}
		filtered = tmp
	}

	totalStrings := len(filtered)
	offset, limit, err := normalizePagination(args.Offset, args.Limit)
	if err != nil {
		return nil, err, nil
	}
	if offset > totalStrings {
		offset = totalStrings
	}
	end := offset + limit
	if end > totalStrings {
		end = totalStrings
	}
	selection := mapStringItems(filtered[offset:end])
	result, _ := s.marshalJSON(map[string]interface{}{
		"strings": selection,
		"total":   totalStrings,
		"offset":  offset,
		"count":   len(selection),
		"limit":   limit,
		"regex":   args.Regex,
	})

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(result)},
		},
	}, nil, nil
}

func (s *Server) getXRefsTo(ctx context.Context, req *mcp.CallToolRequest, args XRefRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_xrefs_to", args.SessionID, map[string]any{"address": args.Address})
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("get_xrefs_to worker client", err), nil
	}
	resp, err := (*client.Analysis).GetXRefsTo(ctx, connect.NewRequest(&pb.GetXRefsToRequest{Address: args.Address}))
	if err != nil {
		return nil, s.logAndSanitizeError("get_xrefs_to RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("get_xrefs_to IDA operation", errors.New(msgErr)), nil
	}
	entries := make([]map[string]any, 0, len(resp.Msg.GetXrefs()))
	for _, x := range resp.Msg.GetXrefs() {
		entries = append(entries, map[string]any{
			"from": x.GetFrom(),
			"to":   x.GetTo(),
			"type": x.GetType(),
		})
	}
	result, _ := s.marshalJSON(map[string]any{"xrefs": entries, "count": len(entries)})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}

func (s *Server) getXRefsFrom(ctx context.Context, req *mcp.CallToolRequest, args XRefRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_xrefs_from", args.SessionID, map[string]any{"address": args.Address})
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("get_xrefs_from worker client", err), nil
	}
	resp, err := (*client.Analysis).GetXRefsFrom(ctx, connect.NewRequest(&pb.GetXRefsFromRequest{Address: args.Address}))
	if err != nil {
		return nil, s.logAndSanitizeError("get_xrefs_from RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("get_xrefs_from IDA operation", errors.New(msgErr)), nil
	}
	entries := make([]map[string]any, 0, len(resp.Msg.GetXrefs()))
	for _, x := range resp.Msg.GetXrefs() {
		entries = append(entries, map[string]any{
			"from": x.GetFrom(),
			"to":   x.GetTo(),
			"type": x.GetType(),
		})
	}
	result, _ := s.marshalJSON(map[string]any{"xrefs": entries, "count": len(entries)})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}

func (s *Server) getDataRefs(ctx context.Context, req *mcp.CallToolRequest, args DataRefRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_data_refs", args.SessionID, map[string]any{"address": args.Address})
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("get_data_refs worker client", err), nil
	}
	resp, err := (*client.Analysis).GetDataRefs(ctx, connect.NewRequest(&pb.GetDataRefsRequest{Address: args.Address}))
	if err != nil {
		return nil, s.logAndSanitizeError("get_data_refs RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("get_data_refs IDA operation", errors.New(msgErr)), nil
	}
	entries := make([]map[string]any, 0, len(resp.Msg.GetRefs()))
	for _, ref := range resp.Msg.GetRefs() {
		entries = append(entries, map[string]any{
			"from": ref.GetFrom(),
			"type": ref.GetType(),
		})
	}
	result, _ := s.marshalJSON(map[string]any{"refs": entries, "count": len(entries)})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}

func (s *Server) getStringXRefs(ctx context.Context, req *mcp.CallToolRequest, args StringXRefRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_string_xrefs", args.SessionID, map[string]any{"address": args.Address})
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("get_string_xrefs worker client", err), nil
	}
	resp, err := (*client.Analysis).GetStringXRefs(ctx, connect.NewRequest(&pb.GetStringXRefsRequest{Address: args.Address}))
	if err != nil {
		return nil, s.logAndSanitizeError("get_string_xrefs RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("get_string_xrefs IDA operation", errors.New(msgErr)), nil
	}
	entries := make([]map[string]any, 0, len(resp.Msg.GetRefs()))
	for _, ref := range resp.Msg.GetRefs() {
		entries = append(entries, map[string]any{
			"address":          ref.GetAddress(),
			"function_address": ref.GetFunctionAddress(),
			"function_name":    ref.GetFunctionName(),
		})
	}
	result, _ := s.marshalJSON(map[string]any{"refs": entries, "count": len(entries)})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}

func (s *Server) getComment(ctx context.Context, req *mcp.CallToolRequest, args GetCommentRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_comment", args.SessionID, map[string]any{"address": args.Address, "repeatable": args.Repeatable})
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("get_comment worker client", err), nil
	}
	resp, err := (*client.Analysis).GetComment(ctx, connect.NewRequest(&pb.GetCommentRequest{
		Address:    args.Address,
		Repeatable: args.Repeatable,
	}))
	if err != nil {
		return nil, s.logAndSanitizeError("get_comment RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("get_comment IDA operation", errors.New(msgErr)), nil
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: resp.Msg.GetComment()}}}, nil, nil
}

func (s *Server) getFuncComment(ctx context.Context, req *mcp.CallToolRequest, args GetFuncCommentRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_func_comment", args.SessionID, map[string]any{"address": args.Address})
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("get_func_comment worker client", err), nil
	}
	resp, err := (*client.Analysis).GetFuncComment(ctx, connect.NewRequest(&pb.GetFuncCommentRequest{
		Address: args.Address,
	}))
	if err != nil {
		return nil, s.logAndSanitizeError("get_func_comment RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("get_func_comment IDA operation", errors.New(msgErr)), nil
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: resp.Msg.GetComment()}}}, nil, nil
}

func (s *Server) getName(ctx context.Context, req *mcp.CallToolRequest, args GetNameRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_name", args.SessionID, map[string]any{"address": args.Address})
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("get_name worker client", err), nil
	}
	resp, err := (*client.Analysis).GetName(ctx, connect.NewRequest(&pb.GetNameRequest{
		Address: args.Address,
	}))
	if err != nil {
		return nil, s.logAndSanitizeError("get_name RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("get_name IDA operation", errors.New(msgErr)), nil
	}
	result, _ := s.marshalJSON(map[string]any{"name": resp.Msg.GetName()})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}

func (s *Server) getFunctionInfo(ctx context.Context, req *mcp.CallToolRequest, args GetFunctionInfoRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_function_info", args.SessionID, map[string]any{"address": args.Address})
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Session not found: %s", args.SessionID)}}}, nil, nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("get_function_info worker client", err), nil
	}
	resp, err := (*client.Analysis).GetFunctionInfo(ctx, connect.NewRequest(&pb.GetFunctionInfoRequest{Address: args.Address}))
	if err != nil {
		return nil, s.logAndSanitizeError("get_function_info RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("get_function_info IDA operation", errors.New(msgErr)), nil
	}
	flags := resp.Msg.GetFlags()
	body, _ := s.marshalJSON(map[string]any{
		"address":    resp.Msg.GetAddress(),
		"name":       resp.Msg.GetName(),
		"start":      resp.Msg.GetStart(),
		"end":        resp.Msg.GetEnd(),
		"size":       resp.Msg.GetSize(),
		"frame_size": resp.Msg.GetFrameSize(),
		"flags": map[string]any{
			"is_library": flags.GetIsLibrary(),
			"is_thunk":   flags.GetIsThunk(),
			"no_return":  flags.GetNoReturn(),
			"has_farseg": flags.GetHasFarseg(),
			"is_static":  flags.GetIsStatic(),
		},
		"calling_convention": resp.Msg.GetCallingConvention(),
		"return_type":        resp.Msg.GetReturnType(),
		"num_args":           resp.Msg.GetNumArgs(),
	})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(body)}}}, nil, nil
}


func (s *Server) getSegments(ctx context.Context, req *mcp.CallToolRequest, args GetSegmentsRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_segments", args.SessionID, nil)
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("get_segments worker client", err), nil
	}
	resp, err := (*client.Analysis).GetSegments(ctx, connect.NewRequest(&pb.GetSegmentsRequest{}))
	if err != nil {
		return nil, s.logAndSanitizeError("get_segments RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("get_segments IDA operation", errors.New(msgErr)), nil
	}

	segments := make([]map[string]any, 0, len(resp.Msg.GetSegments()))
	for _, seg := range resp.Msg.GetSegments() {
		segments = append(segments, map[string]any{
			"start":       seg.GetStart(),
			"end":         seg.GetEnd(),
			"name":        seg.GetName(),
			"class":       seg.GetSegClass(),
			"permissions": seg.GetPermissions(),
			"bitness":     seg.GetBitness(),
		})
	}

	result, _ := s.marshalJSON(map[string]any{
		"segments": segments,
		"count":    len(segments),
	})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}


func (s *Server) getFunctionName(ctx context.Context, req *mcp.CallToolRequest, args GetFunctionNameRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_function_name", args.SessionID, map[string]any{"address": args.Address})
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("get_function_name worker client", err), nil
	}
	resp, err := (*client.Analysis).GetFunctionName(ctx, connect.NewRequest(&pb.GetFunctionNameRequest{
		Address: args.Address,
	}))
	if err != nil {
		return nil, s.logAndSanitizeError("get_function_name RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("get_function_name IDA operation", errors.New(msgErr)), nil
	}
	result, _ := s.marshalJSON(map[string]any{"name": resp.Msg.GetName()})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}


func (s *Server) getEntryPoint(ctx context.Context, req *mcp.CallToolRequest, args GetEntryPointRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_entry_point", args.SessionID, nil)
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("get_entry_point worker client", err), nil
	}
	resp, err := (*client.Analysis).GetEntryPoint(ctx, connect.NewRequest(&pb.GetEntryPointRequest{}))
	if err != nil {
		return nil, s.logAndSanitizeError("get_entry_point RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("get_entry_point IDA operation", errors.New(msgErr)), nil
	}
	result, _ := s.marshalJSON(map[string]any{"address": resp.Msg.GetAddress()})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}

func (s *Server) getDwordAt(ctx context.Context, req *mcp.CallToolRequest, args GetDwordAtRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_dword_at", args.SessionID, map[string]any{"address": args.Address})
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("get_dword_at worker client", err), nil
	}
	resp, err := (*client.Analysis).GetDwordAt(ctx, connect.NewRequest(&pb.GetDwordAtRequest{Address: args.Address}))
	if err != nil {
		return nil, s.logAndSanitizeError("get_dword_at RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("get_dword_at IDA operation", errors.New(msgErr)), nil
	}
	result, _ := s.marshalJSON(map[string]any{"value": resp.Msg.GetValue()})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}

func (s *Server) getQwordAt(ctx context.Context, req *mcp.CallToolRequest, args GetQwordAtRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_qword_at", args.SessionID, map[string]any{"address": args.Address})
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("get_qword_at worker client", err), nil
	}
	resp, err := (*client.Analysis).GetQwordAt(ctx, connect.NewRequest(&pb.GetQwordAtRequest{Address: args.Address}))
	if err != nil {
		return nil, s.logAndSanitizeError("get_qword_at RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("get_qword_at IDA operation", errors.New(msgErr)), nil
	}
	result, _ := s.marshalJSON(map[string]any{"value": resp.Msg.GetValue()})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}

func (s *Server) getInstructionLength(ctx context.Context, req *mcp.CallToolRequest, args GetInstructionLengthRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_instruction_length", args.SessionID, map[string]any{"address": args.Address})
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}
	sess.Touch()
	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("get_instruction_length worker client", err), nil
	}
	resp, err := (*client.Analysis).GetInstructionLength(ctx, connect.NewRequest(&pb.GetInstructionLengthRequest{Address: args.Address}))
	if err != nil {
		return nil, s.logAndSanitizeError("get_instruction_length RPC call", err), nil
	}
	if msgErr := resp.Msg.GetError(); msgErr != "" {
		return nil, s.logAndSanitizeError("get_instruction_length IDA operation", errors.New(msgErr)), nil
	}
	result, _ := s.marshalJSON(map[string]any{"length": resp.Msg.GetLength()})
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil, nil
}
