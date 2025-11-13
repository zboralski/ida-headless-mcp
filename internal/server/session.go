package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	pb "github.com/zboralski/ida-headless-mcp/ida/worker/v1"
	"github.com/zboralski/ida-headless-mcp/internal/session"
)

// Session lifecycle management functions

func (s *Server) RestoreSessions() {
	if s.store == nil {
		return
	}
	metas, err := s.store.Load()
	if err != nil {
		s.logger.Printf("Failed to load persisted sessions: %v", err)
		return
	}
	if len(metas) == 0 {
		return
	}

	s.logger.Printf("Restoring %d session(s) from disk", len(metas))
	for _, meta := range metas {
		sess, err := s.registry.Restore(meta)
		if err != nil {
			s.logger.Printf("Skipping session %s: %v", meta.ID, err)
			continue
		}
		if err := s.workers.Start(context.Background(), sess, meta.BinaryPath); err != nil {
			s.logger.Printf("Failed to restart worker for session %s: %v", sess.ID, err)
			s.registry.Delete(sess.ID)
			s.deleteSessionState(sess.ID)
			s.deleteSessionCache(sess.ID)
			continue
		}
		s.logger.Printf("Session %s restored for binary %s", sess.ID, meta.BinaryPath)
	}
}

func (s *Server) persistSession(sess *session.Session) {
	if s.store == nil {
		return
	}
	if err := s.store.Save(sess); err != nil {
		s.logger.Printf("Warning: failed to persist session %s: %v", sess.ID, err)
	}
}

func (s *Server) deleteSessionState(sessionID string) {
	if s.store == nil {
		return
	}
	if err := s.store.Delete(sessionID); err != nil {
		s.logger.Printf("Warning: failed to delete session %s: %v", sessionID, err)
	}
}

// Watchdog cleans up expired sessions
func (s *Server) Watchdog() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		expired := s.registry.Expired()
		for _, sess := range expired {
			s.debugf("[Watchdog] Session %s expired, cleaning up", sess.ID)
			s.workers.Stop(sess.ID)
			s.registry.Delete(sess.ID)
			s.deleteSessionState(sess.ID)
			s.deleteSessionCache(sess.ID)
			s.clearProgress(sess.ID)
		}
	}
}

// MCP tool implementations for session management

func (s *Server) openBinary(ctx context.Context, req *mcp.CallToolRequest, args OpenBinaryRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("open_binary", "", map[string]interface{}{"path": args.Path})
	if existing, ok := s.registry.FindByBinaryPath(args.Path); ok {
		s.recordProgress(existing.ID, "open_binary", "Session reused", 1, 1)
		result := map[string]interface{}{
			"session_id":     existing.ID,
			"binary_path":    existing.BinaryPath,
			"has_decompiler": true,
			"created_at":     existing.CreatedAt.Unix(),
			"reused":         true,
		}
		jsonResult, _ := s.marshalJSON(result)
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: string(jsonResult)},
			},
		}, nil, nil
	}

	sess, err := s.registry.Create(args.Path, s.sessionTimeout)
	if err != nil {
		return nil, s.logAndSanitizeError("open_binary session creation", err), nil
	}
	progress := s.progressReporter(ctx, req, sess.ID, "open_binary")
	const totalSteps = 5.0
	currentStep := 0.0
	s.emitProgress(progress, sess.ID, "open_binary", "Session created", currentStep, totalSteps)
	currentStep++
	s.emitProgress(progress, sess.ID, "open_binary", "Starting Python worker", currentStep, totalSteps)

	if err := s.workers.Start(ctx, sess, args.Path); err != nil {
		s.registry.Delete(sess.ID)
		s.deleteSessionCache(sess.ID)
		s.clearProgress(sess.ID)
		return nil, s.logAndSanitizeError("open_binary worker start", err), nil
	}
	currentStep++
	s.emitProgress(progress, sess.ID, "open_binary", "Connecting to worker", currentStep, totalSteps)

	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		s.workers.Stop(sess.ID)
		s.registry.Delete(sess.ID)
		s.deleteSessionCache(sess.ID)
		s.clearProgress(sess.ID)
		return nil, s.logAndSanitizeError("open_binary worker client", err), nil
	}
	currentStep++
	s.emitProgress(progress, sess.ID, "open_binary", "Opening binary in IDA", currentStep, totalSteps)

	resp, err := (*client.SessionCtrl).OpenBinary(ctx, connect.NewRequest(&pb.OpenBinaryRequest{
		BinaryPath:  args.Path,
		AutoAnalyze: false,
	}))
	if err != nil {
		s.workers.Stop(sess.ID)
		s.registry.Delete(sess.ID)
		s.deleteSessionCache(sess.ID)
		s.clearProgress(sess.ID)
		return nil, s.logAndSanitizeError("open_binary RPC call", err), nil
	}

	if !resp.Msg.Success {
		s.workers.Stop(sess.ID)
		s.registry.Delete(sess.ID)
		s.deleteSessionCache(sess.ID)
		s.clearProgress(sess.ID)
		return nil, s.logAndSanitizeError("open_binary IDA analysis", errors.New(resp.Msg.Error)), nil
	}

	var autoState string
	var autoRunning bool
	if infoResp, infoErr := (*client.SessionCtrl).GetSessionInfo(ctx, connect.NewRequest(&pb.GetSessionInfoRequest{})); infoErr == nil && infoResp.Msg != nil {
		autoState = infoResp.Msg.GetAutoState()
		autoRunning = infoResp.Msg.GetAutoRunning()
	}

	s.persistSession(sess)
	s.emitProgress(progress, sess.ID, "ready", "Session ready", totalSteps, totalSteps)

	result := map[string]interface{}{
		"session_id":     sess.ID,
		"binary_path":    args.Path,
		"has_decompiler": resp.Msg.HasDecompiler,
		"created_at":     sess.CreatedAt.Unix(),
		"auto_state":     autoState,
		"auto_running":   autoRunning,
	}
	if autoRunning {
		result["analysis_tip"] = "Auto-analysis is still running. Call run_auto_analysis to block until completion."
	} else {
		result["analysis_tip"] = "Auto-analysis is disabled. You can now import_il2cpp, set_name, set_function_type, or make other changes, then call run_auto_analysis to refresh the database."
	}

	jsonResult, _ := s.marshalJSON(result)
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(jsonResult)},
		},
	}, nil, nil
}

func (s *Server) closeBinary(ctx context.Context, req *mcp.CallToolRequest, args CloseBinaryRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("close_binary", args.SessionID, nil)
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}

	if err := s.workers.Stop(sess.ID); err != nil {
		return nil, s.logAndSanitizeError("close_binary worker stop", err), nil
	}

	s.registry.Delete(sess.ID)
	s.deleteSessionState(sess.ID)
	s.deleteSessionCache(sess.ID)
	s.clearProgress(sess.ID)

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: `{"success": true}`},
		},
	}, nil, nil
}

func (s *Server) listSessions(ctx context.Context, req *mcp.CallToolRequest, args ListSessionsRequest) (*mcp.CallToolResult, any, error) {
	sessions := s.registry.List()

	result := make([]map[string]interface{}, 0, len(sessions))
	for _, sess := range sessions {
		result = append(result, map[string]interface{}{
			"session_id":    sess.ID,
			"binary_path":   sess.BinaryPath,
			"created_at":    sess.CreatedAt.Unix(),
			"last_activity": sess.LastActivity.Unix(),
			"age_seconds":   time.Since(sess.CreatedAt).Seconds(),
			"idle_seconds":  time.Since(sess.LastActivity).Seconds(),
		})
	}

	jsonResult, _ := s.marshalJSON(map[string]interface{}{
		"sessions": result,
		"count":    len(result),
	})

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(jsonResult)},
		},
	}, nil, nil
}

func (s *Server) saveDatabase(ctx context.Context, req *mcp.CallToolRequest, args SaveDatabaseRequest) (*mcp.CallToolResult, any, error) {
	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}

	sess.Touch()

	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("save_database worker client", err), nil
	}

	resp, err := (*client.SessionCtrl).SaveDatabase(ctx, connect.NewRequest(&pb.SaveDatabaseRequest{}))
	if err != nil {
		return nil, s.logAndSanitizeError("save_database RPC call", err), nil
	}

	result, _ := s.marshalJSON(map[string]interface{}{
		"success":   resp.Msg.Success,
		"timestamp": resp.Msg.Timestamp,
		"dirty":     resp.Msg.Dirty,
	})

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(result)},
		},
	}, nil, nil
}

func (s *Server) getSessionProgress(ctx context.Context, req *mcp.CallToolRequest, args GetSessionProgressRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("get_session_progress", args.SessionID, nil)

	if args.SessionID == "" {
		return nil, fmt.Errorf("session_id is required"), nil
	}

	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}

	sess.Touch()

	progressSnapshot, hasProgress := s.getProgress(args.SessionID)
	stage := "idle"
	message := "No active operation"
	var progressValue, totalValue float64
	var updatedAt time.Time
	if hasProgress && progressSnapshot != nil {
		stage = progressSnapshot.Stage
		message = progressSnapshot.Message
		progressValue = progressSnapshot.Progress
		totalValue = progressSnapshot.Total
		updatedAt = progressSnapshot.UpdatedAt
	}

	var percent float64
	if totalValue > 0 {
		percent = (progressValue / totalValue) * 100.0
	}

	var autoState = "unknown"
	var autoRunning bool
	if client, err := s.workers.GetClient(sess.ID); err == nil {
		if infoResp, err := (*client.SessionCtrl).GetSessionInfo(ctx, connect.NewRequest(&pb.GetSessionInfoRequest{})); err == nil {
			autoState = infoResp.Msg.GetAutoState()
			autoRunning = infoResp.Msg.GetAutoRunning()
		}
	}

	var lastUpdatedUnix int64
	var lastUpdatedAgo float64 = -1
	if !updatedAt.IsZero() {
		lastUpdatedUnix = updatedAt.Unix()
		lastUpdatedAgo = time.Since(updatedAt).Seconds()
	}

	now := time.Now().UTC()

	result := map[string]interface{}{
		"session_id":        args.SessionID,
		"stage":             stage,
		"message":           message,
		"progress":          progressValue,
		"total":             totalValue,
		"percent":           percent,
		"has_progress":      hasProgress,
		"auto_state":        autoState,
		"auto_running":      autoRunning,
		"ready":             stage == "ready" && !autoRunning,
		"last_updated_at":   lastUpdatedUnix,
		"last_updated_ago":  lastUpdatedAgo,
		"server_timestamp":  now.Unix(),
		"server_time_iso":   now.Format(time.RFC3339),
		"analysis_required": autoRunning,
	}

	jsonResult, _ := s.marshalJSON(result)
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(jsonResult)},
		},
	}, nil, nil
}

func (s *Server) runAutoAnalysis(ctx context.Context, req *mcp.CallToolRequest, args RunAutoAnalysisRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("run_auto_analysis", args.SessionID, nil)

	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}

	sess.Touch()

	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("run_auto_analysis worker client", err), nil
	}

	progress := s.progressReporter(ctx, req, sess.ID, "auto_analysis")
	s.emitProgress(progress, sess.ID, "auto_analysis", "Running plan_and_wait", 0, 0)

	type planResult struct {
		resp *pb.PlanAndWaitResponse
		err  error
	}

	planCh := make(chan planResult, 1)
	go func() {
		resp, err := (*client.SessionCtrl).PlanAndWait(ctx, connect.NewRequest(&pb.PlanAndWaitRequest{}))
		if err != nil {
			planCh <- planResult{err: err}
			return
		}
		planCh <- planResult{resp: resp.Msg}
	}()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	start := time.Now()
	updates := make([]map[string]interface{}, 0, 32)
	var lastState string
	var lastRunning bool
	var planResp *pb.PlanAndWaitResponse

	fetchInfo := func() {
		infoResp, err := (*client.SessionCtrl).GetSessionInfo(ctx, connect.NewRequest(&pb.GetSessionInfoRequest{}))
		if err != nil || infoResp.Msg == nil {
			return
		}
		lastState = infoResp.Msg.GetAutoState()
		lastRunning = infoResp.Msg.GetAutoRunning()
		entry := map[string]interface{}{
			"timestamp":       time.Now().Unix(),
			"auto_state":      lastState,
			"auto_running":    lastRunning,
			"session_id":      sess.ID,
			"elapsed_seconds": time.Since(start).Seconds(),
		}
		updates = append(updates, entry)
		s.emitProgress(progress, sess.ID, "auto_analysis", fmt.Sprintf("auto_state=%s running=%t", lastState, lastRunning), 0, 0)
	}

loop:
	for {
		select {
		case <-ctx.Done():
			return nil, s.logAndSanitizeError("run_auto_analysis", ctx.Err()), nil
		case pr := <-planCh:
			if pr.err != nil {
				s.emitProgress(progress, sess.ID, "auto_analysis", fmt.Sprintf("plan_and_wait failed: %v", pr.err), 0, 0)
				return nil, s.logAndSanitizeError("run_auto_analysis plan_and_wait", pr.err), nil
			}
			planResp = pr.resp
			fetchInfo()
			break loop
		case <-ticker.C:
			fetchInfo()
		}
	}

	s.emitProgress(progress, sess.ID, "auto_analysis", "Auto-analysis complete", 1, 1)

	s.deleteSessionCache(sess.ID)

	resultPayload := map[string]interface{}{
		"session_id":       sess.ID,
		"duration_seconds": 0.0,
		"updates":          updates,
		"update_count":     len(updates),
		"success":          planResp != nil && planResp.GetSuccess(),
		"auto_state":       lastState,
		"auto_running":     lastRunning,
	}
	if planResp != nil {
		resultPayload["duration_seconds"] = planResp.GetDurationSeconds()
		if errMsg := planResp.GetError(); errMsg != "" {
			resultPayload["error"] = errMsg
		}
	}

	result, _ := s.marshalJSON(resultPayload)
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(result)},
		},
	}, nil, nil
}

func (s *Server) watchAutoAnalysis(ctx context.Context, req *mcp.CallToolRequest, args WatchAutoAnalysisRequest) (*mcp.CallToolResult, any, error) {
	s.logToolInvocation("watch_auto_analysis", args.SessionID, map[string]interface{}{
		"interval_ms":  args.IntervalMs,
		"timeout_secs": args.TimeoutSecs,
	})

	sess, ok := s.registry.Get(args.SessionID)
	if !ok {
		return nil, fmt.Errorf("session not found: %s", args.SessionID), nil
	}

	sess.Touch()

	client, err := s.workers.GetClient(sess.ID)
	if err != nil {
		return nil, s.logAndSanitizeError("watch_auto_analysis worker client", err), nil
	}

	interval := time.Duration(args.IntervalMs) * time.Millisecond
	if interval <= 0 {
		interval = time.Second
	}
	if interval < 200*time.Millisecond {
		interval = 200 * time.Millisecond
	}

	watchCtx := ctx
	cancel := func() {}
	if args.TimeoutSecs > 0 {
		watchCtx, cancel = context.WithTimeout(ctx, time.Duration(args.TimeoutSecs)*time.Second)
	}
	defer cancel()

	progress := s.progressReporter(ctx, req, sess.ID, "auto_analysis")
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	start := time.Now()
	updates := make([]map[string]interface{}, 0, 32)
	var lastState string
	var lastRunning bool

	for {
		infoResp, err := (*client.SessionCtrl).GetSessionInfo(watchCtx, connect.NewRequest(&pb.GetSessionInfoRequest{}))
		if err != nil {
			return nil, s.logAndSanitizeError("watch_auto_analysis GetSessionInfo", err), nil
		}
		info := infoResp.Msg
		lastState = info.GetAutoState()
		lastRunning = info.GetAutoRunning()

		entry := map[string]interface{}{
			"timestamp":       time.Now().Unix(),
			"auto_state":      lastState,
			"auto_running":    lastRunning,
			"session_id":      sess.ID,
			"elapsed_seconds": time.Since(start).Seconds(),
		}
		updates = append(updates, entry)
		s.emitProgress(progress, sess.ID, "auto_analysis", fmt.Sprintf("auto_state=%s running=%t", lastState, lastRunning), 0, 0)

		if !lastRunning {
			break
		}

		select {
		case <-watchCtx.Done():
			result, _ := s.marshalJSON(map[string]interface{}{
				"auto_running": true,
				"auto_state":   lastState,
				"updates":      updates,
				"update_count": len(updates),
				"message":      fmt.Sprintf("Stopped waiting: %v", watchCtx.Err()),
			})
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: string(result)},
				},
			}, nil, nil
		case <-ticker.C:
		}
	}

	duration := time.Since(start).Seconds()
	result, _ := s.marshalJSON(map[string]interface{}{
		"auto_running":     false,
		"auto_state":       lastState,
		"updates":          updates,
		"update_count":     len(updates),
		"duration_seconds": duration,
	})

	s.emitProgress(progress, sess.ID, "auto_analysis", "Auto-analysis complete", 1, 1)

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(result)},
		},
	}, nil, nil
}
