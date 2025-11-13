package server

import (
	"context"
	"log"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type sessionProgress struct {
	Stage     string
	Message   string
	Progress  float64
	Total     float64
	UpdatedAt time.Time
}

type progressReporter struct {
	ctx      context.Context
	session  *mcp.ServerSession
	token    any
	logger   *log.Logger
	last     float64
	stage    string
	recorder func(stage, message string, progress, total float64)
}

func (s *Server) recordProgress(sessionID, stage, message string, progress, total float64) {
	if sessionID == "" {
		return
	}
	s.progressMu.Lock()
	defer s.progressMu.Unlock()
	if s.progress == nil {
		s.progress = make(map[string]*sessionProgress)
	}
	s.progress[sessionID] = &sessionProgress{
		Stage:     stage,
		Message:   message,
		Progress:  progress,
		Total:     total,
		UpdatedAt: time.Now(),
	}
}

func (s *Server) clearProgress(sessionID string) {
	if sessionID == "" {
		return
	}
	s.progressMu.Lock()
	defer s.progressMu.Unlock()
	delete(s.progress, sessionID)
}

func (s *Server) getProgress(sessionID string) (*sessionProgress, bool) {
	s.progressMu.Lock()
	defer s.progressMu.Unlock()
	if s.progress == nil {
		return nil, false
	}
	p, ok := s.progress[sessionID]
	if !ok {
		return nil, false
	}
	cpy := *p
	return &cpy, true
}

func newProgressReporter(ctx context.Context, req *mcp.CallToolRequest, logger *log.Logger, stage string, recorder func(stage, message string, progress, total float64)) *progressReporter {
	var session *mcp.ServerSession
	var token any
	if req != nil && req.Session != nil && req.Params != nil {
		session = req.Session
		token = req.Params.GetProgressToken()
	}
	return &progressReporter{
		ctx:      ctx,
		session:  session,
		token:    token,
		logger:   logger,
		stage:    stage,
		recorder: recorder,
	}
}

func (p *progressReporter) Emit(stage, message string, progress, total float64) {
	if p == nil {
		return
	}
	if stage == "" {
		stage = p.stage
	}
	if stage != "" {
		p.stage = stage
	}
	if p.recorder != nil {
		p.recorder(p.stage, message, progress, total)
	}
	if p.token == nil || p.session == nil {
		return
	}
	if progress < p.last {
		progress = p.last
	} else {
		p.last = progress
	}
	params := &mcp.ProgressNotificationParams{
		ProgressToken: p.token,
		Progress:      progress,
	}
	if message != "" {
		params.Message = message
	}
	if total > 0 {
		params.Total = total
	}
	if err := p.session.NotifyProgress(p.ctx, params); err != nil && p.logger != nil {
		p.logger.Printf("Warning: failed to send progress notification: %v", err)
	}
}

func (s *Server) progressReporter(ctx context.Context, req *mcp.CallToolRequest, sessionID, stage string) *progressReporter {
	return newProgressReporter(ctx, req, s.logger, stage, func(stage, message string, progress, total float64) {
		s.recordProgress(sessionID, stage, message, progress, total)
	})
}

func (s *Server) emitProgress(progress *progressReporter, sessionID, stage, message string, current, total float64) {
	if progress != nil {
		progress.Emit(stage, message, current, total)
	} else {
		s.recordProgress(sessionID, stage, message, current, total)
	}
}
