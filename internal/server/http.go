package server

import (
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func (s *Server) HTTPMux(mcpServer *mcp.Server) http.Handler {
	sseHandler := mcp.NewSSEHandler(func(r *http.Request) *mcp.Server {
		if s.debug {
			s.logger.Printf("[DEBUG] SSE connection from %s: %s %s", r.RemoteAddr, r.Method, r.URL.Path)
		}
		return mcpServer
	}, nil)

	streamHandler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return mcpServer
	}, &mcp.StreamableHTTPOptions{
		JSONResponse:   true,
		SessionTimeout: s.sessionTimeout,
		Stateless:      true,
	})

	mux := http.NewServeMux()
	mux.Handle("/sse", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.debug {
			s.logger.Printf("[SSE] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		}
		sseHandler.ServeHTTP(w, r)
	}))
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.debug {
			s.logger.Printf("[HTTP] %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		}
		streamHandler.ServeHTTP(w, r)
	}))
	return mux
}
