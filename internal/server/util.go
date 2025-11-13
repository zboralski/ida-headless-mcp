package server

// logAndSanitizeError logs the full error server-side and returns a sanitized error for the MCP client

import (
	"encoding/json"
	"fmt"
)
// This prevents leaking internal details like file paths, connection strings, etc.
func (s *Server) logAndSanitizeError(context string, err error) error {
	s.logger.Printf("[Error] %s: %v", context, err)

	return fmt.Errorf("%s failed", context)
}

func (s *Server) logToolInvocation(tool, sessionID string, details map[string]interface{}) {
	if details == nil {
		details = map[string]interface{}{}
	}
	if sessionID != "" {
		details["session"] = sessionID
	}
	s.logger.Printf("[Tool] %s %v", tool, details)
}

// marshalJSON marshals v to JSON, using indentation when debug mode is enabled
func (s *Server) marshalJSON(v interface{}) ([]byte, error) {

	return json.MarshalIndent(v, "", "  ")
}

func (s *Server) debugf(format string, args ...interface{}) {
	if s.debug {
		s.logger.Printf("[DEBUG] "+format, args...)
	}
}
