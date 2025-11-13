package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"

	"connectrpc.com/connect"
	pb "github.com/zboralski/ida-headless-mcp/ida/worker/v1"
	"github.com/zboralski/ida-headless-mcp/internal/worker"
)

type sessionCache struct {
	mu        sync.RWMutex
	strings   []*pb.StringItem
	functions []*pb.Function
	imports   []*pb.Import
	exports   []*pb.Export
}

func (s *Server) fetchAllStrings(ctx context.Context, client *worker.WorkerClient, progress *progressReporter) ([]*pb.StringItem, error) {
	const chunkSize = defaultPageLimit
	chunkLimit := int32(chunkSize)
	var all []*pb.StringItem
	offset := 0
	var total float64
	for {
		req := &pb.GetStringsRequest{Offset: int32(offset), Limit: chunkLimit}
		resp, err := (*client.Analysis).GetStrings(ctx, connect.NewRequest(req))
		if err != nil {
			if progress != nil {
				progress.Emit("get_strings", fmt.Sprintf("Failed to enumerate strings: %v", err), float64(len(all)), total)
			}
			return nil, err
		}
		if resp.Msg.Error != "" {
			if progress != nil {
				progress.Emit("get_strings", fmt.Sprintf("IDA error enumerating strings: %s", resp.Msg.Error), float64(len(all)), total)
			}
			return nil, errors.New(resp.Msg.Error)
		}
		chunk := resp.Msg.GetStrings()
		all = append(all, chunk...)
		if total == 0 && resp.Msg.Total > 0 {
			total = float64(resp.Msg.Total)
		}
		if progress != nil {
			progress.Emit("get_strings", fmt.Sprintf("Enumerated %d strings", len(all)), float64(len(all)), total)
		}
		if len(chunk) < chunkSize {
			break
		}
		offset += len(chunk)
	}
	if progress != nil {
		progress.Emit("get_strings", "String enumeration complete", float64(len(all)), total)
	}
	return all, nil
}

func (s *Server) fetchAllFunctions(ctx context.Context, client *worker.WorkerClient, progress *progressReporter) ([]*pb.Function, error) {
	if progress != nil {
		progress.Emit("get_functions", "Fetching functions from IDA", 0, 0)
	}
	resp, err := (*client.Analysis).GetFunctions(ctx, connect.NewRequest(&pb.GetFunctionsRequest{}))
	if err != nil {
		if progress != nil {
			progress.Emit("get_functions", fmt.Sprintf("Failed to fetch functions: %v", err), 0, 0)
		}
		return nil, err
	}
	if resp.Msg.Error != "" {
		if progress != nil {
			progress.Emit("get_functions", fmt.Sprintf("IDA error fetching functions: %s", resp.Msg.Error), 0, 0)
		}
		return nil, errors.New(resp.Msg.Error)
	}
	functions := resp.Msg.GetFunctions()
	if progress != nil {
		progress.Emit("get_functions", fmt.Sprintf("Fetched %d functions", len(functions)), float64(len(functions)), float64(len(functions)))
	}
	return functions, nil
}

func (s *Server) fetchAllImports(ctx context.Context, client *worker.WorkerClient, progress *progressReporter) ([]*pb.Import, error) {
	if progress != nil {
		progress.Emit("get_imports", "Fetching imports from IDA", 0, 0)
	}
	resp, err := (*client.Analysis).GetImports(ctx, connect.NewRequest(&pb.GetImportsRequest{}))
	if err != nil {
		if progress != nil {
			progress.Emit("get_imports", fmt.Sprintf("Failed to fetch imports: %v", err), 0, 0)
		}
		return nil, err
	}
	if resp.Msg.Error != "" {
		if progress != nil {
			progress.Emit("get_imports", fmt.Sprintf("IDA error fetching imports: %s", resp.Msg.Error), 0, 0)
		}
		return nil, errors.New(resp.Msg.Error)
	}
	imports := resp.Msg.GetImports()
	if progress != nil {
		progress.Emit("get_imports", fmt.Sprintf("Fetched %d imports", len(imports)), float64(len(imports)), float64(len(imports)))
	}
	return imports, nil
}

func (s *Server) fetchAllExports(ctx context.Context, client *worker.WorkerClient, progress *progressReporter) ([]*pb.Export, error) {
	if progress != nil {
		progress.Emit("get_exports", "Fetching exports from IDA", 0, 0)
	}
	resp, err := (*client.Analysis).GetExports(ctx, connect.NewRequest(&pb.GetExportsRequest{}))
	if err != nil {
		if progress != nil {
			progress.Emit("get_exports", fmt.Sprintf("Failed to fetch exports: %v", err), 0, 0)
		}
		return nil, err
	}
	if resp.Msg.Error != "" {
		if progress != nil {
			progress.Emit("get_exports", fmt.Sprintf("IDA error fetching exports: %s", resp.Msg.Error), 0, 0)
		}
		return nil, errors.New(resp.Msg.Error)
	}
	exports := resp.Msg.GetExports()
	if progress != nil {
		progress.Emit("get_exports", fmt.Sprintf("Fetched %d exports", len(exports)), float64(len(exports)), float64(len(exports)))
	}
	return exports, nil
}

func (c *sessionCache) loadStrings(sessionID string, logger *log.Logger, loader func() ([]*pb.StringItem, error)) ([]*pb.StringItem, bool, error) {
	c.mu.RLock()
	if c.strings != nil {
		data := c.strings
		c.mu.RUnlock()
		logger.Printf("[Cache] strings HIT session=%s", sessionID)
		return data, true, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.strings == nil {
		logger.Printf("[Cache] strings MISS session=%s", sessionID)
		data, err := loader()
		if err != nil {
			return nil, false, err
		}
		c.strings = data
	}
	return c.strings, false, nil
}

func (c *sessionCache) loadFunctions(sessionID string, logger *log.Logger, loader func() ([]*pb.Function, error)) ([]*pb.Function, bool, error) {
	c.mu.RLock()
	if c.functions != nil {
		data := c.functions
		c.mu.RUnlock()
		logger.Printf("[Cache] functions HIT session=%s", sessionID)
		return data, true, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.functions == nil {
		logger.Printf("[Cache] functions MISS session=%s", sessionID)
		data, err := loader()
		if err != nil {
			return nil, false, err
		}
		c.functions = data
	}
	return c.functions, false, nil
}

func (c *sessionCache) loadImports(sessionID string, logger *log.Logger, loader func() ([]*pb.Import, error)) ([]*pb.Import, bool, error) {
	c.mu.RLock()
	if c.imports != nil {
		data := c.imports
		c.mu.RUnlock()
		logger.Printf("[Cache] imports HIT session=%s", sessionID)
		return data, true, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.imports == nil {
		logger.Printf("[Cache] imports MISS session=%s", sessionID)
		data, err := loader()
		if err != nil {
			return nil, false, err
		}
		c.imports = data
	}
	return c.imports, false, nil
}

func (c *sessionCache) loadExports(sessionID string, logger *log.Logger, loader func() ([]*pb.Export, error)) ([]*pb.Export, bool, error) {
	c.mu.RLock()
	if c.exports != nil {
		data := c.exports
		c.mu.RUnlock()
		logger.Printf("[Cache] exports HIT session=%s", sessionID)
		return data, true, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.exports == nil {
		logger.Printf("[Cache] exports MISS session=%s", sessionID)
		data, err := loader()
		if err != nil {
			return nil, false, err
		}
		c.exports = data
	}
	return c.exports, false, nil
}

func (s *Server) getSessionCache(sessionID string) *sessionCache {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if s.cache == nil {
		s.cache = make(map[string]*sessionCache)
	}
	cache := s.cache[sessionID]
	if cache == nil {
		cache = &sessionCache{}
		s.cache[sessionID] = cache
	}
	return cache
}

func (s *Server) deleteSessionCache(sessionID string) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if s.cache != nil {
		if _, ok := s.cache[sessionID]; ok {
			s.logger.Printf("[Cache] clear session=%s", sessionID)
		}
		delete(s.cache, sessionID)
	}
}
