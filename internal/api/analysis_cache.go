package api

import (
	"context"
	"sync"
)

type analysisCacheStore struct {
	mu      sync.Mutex
	max     int
	order   []string
	results map[string]any
	calls   map[string]*analysisCall
}

type analysisCall struct {
	done   chan struct{}
	result any
	err    error
}

func newAnalysisCacheStore(max int) *analysisCacheStore {
	if max <= 0 {
		max = 128
	}
	return &analysisCacheStore{
		max:     max,
		results: make(map[string]any),
		calls:   make(map[string]*analysisCall),
	}
}

func (s *analysisCacheStore) getOrCompute(ctx context.Context, key string, compute func(context.Context) (any, error)) (any, error) {
	s.mu.Lock()
	if result, ok := s.results[key]; ok {
		s.mu.Unlock()
		return result, nil
	}
	if call, ok := s.calls[key]; ok {
		s.mu.Unlock()
		select {
		case <-call.done:
			return call.result, call.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	call := &analysisCall{done: make(chan struct{})}
	s.calls[key] = call
	s.mu.Unlock()

	call.result, call.err = compute(ctx)

	s.mu.Lock()
	delete(s.calls, key)
	if call.err == nil && call.result != nil {
		s.results[key] = call.result
		s.order = append(s.order, key)
		for len(s.order) > s.max {
			oldest := s.order[0]
			s.order = s.order[1:]
			delete(s.results, oldest)
		}
	}
	close(call.done)
	s.mu.Unlock()

	return call.result, call.err
}
