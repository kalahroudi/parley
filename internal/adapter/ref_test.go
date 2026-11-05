// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package adapter_test

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/kalahroudi/parley/internal/adapter/adaptertest"
	"github.com/kalahroudi/parley/internal/bot/bottest"
)

// refServer serves the Fake over HTTP as a bot service and records what it saw.
type refServer struct {
	mu       sync.Mutex
	convs    map[string]*adaptertest.Conv
	auth     []string
	cancels  int
	requests []adaptertest.InLine
}

func (s *refServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	line, _ := bufio.NewReaderSize(r.Body, 1<<22).ReadBytes('\n')
	var in adaptertest.InLine
	if json.Unmarshal(line, &in) != nil {
		http.Error(w, "bad", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.auth = append(s.auth, r.Header.Get("Authorization"))
	s.requests = append(s.requests, in)
	var c *adaptertest.Conv
	switch in.Type {
	case "task":
		c = adaptertest.Start(&bottest.Fake{}, in)
		s.convs[in.ID] = c
	case "answer":
		c = s.convs[in.ID]
	case "cancel":
		s.cancels++
		if c = s.convs[in.ID]; c != nil {
			c.Cancel()
			delete(s.convs, in.ID)
		}
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	if c == nil {
		http.Error(w, "unknown", http.StatusNotFound)
		return
	}
	if in.Type == "answer" {
		c.Answers <- in.Content
	}
	fl := w.(http.Flusher)
	for {
		select {
		case o, ok := <-c.Out:
			if !ok {
				s.forget(in.ID)
				return
			}
			adaptertest.WriteLine(w, o)
			fl.Flush()
			if o.Type == "question" {
				return
			}
		case <-r.Context().Done():
			c.Cancel()
			s.forget(in.ID)
			return
		}
	}
}

func (s *refServer) forget(id string) { s.mu.Lock(); delete(s.convs, id); s.mu.Unlock() }

func newRefServer(t testing.TB) (*refServer, *httptest.Server) {
	s := &refServer{convs: map[string]*adaptertest.Conv{}}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	return s, srv
}
