// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/kalahroudi/parley/internal/logx"
)

const (
	// maxSocketPath keeps the path under the smallest sun_path limit (104 on macOS).
	maxSocketPath   = 100
	maxRequestBytes = 64 << 10
	connDeadline    = 30 * time.Second
	maxConns        = 32
)

// RPCError is an error a Method may return to the client. Code must be a fixed
// identifier chosen by the daemon; it is sent verbatim. Any other error is
// reported as "internal" and its text is never sent or logged.
type RPCError struct{ Code string }

func (e *RPCError) Error() string { return "daemon: rpc error " + e.Code }

// Method handles one local request. params is the raw JSON the client sent.
type Method func(ctx context.Context, params json.RawMessage) (any, error)

type request struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Response is the daemon's reply to one request.
type Response struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// listenSocket binds the local socket inside a private directory. The caller
// must hold the instance lock, which is what makes removing a stale socket
// file safe.
func listenSocket(path string) (net.Listener, error) {
	if len(path) > maxSocketPath {
		return nil, fmt.Errorf("daemon: socket path is longer than %d characters; use a shorter config directory", maxSocketPath)
	}
	if err := ensurePrivateDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode().Type()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("daemon: %s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("daemon: remove stale socket: %w", err)
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("daemon: listen: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil && runtime.GOOS != "windows" {
		ln.Close()
		return nil, fmt.Errorf("daemon: restrict socket: %w", err)
	}
	return ln, nil
}

// server answers requests on the local socket, one request per connection.
type server struct {
	log     *logx.Logger
	methods map[string]Method
	uid     int // the only user whose processes may connect

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// serve accepts connections until ctx ends, then closes the listener and every
// open connection and waits for the handlers to return.
func (s *server) serve(ctx context.Context, ln net.Listener) {
	s.conns = map[net.Conn]struct{}{}
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConns)
	stop := context.AfterFunc(ctx, func() {
		ln.Close()
		s.mu.Lock()
		for c := range s.conns {
			c.Close()
		}
		s.mu.Unlock()
	})
	defer stop()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			time.Sleep(10 * time.Millisecond) // transient accept error: do not spin
			continue
		}
		if err := checkPeer(c, s.uid); err != nil {
			c.Close()
			s.log.Warn("local connection refused: not this user")
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			c.Close()
			s.log.Warn("local connection refused: too many open", logx.Size("count", maxConns))
			continue
		}
		s.mu.Lock()
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			s.handle(ctx, c)
			s.mu.Lock()
			delete(s.conns, c)
			s.mu.Unlock()
		}()
	}
	wg.Wait()
}

func (s *server) handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(connDeadline))
	var req request
	dec := json.NewDecoder(io.LimitReader(c, maxRequestBytes))
	if err := dec.Decode(&req); err != nil {
		reply(c, Response{Error: "bad_request"})
		return
	}
	m, ok := s.methods[req.Method]
	if !ok {
		reply(c, Response{Error: "unknown_method"})
		return
	}
	res, err := m(ctx, req.Params)
	if err != nil {
		var re *RPCError
		if errors.As(err, &re) {
			reply(c, Response{Error: re.Code})
		} else {
			s.log.Error("local request failed")
			reply(c, Response{Error: "internal"})
		}
		return
	}
	b, err := json.Marshal(res)
	if err != nil {
		reply(c, Response{Error: "internal"})
		return
	}
	reply(c, Response{OK: true, Result: b})
}

func reply(c net.Conn, r Response) { _ = json.NewEncoder(c).Encode(r) }

// Call sends one request to the daemon's socket and returns its reply. It is
// what parley-cli uses; it has no retries and a bounded wait.
func Call(ctx context.Context, socketPath, method string, params any) (Response, error) {
	var d net.Dialer
	ctx, cancel := context.WithTimeout(ctx, connDeadline)
	defer cancel()
	c, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return Response{}, fmt.Errorf("daemon: not running or not reachable: %w", err)
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	req := request{Method: method}
	if params != nil {
		if req.Params, err = json.Marshal(params); err != nil {
			return Response{}, err
		}
	}
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return Response{}, err
	}
	var r Response
	if err := json.NewDecoder(io.LimitReader(c, maxRequestBytes)).Decode(&r); err != nil {
		return Response{}, fmt.Errorf("daemon: bad reply: %w", err)
	}
	return r, nil
}
