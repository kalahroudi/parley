// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package localsock is the daemon's local control socket: one JSON request per
// connection, answered only to processes of the daemon's own user. The socket
// lives in a private directory (see fsperm); on Linux and macOS the kernel also
// attests the peer's uid on every connection, so a mis-set mode or a bind mount
// cannot open the daemon to other users. On Windows the protected DACL on the
// directory is the restriction (AF_UNIX there carries no peer credentials).
// Requests and the number of open connections are bounded.
package localsock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kalahroudi/parley/internal/fsperm"
	"github.com/kalahroudi/parley/internal/logx"
)

// The limits are single literals: a product such as 64 << 10 has no statement
// for the mutation gate to cover. TestConstantsArePinned pins them.
const (
	// MaxPath keeps the path under the smallest sun_path limit (104 on macOS).
	MaxPath         = 100
	maxRequestBytes = 65536                         // 64 KiB
	connDeadline    = time.Duration(30_000_000_000) // 30s
	acceptRetry     = time.Duration(10_000_000)     // 10ms
	maxConns        = 32
)

// RPCError is an error a Method may return to the client. Code must be a fixed
// identifier chosen by the daemon; it is sent verbatim. Any other error is
// reported as "internal" and its text is never sent or logged.
type RPCError struct{ Code string }

func (e *RPCError) Error() string { return "localsock: rpc error " + e.Code }

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

// Seams for tests: the OS calls that cannot be made to fail on a healthy machine.
var (
	listenUnix  = func(path string) (net.Listener, error) { return net.Listen("unix", path) }
	removeFile  = os.Remove
	restrictFn  = restrict  // OS-specific: closes the socket file to other users
	checkPeerFn = checkPeer // OS-specific: the kernel-attested peer uid check
	dialUnix    = func(ctx context.Context, path string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", path)
	}
)

// Listen binds the local socket inside a private directory. The caller must
// hold the instance lock, which is what makes removing a stale socket file
// safe: nothing else of this user's can be listening on it.
func Listen(path string) (net.Listener, error) {
	// A path starting with "@" would bind a Linux abstract socket, which has no
	// file mode and is reachable by every user; absolute paths never do.
	if !filepath.IsAbs(path) {
		return nil, errors.New("localsock: socket path must be absolute")
	}
	if len(path) > MaxPath {
		return nil, fmt.Errorf("localsock: socket path is longer than %d characters; use a shorter config directory", MaxPath)
	}
	if err := fsperm.EnsureDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode().Type()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("localsock: %s exists and is not a socket", path)
		}
		if err := removeFile(path); err != nil {
			return nil, fmt.Errorf("localsock: remove stale socket: %w", err)
		}
	}
	ln, err := listenUnix(path)
	if err != nil {
		return nil, fmt.Errorf("localsock: listen: %w", err)
	}
	if err := restrictFn(path); err != nil {
		ln.Close()
		return nil, fmt.Errorf("localsock: restrict socket: %w", err)
	}
	return ln, nil
}

// Server answers requests on the local socket, one request per connection.
type Server struct {
	Log     *logx.Logger
	Methods map[string]Method
	UID     int // the only user whose processes may connect (ignored on Windows)

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// Serve accepts connections until ctx ends, then closes the listener and every
// open connection and waits for the handlers to return.
func (s *Server) Serve(ctx context.Context, ln net.Listener) {
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
			time.Sleep(acceptRetry) // transient accept error: do not spin
			continue
		}
		if err := checkPeerFn(c, s.UID); err != nil {
			c.Close()
			s.Log.Warn("local connection refused: not this user")
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			c.Close()
			s.Log.Warn("local connection refused: too many open", logx.Size("count", maxConns))
			continue
		}
		s.mu.Lock()
		if ctx.Err() != nil {
			// Shutdown's sweep may already have run; a connection added now
			// would never be closed and wg.Wait would sit out its deadline.
			s.mu.Unlock()
			c.Close()
			<-sem
			break
		}
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

func (s *Server) handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(connDeadline))
	var req request
	dec := json.NewDecoder(io.LimitReader(c, maxRequestBytes))
	if err := dec.Decode(&req); err != nil {
		reply(c, Response{Error: "bad_request"})
		return
	}
	m, ok := s.Methods[req.Method]
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
			s.Log.Error("local request failed")
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
	ctx, cancel := context.WithTimeout(ctx, connDeadline)
	defer cancel()
	c, err := dialUnix(ctx, socketPath)
	if err != nil {
		return Response{}, fmt.Errorf("localsock: daemon not running or not reachable: %w", err)
	}
	defer c.Close()
	dl, _ := ctx.Deadline() // always set: the context has a timeout
	c.SetDeadline(dl)
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
		return Response{}, fmt.Errorf("localsock: bad reply: %w", err)
	}
	return r, nil
}
