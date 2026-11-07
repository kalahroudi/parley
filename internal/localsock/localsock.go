// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package localsock is the daemon's local control socket: one JSON request per
// connection, answered only to processes of the daemon's own user. The socket
// lives in a private directory (see fsperm); on Linux and macOS the kernel also
// attests the peer's uid on every connection, so a mis-set mode or a bind mount
// cannot open the daemon to other users. Requests and the number of open
// connections are bounded.
//
// Supported platforms are Linux, macOS and Windows. The package deliberately
// does not build anywhere else (there is no checkPeer for them): an untested
// port must fail to compile rather than run without the peer check.
//
// What this guarantees, exactly.
//
// Linux and macOS: another local user cannot connect (the directory is 0700 and
// the socket 0600, and the kernel-reported uid of every connection is checked).
// Root can. Any process running as the same user can connect and use every
// method except the Sensitive ones; the socket is not a boundary against the
// user's own processes. For a Sensitive method the kernel-reported pid of the
// caller is read and the Guard decides (the daemon refuses callers that belong to
// a bot it started, see internal/botproc); a pid that cannot be read is refused.
//
// Windows: the socket is AF_UNIX inside a directory with a protected DACL that
// grants only the current user, SYSTEM and Administrators, and it is verified at
// every start. Another standard user cannot reach the socket because they cannot
// open its directory, and a second check reads the pid of every connecting
// process (SIO_AF_UNIX_GETPEERPID), opens its token and refuses the connection
// unless its user SID is the daemon's own; anything that cannot be read is
// refused. Administrators and SYSTEM can open the directory but are refused
// unless they run as the daemon's user. Any process running as the same user can
// connect and use every method except the Sensitive ones. The pid is looked up
// after accept, so a peer that exits and whose pid is reused before the lookup is
// judged as the new process; the directory DACL still keeps other users out.
package localsock

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/kalahroudi/parley/internal/fsperm"
	"github.com/kalahroudi/parley/internal/logx"
)

// The limits are single literals: a product such as 64 << 10 has no statement
// for the mutation gate to cover. TestConstantsArePinned pins them.
const (
	// MaxPath keeps the path under the smallest sun_path limit (104 on macOS).
	MaxPath = 100
	// A request carries up to 32 KiB of task text, which JSON escaping can make
	// six times as long (control characters), so 256 KiB. A reply carries a
	// directory page (at most 512 KiB from the gateway) that escaping can
	// also inflate six times, so 4 MiB.
	maxRequestBytes = 262144                        // 256 KiB
	maxReplyBytes   = 4194304                       // 4 MiB
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
	peerPIDFn   = peerPID   // OS-specific: the kernel-attested peer pid
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
	// Sensitive names the methods that change what the daemon trusts or runs (approving a task). For these the
	// kernel-reported pid of the caller is read, and Guard must allow it. If the pid cannot be read, or Guard is nil
	// or returns an error, the request is refused: these methods fail closed.
	Sensitive map[string]bool
	Guard     func(pid int) error

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
	// The method gets the same deadline as the connection: a handler that waits
	// on the network must not outlive the client that has given up, or hold one
	// of the connection slots for ever.
	ctx, cancel := context.WithTimeout(ctx, connDeadline)
	defer cancel()
	var req request
	dec := json.NewDecoder(io.LimitReader(c, maxRequestBytes))
	dec.DisallowUnknownFields()
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil || !onlySpace(dec.Buffered()) || !ExactKeys(raw, "method", "params") || json.Unmarshal(raw, &req) != nil {
		reply(c, Response{Error: "bad_request"})
		return
	}
	m, ok := s.Methods[req.Method]
	if !ok {
		reply(c, Response{Error: "unknown_method"})
		return
	}
	if s.Sensitive[req.Method] && s.guard(c) != nil {
		s.Log.Warn("local request refused: caller not allowed to change trust")
		reply(c, Response{Error: CodeNotPermitted})
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

// ExactKeys reports whether b is one JSON object whose top-level keys are all different, even when compared without
// case (encoding/json would fold them into one field and keep the last), and, when allowed is given, are all exactly
// among allowed, with nothing after it. Nested values are skipped, not inspected: they are the business of whoever reads them.
func ExactKeys(b []byte, allowed ...string) bool {
	d := json.NewDecoder(bytes.NewReader(b))
	if t, err := d.Token(); err != nil || t != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for d.More() {
		kt, err := d.Token()
		k, _ := kt.(string)
		if err != nil || seen[strings.ToLower(k)] || (len(allowed) > 0 && !slices.Contains(allowed, k)) {
			return false
		}
		seen[strings.ToLower(k)] = true
		var skip json.RawMessage
		if d.Decode(&skip) != nil {
			return false
		}
	}
	_, _ = d.Token() // the closing brace: More is only false before one
	_, err := d.Token()
	return err == io.EOF // and nothing after it
}

// onlySpace reports whether what the decoder has already read past the request is only JSON whitespace. It never
// reads more: a client that sends one request and waits for the reply must not be made to wait for more bytes.
func onlySpace(r io.Reader) bool {
	b, _ := io.ReadAll(r)
	return len(bytes.TrimLeft(b, " \t\r\n")) == 0
}

// CodeNotPermitted is the fixed error a sensitive method gives a caller the Guard refused.
const CodeNotPermitted = "not_permitted"

// guard allows a sensitive request only if the caller's pid is known and Guard accepts it.
func (s *Server) guard(c net.Conn) error {
	if s.Guard == nil {
		return errNoGuard
	}
	pid, err := peerPIDFn(c)
	if err != nil {
		return err
	}
	if pid <= 0 {
		return errNoPID
	}
	return s.Guard(pid)
}

var (
	errNoGuard = errors.New("localsock: no guard for a sensitive method")
	errNoPID   = errors.New("localsock: the kernel gave no caller pid")
)

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
	if err := json.NewDecoder(io.LimitReader(c, maxReplyBytes)).Decode(&r); err != nil {
		return Response{}, fmt.Errorf("localsock: bad reply: %w", err)
	}
	return r, nil
}
