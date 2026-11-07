// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package acceptance

// T412 acceptance: real daemons (internal/daemon with the pipeline in internal/pipeline) talk through a small
// gateway that speaks the real protocols (connect tokens, the tunnel, the A2A endpoint, the prekey relay) and
// writes down every byte it handles. The tests prove what the plan promises for the message path:
//   - a task sent from one daemon reaches the other's bot through verify, open, erase, ack, execute, and the
//     replies come back, with nothing dropped or run twice;
//   - nothing readable crosses the gateway;
//   - hostile events change nothing;
//   - a daemon with no fresh trust state sends nothing at all.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/kalahroudi/parley/internal/binding"
	"github.com/kalahroudi/parley/internal/connect"
	"github.com/kalahroudi/parley/internal/daemon"
	"github.com/kalahroudi/parley/internal/envelope"
	"github.com/kalahroudi/parley/internal/frames"
	"github.com/kalahroudi/parley/internal/localsock"
	"github.com/kalahroudi/parley/internal/logx"
	"github.com/kalahroudi/parley/internal/outbox"
	"github.com/kalahroudi/parley/internal/pipeline"
	"github.com/kalahroudi/parley/internal/revocation"
	"github.com/kalahroudi/parley/internal/tunnel"
)

const pipeTenant = "acme"

// pipeGW is the gateway the daemons talk to. It authenticates devices the way the Worker does (a signed
// challenge, then a single-use connect token, then a bearer for /a2a), relays prekey frames, wraps sealed parts
// in A2A events, and records everything it sees.
type pipeGW struct {
	t       *testing.T
	srv     *httptest.Server
	rootKey ed25519.PrivateKey

	mu         sync.Mutex
	devs       map[string]*pipeDev
	tokens     map[string]tokenRec
	challenges map[string]int64
	conns      map[string]chan string // device -> events to push
	seen       [][]byte
	wires      [][]byte // every sealed message sent through /a2a, in order
	revs       *revocation.Signed
	nTokens    int

	// dirHook, if set, answers /v1/directory/binding instead of the honest rule (a hostile or broken gateway):
	// it returns the status and the body, or ok false to fall through to the honest answer.
	dirHook  func(caller, device string) (status int, body string, ok bool)
	dirCalls atomic.Int32 // /v1/directory/binding calls

	relayed atomic.Int32 // prekey frames relayed
	a2a     atomic.Int32 // /a2a calls
	opens   atomic.Int32 // tunnel connections
}

type tokenRec struct {
	device string
	scope  connect.Scope
	used   bool
}

type pipeDev struct {
	id   string
	key  ed25519.PrivateKey
	bind *binding.Signed
}

func newPipeGW(t *testing.T) *pipeGW {
	t.Helper()
	_, rk, _ := ed25519.GenerateKey(rand.Reader)
	g := &pipeGW{t: t, rootKey: rk, devs: map[string]*pipeDev{}, tokens: map[string]tokenRec{}, challenges: map[string]int64{}, conns: map[string]chan string{}}
	g.srv = httptest.NewServer(http.HandlerFunc(g.serve))
	t.Cleanup(g.srv.Close)
	return g
}

func (g *pipeGW) rootPub() ed25519.PublicKey { return g.rootKey.Public().(ed25519.PublicKey) }

func (g *pipeGW) note(b []byte) {
	g.mu.Lock()
	g.seen = append(g.seen, bytes.Clone(b))
	g.mu.Unlock()
}

// everything is every byte the gateway handled, for the canary scan.
func (g *pipeGW) everything() []byte {
	g.mu.Lock()
	defer g.mu.Unlock()
	return bytes.Join(g.seen, []byte("\n"))
}

func (g *pipeGW) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/v1/connect/challenge":
		g.mu.Lock()
		ch := fmt.Sprint("ch", len(g.challenges)+1, "-", time.Now().UnixNano())
		exp := time.Now().Add(time.Minute).UnixMilli()
		g.challenges[ch] = exp
		g.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"challenge": ch, "expires_at": exp})
	case "/v1/connect/token":
		g.token(w, r)
	case "/v1/revocations":
		g.mu.Lock()
		l := g.revs
		g.mu.Unlock()
		if l == nil {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(l)
	case "/v1/connect":
		g.tunnel(w, r)
	case "/a2a":
		g.a2aCall(w, r)
	case "/v1/directory/binding":
		g.binding(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (g *pipeGW) token(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Tenant, Device, Challenge string
		Version                   uint64
		Scope                     connect.Scope
		Signature                 []byte
	}
	body, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(body, &in)
	g.mu.Lock()
	d, exp := g.devs[in.Device], g.challenges[in.Challenge]
	delete(g.challenges, in.Challenge) // single use
	g.mu.Unlock()
	if d == nil || exp == 0 || in.Tenant != pipeTenant || in.Version != d.bind.Version ||
		!ed25519.Verify(d.key.Public().(ed25519.PublicKey), connect.Message(in.Tenant, in.Device, in.Challenge, exp, in.Version, in.Scope), in.Signature) {
		http.Error(w, "no", http.StatusUnauthorized)
		return
	}
	g.mu.Lock()
	g.nTokens++
	tok := fmt.Sprintf("pdt_%s.%s.%d", pipeTenant, in.Device, g.nTokens)
	g.tokens[tok] = tokenRec{device: in.Device, scope: in.Scope}
	g.mu.Unlock()
	json.NewEncoder(w).Encode(map[string]any{"token": tok, "expires_at": time.Now().Add(5 * time.Minute).UnixMilli()})
}

// binding is what the Worker does for /v1/directory/binding: a device with an api token of this tenant gets the
// root-signed binding of an enrolled device, and 404 for anything else.
func (g *pipeGW) binding(w http.ResponseWriter, r *http.Request) {
	g.dirCalls.Add(1)
	caller, ok := g.bearer(r, connect.ScopeAPI, false)
	if !ok {
		http.Error(w, "no", http.StatusUnauthorized)
		return
	}
	var in struct{ Device string }
	body, _ := io.ReadAll(r.Body)
	g.note(body)
	if json.Unmarshal(body, &in) != nil {
		http.Error(w, "bad", http.StatusBadRequest)
		return
	}
	g.mu.Lock()
	hook, d := g.dirHook, g.devs[in.Device]
	g.mu.Unlock()
	if hook != nil {
		if status, out, ok := hook(caller, in.Device); ok {
			w.WriteHeader(status)
			io.WriteString(w, out)
			return
		}
	}
	if d == nil {
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, `{"error":"not_found"}`)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"binding": d.bind})
}

func (g *pipeGW) bearer(r *http.Request, scope connect.Scope, spend bool) (string, bool) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	g.mu.Lock()
	defer g.mu.Unlock()
	rec, ok := g.tokens[tok]
	if !ok || rec.scope != scope || (spend && rec.used) {
		return "", false
	}
	if spend {
		rec.used = true
		g.tokens[tok] = rec
	}
	return rec.device, true
}

func (g *pipeGW) tunnel(w http.ResponseWriter, r *http.Request) {
	dev, ok := g.bearer(r, connect.ScopeConnect, true)
	if !ok {
		http.Error(w, "no", http.StatusUnauthorized)
		return
	}
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer c.CloseNow()
	ctx := r.Context()
	if _, _, err := c.Read(ctx); err != nil { // hello
		return
	}
	g.opens.Add(1)
	c.Write(ctx, websocket.MessageText, []byte(`{"t":"welcome","v":1,"session":"s","resumed":false,"rx_seq":0,"heartbeat_ms":20000}`))
	out := make(chan string, 256)
	g.mu.Lock()
	g.conns[dev] = out
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		if g.conns[dev] == out {
			delete(g.conns, dev)
		}
		g.mu.Unlock()
	}()
	go func() {
		for seq := 1; ; seq++ {
			select {
			case body := <-out:
				b, _ := json.Marshal(map[string]any{"t": "event", "seq": seq, "body": body})
				if c.Write(ctx, websocket.MessageText, b) != nil {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	for {
		typ, data, err := c.Read(ctx)
		if err != nil {
			return
		}
		if typ != websocket.MessageText || string(data) == "ping" {
			continue
		}
		var m struct {
			T    string `json:"t"`
			Seq  uint64 `json:"seq"`
			Body string `json:"body"`
		}
		if json.Unmarshal(data, &m) != nil || m.T != "frame" {
			continue
		}
		g.note([]byte(m.Body))
		b, _ := json.Marshal(map[string]any{"t": "ack", "seq": m.Seq})
		c.Write(ctx, websocket.MessageText, b)
		g.relay(dev, m.Body)
	}
}

// relay is what the Worker does with a prekey frame: name the sender it authenticated, forward it, and tell a
// requester when the target is not there.
func (g *pipeGW) relay(from, body string) {
	if !strings.HasPrefix(body, `{"t":"prekey_`) {
		return
	}
	var f map[string]any
	if json.Unmarshal([]byte(body), &f) != nil {
		return
	}
	g.relayed.Add(1)
	to, _ := f["to"].(string)
	delete(f, "to")
	f["from"] = from
	if f["t"] == frames.KindPrekeyRefused {
		f["reason"] = frames.ReasonRefused
	}
	out, _ := json.Marshal(f)
	if !g.push(to, string(out)) && f["t"] == frames.KindPrekeyRequest {
		g.push(from, fmt.Sprintf(`{"t":"prekey_refused","id":%q,"from":%q,"reason":"offline"}`, f["id"], to))
	}
}

// push puts an event on a device's tunnel; false when it is not connected.
func (g *pipeGW) push(to, body string) bool {
	g.mu.Lock()
	ch := g.conns[to]
	g.mu.Unlock()
	if ch == nil {
		return false
	}
	g.note([]byte(body))
	select {
	case ch <- body:
		return true
	default:
		return false
	}
}

func (g *pipeGW) a2aCall(w http.ResponseWriter, r *http.Request) {
	g.a2a.Add(1)
	dev, ok := g.bearer(r, connect.ScopeAPI, false)
	if !ok {
		http.Error(w, "no", http.StatusUnauthorized)
		return
	}
	body, _ := io.ReadAll(r.Body)
	g.note(body)
	var rpc struct {
		Method string
		Params struct {
			Message struct {
				Parts []struct{ Raw string }
			}
			Metadata struct {
				Parley struct{ Parts []struct{ Raw string } }
			}
		}
	}
	_ = json.Unmarshal(body, &rpc)
	parts := rpc.Params.Message.Parts
	if rpc.Method == "CancelTask" {
		parts = rpc.Params.Metadata.Parley.Parts
	}
	reply := func(v any) { json.NewEncoder(w).Encode(v) }
	if len(parts) != 1 {
		reply(map[string]any{"jsonrpc": "2.0", "id": 1, "error": map[string]any{"code": -32602, "message": "invalid params"}})
		return
	}
	wire, err := base64.StdEncoding.DecodeString(parts[0].Raw)
	var m *envelope.Message
	if err == nil {
		m, err = envelope.Unmarshal(wire)
	}
	if err != nil || m.Header.SenderDevice != dev || m.Header.Tenant != pipeTenant {
		reply(map[string]any{"jsonrpc": "2.0", "id": 1, "error": map[string]any{"code": -32602, "message": "invalid params"}})
		return
	}
	g.mu.Lock()
	g.wires = append(g.wires, wire)
	g.mu.Unlock()
	if !g.push(m.Header.TargetDevice, aEvent(wire)) {
		reply(map[string]any{"jsonrpc": "2.0", "id": 1, "error": map[string]any{"code": -32010, "message": "recipient offline"}})
		return
	}
	reply(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"task": map[string]any{"id": hexID(m.Header.TaskID)}}})
}

func hexID(id [16]byte) string { return fmt.Sprintf("%x", id[:]) }

// aEvent is what the Worker pushes to a daemon for a sealed message (src/a2a.ts eventBody).
func aEvent(wire []byte) string {
	b, _ := json.Marshal(map[string]any{"a2a": "1.0", "task": map[string]any{"id": "x", "status": map[string]any{"state": "TASK_STATE_WORKING",
		"message": map[string]any{"messageId": "m", "parts": []map[string]string{{"raw": base64.StdEncoding.EncodeToString(wire), "mediaType": frames.SealedMediaType}},
			"metadata": map[string]any{"parley": map[string]any{"kind": "STATUS", "from": "not-trusted"}}}}}})
	return string(b)
}

// directory is the honest peer lookup that tests give a daemon to keep the gateway out of it; the daemon's own
// lookup through /v1/directory/binding is tested in daemon_m1_test.go.
func (g *pipeGW) directory(_ context.Context, device string) (*binding.Signed, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if d := g.devs[device]; d != nil {
		return d.bind, nil
	}
	return nil, fmt.Errorf("no such device: %w", outbox.ErrGone)
}

func (g *pipeGW) setList(l *revocation.Signed) {
	g.mu.Lock()
	g.revs = l
	g.mu.Unlock()
}

// clock is a daemon's clock, which a test can move.
type clock struct{ off atomic.Int64 }

func (c *clock) now() time.Time          { return time.Now().Add(time.Duration(c.off.Load())) }
func (c *clock) advance(d time.Duration) { c.off.Add(int64(d)) }

type got struct {
	Type    envelope.Type
	Task    [16]byte
	Caller  string
	Owner   string
	Content string
}

// pipeNode is a running daemon with a bot that records what it is given.
type pipeNode struct {
	t     *testing.T
	id    string
	d     *daemon.Daemon
	dirs  daemon.Dirs
	key   ed25519.PrivateKey
	bind  *binding.Signed
	clk   *clock
	mu    sync.Mutex
	inbox []got
	ups   []pipeline.Update
	upc   []string
	taps  atomic.Int32
	stop  context.CancelFunc
	done  chan error
	bot   func(n *pipeNode, in pipeline.Inbound)
}

type nodeOpts struct {
	noList    bool          // do not give the daemon a revocation list
	listAge   time.Duration // how old the list it is given was when issued
	noBinding bool          // do not record the daemon's own binding
	prepare   func(dirs daemon.Dirs)
	noBot     bool
	// realDirectory leaves Deps.Directory unset, so the daemon finds peers through the gateway's endpoint.
	realDirectory bool
	testBot       bool   // run the daemon's built-in test bot instead of the test's own bot
	owner         string // the owner its binding names (default: <id>@acme.test)
	deny          func(owner string) bool
	methods       map[string]localsock.Method // extra local socket methods, registered before the daemon runs
	botCfg        *daemon.BotConfig           // run the configured bot (its approval gate and tools) instead of the test's own bot
	log           io.Writer                   // the daemon's log (default: discarded)
}

func (g *pipeGW) shortDir() string {
	base := os.TempDir()
	if runtime.GOOS != "windows" {
		base = "/tmp" // a unix socket path must stay short
	}
	d, err := os.MkdirTemp(base, "pd")
	if err != nil {
		g.t.Fatal(err)
	}
	g.t.Cleanup(func() { os.RemoveAll(d) })
	return filepath.Join(d, "p")
}

// start builds and runs a daemon enrolled in the gateway's tenant. It returns the daemon's construction error
// instead of failing, for tests that corrupt its state first.
func (g *pipeGW) start(id string, o nodeOpts) (*pipeNode, error) {
	t := g.t
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	owner := id + "@acme.test"
	if o.owner != "" {
		owner = o.owner
	}
	b, err := binding.Sign(g.rootKey, binding.Binding{Tenant: pipeTenant, Owner: owner, DeviceID: id, SigningKey: pub, Version: 1, NotAfter: time.Now().Add(binding.Lifetime / 2)})
	if err != nil {
		t.Fatal(err)
	}
	g.mu.Lock()
	g.devs[id] = &pipeDev{id: id, key: key, bind: b}
	g.mu.Unlock()
	n := &pipeNode{t: t, id: id, key: key, bind: b, clk: &clock{}, done: make(chan error, 1)}
	n.dirs = daemon.Dirs{Config: g.shortDir()}
	n.dirs.State = n.dirs.Config
	if o.prepare != nil {
		if err := os.MkdirAll(n.dirs.State, 0o700); err != nil {
			t.Fatal(err)
		}
		o.prepare(n.dirs)
	}
	cfg := daemon.Config{Format: 1, Tenant: pipeTenant, DeviceID: id, GatewayURL: g.srv.URL, RootPublicKey: g.rootPub(), KeyStore: daemon.KeyStoreFile, DisableTestBot: !o.testBot, Bot: o.botCfg}
	logw := o.log
	if logw == nil {
		logw = io.Discard
	}
	deps := daemon.Deps{Log: logx.New(logw), Harden: func() error { return nil }, Keys: memKeys{key}, MinBackoff: time.Millisecond,
		ShutdownTimeout: 5 * time.Second, Now: n.clk.now, Directory: g.directory, AllowUnlockedMemory: true,
		OnEvent: func(tunnel.Event) { n.taps.Add(1) },
		OnUpdate: func(u pipeline.Update) {
			u.Content = bytes.Clone(u.Content)
			n.mu.Lock()
			n.ups = append(n.ups, u)
			n.upc = append(n.upc, string(u.Content))
			n.mu.Unlock()
		}}
	if o.realDirectory {
		deps.Directory = nil
	}
	if !o.noBot && !o.testBot && o.botCfg == nil {
		deps.Allow = func(owner string) bool { return o.deny == nil || !o.deny(owner) }
		deps.OnInbound = func(in pipeline.Inbound) {
			rec := got{Type: in.Type, Task: in.TaskID, Caller: in.Caller, Owner: in.Owner, Content: string(in.Content)}
			n.mu.Lock()
			n.inbox = append(n.inbox, rec)
			bot := n.bot
			n.mu.Unlock()
			if bot != nil {
				cp := in
				cp.Content = bytes.Clone(in.Content)
				go bot(n, cp)
			}
		}
	}
	d, err := daemon.New(cfg, n.dirs, deps)
	if err != nil {
		return nil, err
	}
	n.d = d
	for name, m := range o.methods {
		d.Handle(name, m)
	}
	if !o.noBinding {
		if err := d.Trust().Tracker.Accept(b, n.clk.now()); err != nil {
			t.Fatal(err)
		}
	}
	if !o.noList {
		l, err := revocation.Next(g.rootKey, pipeTenant, nil, nil, n.clk.now().Add(-o.listAge))
		if err != nil {
			t.Fatal(err)
		}
		if err := d.Trust().Guard.Accept(l, n.clk.now()); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	n.stop = cancel
	go func() { n.done <- d.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-n.done })
	if !o.noBinding {
		g.waitFor("the tunnel of "+id, func() bool { g.mu.Lock(); defer g.mu.Unlock(); return g.conns[id] != nil })
	}
	return n, nil
}

func (g *pipeGW) startOK(id string, o nodeOpts) *pipeNode {
	g.t.Helper()
	n, err := g.start(id, o)
	if err != nil {
		g.t.Fatal(err)
	}
	return n
}

func (g *pipeGW) waitFor(what string, cond func() bool) {
	g.t.Helper()
	for i := 0; i < 1500; i++ {
		if cond() {
			return
		}
		time.Sleep(4 * time.Millisecond)
	}
	g.t.Fatalf("timed out waiting for %s", what)
}

func (n *pipeNode) node() *pipeline.Node {
	n.t.Helper()
	p, err := n.d.Node()
	if err != nil {
		n.t.Fatal(err)
	}
	return p
}

func (n *pipeNode) inboxLen() int  { n.mu.Lock(); defer n.mu.Unlock(); return len(n.inbox) }
func (n *pipeNode) updateLen() int { n.mu.Lock(); defer n.mu.Unlock(); return len(n.ups) }

// submit queues a task and waits for sending to finish.
func (n *pipeNode) submit(to, content string) ([16]byte, outbox.Status) {
	n.t.Helper()
	p := n.node()
	id, err := p.Submit(pipeline.Request{Target: to, Content: []byte(content), Expiry: n.clk.now().Add(10 * time.Minute)})
	if err != nil {
		n.t.Fatal(err)
	}
	select {
	case <-p.Done(id):
	case <-time.After(20 * time.Second):
		n.t.Fatal("sending never finished")
	}
	st, _ := p.Status(id)
	return id, st
}

// The plan's central claim for the message path, end to end through real daemons: tasks sent by one reach the
// other's bot after verify, open, erase, ack; the bot's replies come back; none is lost or run twice; and the
// gateway never sees anything readable.
func TestDaemonProcessesTunnelEvents(t *testing.T) {
	g := newPipeGW(t)
	alice := g.startOK("alice", nodeOpts{})
	bob := g.startOK("bob", nodeOpts{})
	bob.bot = func(n *pipeNode, in pipeline.Inbound) {
		p := n.node()
		_ = p.Respond(context.Background(), in.TaskID, envelope.TypeStatus, []byte("working on "+string(in.Content)))
		_ = p.Respond(context.Background(), in.TaskID, envelope.TypeResult, []byte("echo "+string(in.Content)))
	}

	const batches, perBatch = 5, 4
	var canaries []string
	ids := map[[16]byte]string{}
	var idMu sync.Mutex
	for b := 0; b < batches; b++ {
		var wg sync.WaitGroup
		for i := 0; i < perBatch; i++ {
			c := fmt.Sprintf("CANARY-%d-%d-%x", b, i, randBytes(8))
			canaries = append(canaries, c)
			wg.Add(1)
			go func() {
				defer wg.Done()
				id, st := alice.submit("bob", c)
				if st.State != outbox.Sent {
					t.Errorf("task not sent: %+v", st)
				}
				idMu.Lock()
				ids[id] = c
				idMu.Unlock()
			}()
		}
		wg.Wait()
		// A caller's reply key is held until the final reply, and a target issues at most 8 unused prekeys per caller:
		// the next batch starts when this one is finished, however slow the machine is.
		want := (b + 1) * perBatch
		g.waitFor("the batch's results", func() bool { alice.mu.Lock(); defer alice.mu.Unlock(); return finals(alice.ups) == want })
	}
	g.waitFor("every result", func() bool { alice.mu.Lock(); defer alice.mu.Unlock(); return finals(alice.ups) == batches*perBatch })

	bob.mu.Lock()
	defer bob.mu.Unlock()
	if len(bob.inbox) != len(canaries) {
		t.Fatalf("the bot was given %d tasks, want %d: something was dropped or run twice", len(bob.inbox), len(canaries))
	}
	seen := map[string]bool{}
	for _, in := range bob.inbox {
		if in.Type != envelope.TypeTask || in.Caller != "alice" || in.Owner != "alice@acme.test" || seen[in.Content] {
			t.Fatalf("bad delivery %+v", in)
		}
		seen[in.Content] = true
	}
	for _, c := range canaries {
		if !seen[c] {
			t.Fatalf("task %q never reached the bot", c)
		}
	}
	alice.mu.Lock()
	defer alice.mu.Unlock()
	results := map[string]bool{}
	for _, u := range alice.ups {
		if u.Type == envelope.TypeResult {
			results[string(u.Content)] = true
		}
	}
	for _, c := range canaries {
		if !results["echo "+c] {
			t.Fatalf("no result for %q", c)
		}
	}
	// The pipeline saw every event the tunnel pushed (the tap runs first), and the gateway never held a readable byte.
	if bob.taps.Load() < int32(len(canaries)) || alice.taps.Load() < int32(len(canaries)) {
		t.Fatalf("taps: bob %d alice %d", bob.taps.Load(), alice.taps.Load())
	}
	all := g.everything()
	for _, c := range canaries {
		if bytes.Contains(all, []byte(c)) || bytes.Contains(all, []byte("echo "+c)) {
			t.Fatalf("task content crossed the gateway in the clear: %q", c)
		}
	}
	if bytes.Contains(all, []byte("working on")) {
		t.Fatal("status text crossed the gateway in the clear")
	}
}

func finals(ups []pipeline.Update) int {
	n := 0
	for _, u := range ups {
		if u.Type == envelope.TypeResult {
			n++
		}
	}
	return n
}

func randBytes(n int) []byte { b := make([]byte, n); rand.Read(b); return b }

// Hostile events pushed at a running daemon (a replay of a delivered task, junk, a message for someone else, a
// forged prekey answer) change nothing, run nothing twice, and leave the daemon serving.
func TestDaemonSurvivesHostileEvents(t *testing.T) {
	g := newPipeGW(t)
	alice := g.startOK("alice", nodeOpts{})
	bob := g.startOK("bob", nodeOpts{})
	if _, st := alice.submit("bob", "first"); st.State != outbox.Sent {
		t.Fatalf("%+v", st)
	}
	g.waitFor("the task", func() bool { return bob.inboxLen() == 1 })
	g.mu.Lock()
	captured := bytes.Clone(g.wires[0])
	g.mu.Unlock()

	forged := mutateWire(t, captured, func(m *envelope.Message) { m.Ciphertext[0] ^= 1 })
	for _, ev := range []string{
		aEvent(captured), aEvent(captured), aEvent(forged), aEvent([]byte("junk")), "not json", `{}`, `{"t":"prekey_reply","id":"zzz","from":"alice","prekey":"AAAA"}`,
		`{"t":"prekey_request","id":"r","from":"nobody","nonce":"AAAA","expires_at":1}`, strings.Repeat("x", 100000),
	} {
		g.push("bob", ev)
	}
	time.Sleep(200 * time.Millisecond)
	if bob.inboxLen() != 1 {
		t.Fatalf("the bot ran %d times for one task", bob.inboxLen())
	}
	// Still serving.
	if _, st := alice.submit("bob", "second"); st.State != outbox.Sent {
		t.Fatalf("%+v", st)
	}
	g.waitFor("the second task", func() bool { return bob.inboxLen() == 2 })
}

func mutateWire(t *testing.T, wire []byte, f func(m *envelope.Message)) []byte {
	t.Helper()
	m, err := envelope.Unmarshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	f(m)
	return m.Marshal()
}

// A daemon with no fresh trust state sends nothing: not a prekey request, not a partial frame, not a message. The
// checks are the shipped ones (trust.Daemon over binding.Tracker and revocation.Guard, with their file stores), so a
// test that passed with a re-implemented check would prove nothing; each case also shows the daemon sends again once
// the state is good.
func TestDaemonRefusesToSendWithoutFreshTrustState(t *testing.T) {
	type tc struct {
		name  string
		opts  nodeOpts
		setup func(g *pipeGW, a *pipeNode)
		want  error
	}
	revoke := func(g *pipeGW, a *pipeNode, ids ...string) {
		l, err := revocation.Sign(g.rootKey, revocation.List{Tenant: pipeTenant, Version: 2, IssuedAt: a.clk.now(), Revoked: ids})
		if err != nil {
			t.Fatal(err)
		}
		if err := a.d.Trust().Guard.Accept(l, a.clk.now()); err != nil {
			t.Fatal(err)
		}
	}
	cases := []tc{
		{"no revocation list yet", nodeOpts{noList: true}, nil, revocation.ErrNoList},
		{"the list is older than the refusal age", nodeOpts{listAge: 15 * 24 * time.Hour}, nil, revocation.ErrStale},
		{"the list revokes the recipient", nodeOpts{}, func(g *pipeGW, a *pipeNode) { revoke(g, a, "bob") }, revocation.ErrRevoked},
		{"the list revokes this device", nodeOpts{}, func(g *pipeGW, a *pipeNode) { revoke(g, a, "alice") }, revocation.ErrRevoked},
		{"the binding store cannot be written", nodeOpts{}, func(g *pipeGW, a *pipeNode) {
			// The tracker must record the recipient's binding durably before using it. Replace the store with a
			// directory, which no OS lets it write.
			p := filepath.Join(a.dirs.State, "bindings.json")
			os.Remove(p)
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
		}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := newPipeGW(t)
			bob := g.startOK("bob", nodeOpts{})
			alice := g.startOK("alice", c.opts)
			if c.setup != nil {
				c.setup(g, alice)
			}
			relayed, a2a := g.relayed.Load(), g.a2a.Load()
			_, st := alice.submit("bob", "SECRET-TASK")
			if st.State != outbox.Failed || (c.want != nil && !errors.Is(st.Err, c.want)) {
				t.Fatalf("status %+v, want a failure with %v", st, c.want)
			}
			if g.relayed.Load() != relayed || g.a2a.Load() != a2a || bob.inboxLen() != 0 {
				t.Fatalf("the daemon sent something: %d prekey frames, %d a2a calls", g.relayed.Load()-relayed, g.a2a.Load()-a2a)
			}
			if bytes.Contains(g.everything(), []byte("SECRET-TASK")) {
				t.Fatal("content reached the gateway")
			}
			// The state is fixed: a fresh valid list (and a writable store) and the same daemon sends.
			if c.name == "the binding store cannot be written" {
				p := filepath.Join(alice.dirs.State, "bindings.json")
				os.Remove(p)
			}
			if c.want != nil && c.want != revocation.ErrRevoked {
				l, err := revocation.Sign(g.rootKey, revocation.List{Tenant: pipeTenant, Version: 3, IssuedAt: alice.clk.now()})
				if err != nil {
					t.Fatal(err)
				}
				if err := alice.d.Trust().Guard.Accept(l, alice.clk.now()); err != nil {
					t.Fatal(err)
				}
			}
			if c.want == revocation.ErrRevoked {
				return // revocation is permanent: a revoked device enrolls again under a new id
			}
			if _, st := alice.submit("bob", "again"); st.State != outbox.Sent {
				t.Fatalf("after the state was fixed: %+v", st)
			}
			g.waitFor("the task", func() bool { return bob.inboxLen() == 1 })
		})
	}
}

// Stores that are corrupt when the daemon starts stop it before it opens a connection at all.
func TestDaemonDoesNotStartOnCorruptTrustState(t *testing.T) {
	for _, file := range []string{"bindings.json", "revocations.json"} {
		t.Run(file, func(t *testing.T) {
			g := newPipeGW(t)
			_, err := g.start("alice", nodeOpts{prepare: func(d daemon.Dirs) {
				if err := os.WriteFile(filepath.Join(d.State, file), []byte("{not json"), 0o600); err != nil {
					t.Fatal(err)
				}
			}})
			if err == nil {
				t.Fatal("started on corrupt state")
			}
			if g.opens.Load() != 0 || g.relayed.Load() != 0 || g.a2a.Load() != 0 {
				t.Fatal("a daemon with corrupt trust state talked to the gateway")
			}
		})
	}
}

// A daemon that has no binding of its own has nothing to prove and nothing to send with.
func TestDaemonWithoutABindingHasNoPipeline(t *testing.T) {
	g := newPipeGW(t)
	a := g.startOK("alice", nodeOpts{noBinding: true})
	if _, err := a.d.Node(); !errors.Is(err, daemon.ErrNotEnrolled) {
		t.Fatalf("%v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if g.opens.Load() != 0 {
		t.Fatal("an unenrolled daemon opened a tunnel")
	}
}

// A daemon that runs no bot refuses to be a target: its callers are told at the prekey request, before any task
// is sealed, rather than a task being accepted, erased and dropped.
func TestDaemonWithoutABotRefusesPrekeyRequests(t *testing.T) {
	g := newPipeGW(t)
	g.startOK("bob", nodeOpts{noBot: true})
	alice := g.startOK("alice", nodeOpts{})
	_, st := alice.submit("bob", "x")
	if st.State != outbox.Failed || !errors.Is(st.Err, pipeline.ErrRefused) {
		t.Fatalf("%+v", st)
	}
	if g.a2a.Load() != 0 {
		t.Fatal("a task was sent to a daemon with no bot")
	}
}

// The owner's allowlist is the target's own decision, made on the root-signed binding.
func TestDaemonAllowlistIsEnforcedByTheTarget(t *testing.T) {
	g := newPipeGW(t)
	bob := g.startOK("bob", nodeOpts{deny: func(owner string) bool { return owner == "alice@acme.test" }})
	alice := g.startOK("alice", nodeOpts{})
	carol := g.startOK("carol", nodeOpts{})
	if _, st := alice.submit("bob", "x"); st.State != outbox.Failed || !errors.Is(st.Err, pipeline.ErrRefused) {
		t.Fatalf("%+v", st)
	}
	if _, st := carol.submit("bob", "y"); st.State != outbox.Sent {
		t.Fatalf("%+v", st)
	}
	g.waitFor("carol's task", func() bool { return bob.inboxLen() == 1 })
}
