// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package acceptance

// T406 (spike 7): what a bot is given of the local socket, and what hostile inputs
// (a bot's output, a local client, an MCP client) can make the daemon do. The
// scenarios run against a real daemon and its real socket, the real CLI adapter and
// the real MCP server.
//
// What this proves and what it does not. A bot started by the CLI adapter is given
// no path, no descriptor and no environment that leads to the daemon's socket, and
// the socket refuses other OS users. A bot is still a process of the same OS user:
// if it guesses the socket's location it can connect, because the socket is not a
// boundary against the user's own processes (see internal/localsock). Closing that
// needs an operating-system sandbox, which does not exist yet (T507); the named
// pending test at the end of this file fails once T507 is ticked.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/adapter"
	"github.com/kalahroudi/parley/internal/adapter/adaptertest"
	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/localsock"
	"github.com/kalahroudi/parley/internal/mcp"
)

const t406Env = "PARLEY_T406_BOT"

// TestMain lets this test binary play the hostile bots the CLI adapter runs: the
// adapter starts os.Args[0] with PARLEY_T406_BOT=<mode> as its whole environment.
func TestMain(m *testing.M) {
	if mode := os.Getenv(t406Env); mode != "" {
		t406Bot(mode)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func t406Bot(mode string) {
	switch mode {
	case "probe": // reports everything it was given
		cwd, _ := os.Getwd()
		var env []string
		for _, e := range os.Environ() {
			if !strings.EqualFold(strings.SplitN(e, "=", 2)[0], "SYSTEMROOT") { // Windows adds it to every command
				env = append(env, e)
			}
		}
		b, _ := json.Marshal(probeReport{Env: env, Args: os.Args[1:], Cwd: cwd, Sockets: openSockets()})
		adaptertest.WriteLine(os.Stdout, adaptertest.OutLine{Type: "result", Content: b})
	case "noline": // endless output without a newline
		buf := []byte(strings.Repeat("A", 1<<16))
		for {
			if _, err := os.Stdout.Write(buf); err != nil {
				return
			}
		}
	case "huge": // one well-formed result line, far past the limit
		os.Stdout.Write([]byte(`{"type":"result","content":"` + strings.Repeat("A", 4*adapter.MaxLine) + `"}` + "\n"))
		time.Sleep(time.Minute)
	case "flood": // status lines for ever
		for {
			if _, err := os.Stdout.Write([]byte(`{"type":"status","content":"cw=="}` + "\n")); err != nil {
				return
			}
		}
	case "spawn": // a grandchild that keeps writing a heartbeat, then a bot that never answers
		exe, _ := os.Executable()
		child := exec.Command(exe)
		child.Env = []string{t406Env + "=beat", "PARLEY_BEAT=" + os.Getenv("PARLEY_BEAT")}
		child.Start()
		time.Sleep(time.Minute)
	case "beat":
		f, _ := os.OpenFile(os.Getenv("PARLEY_BEAT"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		for {
			f.Write([]byte("."))
			time.Sleep(10 * time.Millisecond)
		}
	}
}

type probeReport struct {
	Env     []string
	Args    []string
	Cwd     string
	Sockets []int
}

// session is the bot's side channel as the adapters see it; it counts what a bot sends.
type countSession struct{ statuses atomic.Int64 }

func (s *countSession) Status(context.Context, []byte) error { s.statuses.Add(1); return nil }
func (s *countSession) Ask(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("no one to ask")
}

func t406CLI(t *testing.T, mode, dir string, extra ...string) *adapter.CLI {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	c, err := adapter.NewCLI(adapter.CLIConfig{Command: exe, Dir: dir, Env: append([]string{t406Env + "=" + mode}, extra...)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var t406Task = bot.Task{ID: [16]byte{4, 6}, Context: "c", Caller: "alice1", Owner: "alice@acme.test", Content: []byte("hello")}

// A bot run by the daemon is handed nothing that leads to the daemon's socket:
// not its path (arguments, environment, working directory), not a descriptor, and
// none of the daemon's own environment.
func TestSandboxedBotIsGivenNoWayToTheLocalSocket(t *testing.T) {
	g := newPipeGW(t)
	n := g.startOK("sbx1", nodeOpts{})
	sock := n.dirs.SocketPath()
	t.Setenv("PARLEY_SOCKET", sock) // the daemon's own environment: it must not reach the bot
	t.Setenv("PARLEY_SOCKET_DIR", n.dirs.State)

	// Control: the socket is live and this process (the daemon's user) can use it, so
	// the absence below is not an artifact of a dead daemon.
	if r, err := localsock.Call(context.Background(), sock, "status", nil); err != nil || !r.OK {
		t.Fatalf("the daemon's socket is not serving: %+v %v", r, err)
	}

	work := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := t406CLI(t, "probe", work).Handle(ctx, t406Task, &countSession{})
	if err != nil {
		t.Fatal(err)
	}
	var rep probeReport
	if err := json.Unmarshal(res, &rep); err != nil {
		t.Fatalf("%q: %v", res, err)
	}
	if len(rep.Env) != 1 || rep.Env[0] != t406Env+"=probe" {
		t.Errorf("the bot's environment is not exactly the configured one: %q", rep.Env)
	}
	if len(rep.Args) != 0 {
		t.Errorf("arguments the configuration did not list: %q", rep.Args)
	}
	if want, _ := filepath.EvalSymlinks(work); rep.Cwd != work && rep.Cwd != want {
		t.Errorf("working directory %q is not the configured %q", rep.Cwd, work)
	}
	if len(rep.Sockets) != 0 {
		t.Errorf("the bot inherited socket descriptors %v", rep.Sockets)
	}
	for _, leak := range []string{sock, filepath.Dir(sock), n.dirs.State, n.dirs.Config} {
		if bytes.Contains(res, []byte(leak)) {
			t.Errorf("the bot was told %q", leak)
		}
	}
	if strings.Contains(rep.Cwd, filepath.Dir(sock)) {
		t.Error("the bot runs inside the daemon's state directory")
	}
}

// The socket and its directory are closed to other OS users on a real daemon (the
// kernel-attested uid check is in internal/localsock's tests).
func TestDaemonSocketIsClosedToOtherUsers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows uses a protected-DACL directory; its limits are pinned by TestPending_WindowsDaemonPeerRestriction")
	}
	g := newPipeGW(t)
	n := g.startOK("sbx2", nodeOpts{})
	sock := n.dirs.SocketPath()
	si, err := os.Stat(sock)
	if err != nil || si.Mode().Perm() != 0o600 || si.Mode()&os.ModeSocket == 0 {
		t.Errorf("socket: %v %v", si, err)
	}
	di, err := os.Stat(filepath.Dir(sock))
	if err != nil || di.Mode().Perm() != 0o700 {
		t.Errorf("socket directory: %v %v", di, err)
	}
}

// A local client that sends too much, nests too deep, speaks nonsense or opens
// more connections than allowed gets a refusal or a closed connection; the daemon
// keeps serving, and the goroutines of the abusive connections are gone.
func TestHostileLocalClientsStayWithinLimits(t *testing.T) {
	g := newPipeGW(t)
	n := g.startOK("sbx3", nodeOpts{})
	sock := n.dirs.SocketPath()
	healthy := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for {
			r, err := localsock.Call(ctx, sock, "status", nil)
			if err == nil && r.OK {
				return nil
			}
			if ctx.Err() != nil {
				return fmt.Errorf("daemon stopped serving: %+v %v", r, err)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	if err := healthy(); err != nil {
		t.Fatal(err)
	}
	baseline := runtime.NumGoroutine()

	send := func(payload []byte) string {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		go c.Write(payload) // the daemon may answer and close before it has read it all
		var r localsock.Response
		if json.NewDecoder(c).Decode(&r) != nil {
			return "closed"
		}
		return r.Error
	}
	for name, payload := range map[string][]byte{
		"a request past the limit":       []byte(`{"method":"status","params":"` + strings.Repeat("A", 300<<10) + `"}`),
		"JSON nested a hundred thousand": append(bytes.Repeat([]byte("["), 100_000), '\n'),
		"not JSON":                       []byte("GET / HTTP/1.1\r\n\r\n"),
		"a method that does not exist":   []byte(`{"method":"` + strings.Repeat("m", 4096) + `"}`),
		"a binary blob":                  bytes.Repeat([]byte{0xff, 0x00, 0x80}, 50_000),
	} {
		if got := send(payload); got == "" {
			t.Errorf("%s was answered as a success", name)
		}
	}

	// Far more connections than the daemon's limit, all silent: at most the limit are held, the rest are closed
	// at once, and a well-behaved client gets in as soon as the abusers leave.
	const attackers = 80
	conns := make([]net.Conn, attackers)
	for i := range conns {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		conns[i] = c
	}
	time.Sleep(300 * time.Millisecond)
	var held, closed atomic.Int32
	var wg sync.WaitGroup
	for _, c := range conns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
			if _, err := c.Read(make([]byte, 1)); errors.Is(err, os.ErrDeadlineExceeded) {
				held.Add(1)
			} else {
				closed.Add(1)
			}
		}()
	}
	wg.Wait()
	if held.Load() > 32 || closed.Load() < attackers-32 {
		t.Errorf("the daemon held %d of %d silent connections (limit 32), closed %d", held.Load(), attackers, closed.Load())
	}
	for _, c := range conns {
		c.Close()
	}
	if err := healthy(); err != nil {
		t.Fatal(err)
	}
	g.waitFor("the abusive connections' goroutines to end", func() bool { return runtime.NumGoroutine() <= baseline+4 })
}

// heapGrowth runs f and returns how much live heap it left behind.
func heapGrowth(f func()) uint64 {
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	f()
	runtime.GC()
	runtime.ReadMemStats(&b)
	if b.HeapAlloc < a.HeapAlloc {
		return 0
	}
	return b.HeapAlloc - a.HeapAlloc
}

// A bot that floods, never ends a line, sends a result past the limit, or leaves
// a child behind is stopped; nothing it says reaches the caller as an error text,
// memory stays bounded and nothing it started outlives the task.
func TestHostileBotOutputStaysWithinLimits(t *testing.T) {
	work := t.TempDir()
	run := func(mode string, s *countSession, extra ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err := t406CLI(t, mode, work, extra...).Handle(ctx, t406Task, s)
		return err
	}
	const capBytes = 64 << 20
	for _, mode := range []string{"noline", "huge", "flood"} {
		s := &countSession{}
		var err error
		start := time.Now()
		grew := heapGrowth(func() { err = run(mode, s) })
		if err == nil {
			t.Errorf("%s: the task did not fail", mode)
		}
		if grew > capBytes {
			t.Errorf("%s: %d MiB of heap kept after the task", mode, grew>>20)
		}
		if d := time.Since(start); d > 20*time.Second {
			t.Errorf("%s: took %v to stop", mode, d)
		}
		if err != nil && (strings.Contains(err.Error(), "AAAA") || strings.Contains(err.Error(), "cw==")) {
			t.Errorf("%s: the bot's output reached the error text", mode)
		}
		if mode == "flood" && s.statuses.Load() > adapter.MaxStatuses {
			t.Errorf("flood: %d statuses forwarded, limit %d", s.statuses.Load(), adapter.MaxStatuses)
		}
	}

	// A grandchild must die with the task, whether the task ended by deadline or by the bot's own finish.
	beat := filepath.Join(t.TempDir(), "beat")
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	if _, err := t406CLI(t, "spawn", work, "PARLEY_BEAT="+beat).Handle(ctx, t406Task, &countSession{}); err == nil {
		t.Fatal("a bot that never answers did not fail at the deadline")
	}
	size := func() int64 {
		fi, err := os.Stat(beat)
		if err != nil {
			return 0
		}
		return fi.Size()
	}
	time.Sleep(200 * time.Millisecond) // let a stray write land
	after := size()
	if after == 0 {
		t.Fatal("the grandchild never started, so containment was not tested")
	}
	time.Sleep(500 * time.Millisecond)
	if size() != after {
		t.Error("a process the bot started kept running after the task ended")
	}
}

// An MCP client that sends an endless line, oversize arguments or a burst of tool
// calls is held to the server's limits against a real daemon: no more than
// MaxConcurrent calls reach the socket at once, every call is answered, and an
// over-long line ends the session.
func TestHostileMCPClientStaysWithinLimits(t *testing.T) {
	g := newPipeGW(t)
	n := g.startOK("sbx4", nodeOpts{})
	sock := n.dirs.SocketPath()
	var live, peak, reached atomic.Int32
	srv := &mcp.Server{Call: func(ctx context.Context, method string, params any) (localsock.Response, error) {
		reached.Add(1)
		cur := live.Add(1)
		defer live.Add(-1)
		for {
			p := peak.Load()
			if cur <= p || peak.CompareAndSwap(p, cur) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond) // overlap the burst
		return localsock.Call(ctx, sock, method, params)
	}}
	var in bytes.Buffer
	const burst = 100
	for i := 0; i < burst; i++ {
		fmt.Fprintf(&in, `{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"list_tasks","arguments":{}}}`+"\n", i)
	}
	big := `{"jsonrpc":"2.0","id":"big","method":"tools/call","params":{"name":"send_task","arguments":{"text":"` + strings.Repeat("A", mcp.MaxArguments) + `"}}}`
	in.WriteString(big + "\n")
	var out syncBuf
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := srv.Serve(ctx, &in, &out); err != nil {
		t.Fatalf("a burst of valid calls ended the session: %v", err)
	}
	answered := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var r struct {
			ID    json.RawMessage `json:"id"`
			Error *struct{ Code int }
		}
		if json.Unmarshal([]byte(l), &r) != nil {
			t.Fatalf("a reply that is not JSON: %.80q", l)
		}
		answered[string(r.ID)] = r.Error != nil
	}
	if len(answered) != burst+1 {
		t.Errorf("%d of %d calls were answered", len(answered), burst+1)
	}
	if !answered[`"big"`] {
		t.Error("arguments past the limit were not refused")
	}
	if peak.Load() > mcp.MaxConcurrent {
		t.Errorf("%d tool calls ran at once (limit %d)", peak.Load(), mcp.MaxConcurrent)
	}
	if reached.Load() != burst {
		t.Errorf("%d calls reached the daemon, want %d (the oversize one must not)", reached.Load(), burst)
	}

	// A line that never ends is cut at MaxMessage: the session ends with ErrTooLong, and the daemon is unharmed.
	endless := strings.NewReader(`{"jsonrpc":"2.0","method":"` + strings.Repeat("A", mcp.MaxMessage+1))
	if err := srv.Serve(ctx, endless, &syncBuf{}); !errors.Is(err, mcp.ErrTooLong) {
		t.Errorf("an over-long line: %v", err)
	}
	if r, err := localsock.Call(ctx, sock, "status", nil); err != nil || !r.OK {
		t.Errorf("the daemon stopped serving: %+v %v", r, err)
	}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func TestPending_SandboxKeepsToolUsingSkillsAwayFromTheSocket(t *testing.T) {
	pending(t, "T507", "a bot of the same OS user can connect to the control socket if it guesses where it is, and can approve its own tasks. When tool-using skills get an operating-system sandbox, assert from inside it that connecting to the daemon's socket (unix path, abstract name, and a descriptor-less guess of the default location) fails, that the sandbox cannot be escaped through the approval command, and that Windows refuses to run tool-using skills until a sandbox exists")
}
