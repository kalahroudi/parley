// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package acceptance

// T406 (spike 7): a bot the daemon starts cannot approve its own tasks, and hostile inputs (a bot's output, a local
// client, an MCP client) stay within limits. The scenarios run against a real daemon and its real socket, the real CLI
// adapter, the real MCP server and real child processes.
//
// What a bot is up against, in layers, each attacked from a real child process below:
//
//  1. No terminal. The owner's confirmation is read from the controlling terminal only (internal/ttyconfirm); a bot is
//     started in a session of its own, so it has none, and a daemon that has a terminal does not pass it on.
//  2. The daemon knows who is calling. For approve and deny it reads the pid of the process at the other end of the
//     socket from the kernel and refuses any process that belongs to a bot it started (internal/botproc): the bot, its
//     children, its children in another process group, and on Windows everything in its job object.
//  3. A bot is handed no socket path, no descriptor and none of the daemon's environment, and the socket is in a
//     directory only the owner can enter.
//
// What this does not close, and the README says so: a process of the same OS user that Parley did not start (it is not
// in any bot's tree), or a bot's descendant that leaves its session and process group and loses its parent, is not
// recognised, and a process that makes itself a pseudo-terminal can type "yes" on it. Only an operating-system
// sandbox covers those; the profiles are in docs/sandbox and the macOS one is run against the daemon's socket below.

import (
	"bytes"
	"context"
	"encoding/hex"
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
	"github.com/kalahroudi/parley/internal/approval"
	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/fsperm"
	"github.com/kalahroudi/parley/internal/localsock"
	"github.com/kalahroudi/parley/internal/mcp"
	"github.com/kalahroudi/parley/internal/ttyconfirm"
	"github.com/kalahroudi/parley/internal/ttyconfirm/ttydev"
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
	case "dial": // connects to the socket it is told about, as any process of the daemon's user can
		out := "connected"
		c, err := net.Dial("unix", os.Getenv("PARLEY_T406_SOCK"))
		if err != nil {
			out = "refused"
		} else {
			c.Close()
		}
		adaptertest.WriteLine(os.Stdout, adaptertest.OutLine{Type: "result", Content: []byte(out)})
	case "attack": // the strongest local attacker: it knows where the socket and the waiting task are
		b, _ := json.Marshal(attack())
		if os.Getenv("PARLEY_T406_RAW") != "" { // run by another attacker, which relays it
			os.Stdout.Write(b)
			return
		}
		adaptertest.WriteLine(os.Stdout, adaptertest.OutLine{Type: "result", Content: b})
	case "attack-child", "attack-group": // the same, from a child (in a process group of its own for the second), relayed
		exe, _ := os.Executable()
		c := exec.Command(exe)
		c.Env = append(os.Environ(), t406Env+"=attack", "PARLEY_T406_RAW=1")
		childAttrs(c, mode == "attack-group")
		out, _ := c.Output()
		adaptertest.WriteLine(os.Stdout, adaptertest.OutLine{Type: "result", Content: bytes.TrimSpace(out)})
	case "tty": // asks the owner's terminal, if it has one
		out := "error: "
		if ok, err := ttyconfirm.Ask(""); err != nil {
			out += err.Error()
		} else {
			out = fmt.Sprint("answered ", ok)
		}
		adaptertest.WriteLine(os.Stdout, adaptertest.OutLine{Type: "result", Content: []byte(out)})
	case "host": // a daemon that has a terminal: starts a bot through the CLI adapter and reports what it saw
		exe, _ := os.Executable()
		_, closeTTY, ttyErr := ttydev.Open()
		if ttyErr == nil {
			closeTTY()
		}
		cli, _ := adapter.NewCLI(adapter.CLIConfig{Command: exe, Dir: os.TempDir(), Env: []string{t406Env + "=tty"}})
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		res, err := cli.Handle(ctx, t406Task, &countSession{})
		b, _ := json.Marshal(hostReport{HostHasTerminal: ttyErr == nil, Bot: string(res), Failed: err != nil})
		os.WriteFile(os.Getenv("PARLEY_T406_OUT"), b, 0o600)
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

type hostReport struct {
	HostHasTerminal bool
	Bot             string
	Failed          bool
}

// attackReport is what a bot managed against the daemon's socket.
type attackReport struct {
	Status  bool   // it could use the socket at all (the control: the refusals below are not a broken connection)
	TTY     string // what asking the owner's terminal gave it
	Approve string // what the daemon answered to approve: "served" or the error code
	Deny    string
}

func attack() attackReport {
	sock, id := os.Getenv("PARLEY_T406_SOCK"), os.Getenv("PARLEY_T406_TASK")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var r attackReport
	if resp, err := localsock.Call(ctx, sock, "status", nil); err == nil && resp.OK {
		r.Status = true
	}
	if ok, err := ttyconfirm.Ask(""); err != nil {
		r.TTY = err.Error()
	} else {
		r.TTY = fmt.Sprint("answered ", ok)
	}
	outcome := func(method string) string {
		resp, err := localsock.Call(ctx, sock, method, approval.DecideParams{TaskID: id})
		switch {
		case err != nil:
			return "unreachable"
		case resp.OK:
			return "served"
		}
		return resp.Error
	}
	r.Approve, r.Deny = outcome("approve"), outcome("deny")
	return r
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
	g := newPipeGW(t)
	n := g.startOK("sbx2", nodeOpts{})
	sock := n.dirs.SocketPath()
	dir := filepath.Dir(sock)
	// On every platform the directory passes the same check the daemon makes at each start (owner-only mode on
	// Unix, a protected DACL for the current user, SYSTEM and Administrators on Windows).
	if err := fsperm.CheckDir(dir); err != nil {
		t.Errorf("the socket directory is not private: %v", err)
	}
	if runtime.GOOS == "windows" {
		return // the Unix modes below do not exist there; the peer-check gap is pinned by TestPending_WindowsDaemonPeerRestriction
	}
	si, err := os.Stat(sock)
	if err != nil || si.Mode().Perm() != 0o600 || si.Mode()&os.ModeSocket == 0 {
		t.Errorf("socket: %v %v", si, err)
	}
	di, err := os.Stat(dir)
	if err != nil || di.Mode().Perm() != 0o700 {
		t.Errorf("socket directory: %v %v", di, err)
	}
	// The check is not vacuous: a directory open to others is refused.
	open := t.TempDir()
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if fsperm.CheckDir(open) == nil {
		t.Error("fsperm accepted a world-readable directory")
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

// heldBot is the bot behind the approval gate: it counts the tasks that reached it.
type heldBot struct{ ran atomic.Int32 }

func (b *heldBot) Handle(context.Context, bot.Task, bot.Session) ([]byte, error) {
	b.ran.Add(1)
	return []byte("ran"), nil
}

// A bot the daemon started cannot approve or deny the tasks that wait for its owner: not by asking the terminal, not
// by calling the socket (which it was told the path of, to give the attack its best chance), not from a child, not
// from a child in another process group. The same calls from the owner's own process are served, so the refusals are
// the guard's and not a broken socket. Removing the registration of bots, the pid check or the terminal rule makes this fail.
func TestBotsStartedByTheDaemonCannotApproveTheirOwnTasks(t *testing.T) {
	held := &heldBot{}
	gate, err := approval.New(approval.Config{Bot: held, Mode: approval.Owner})
	if err != nil {
		t.Fatal(err)
	}
	g := newPipeGW(t)
	n := g.startOK("sbx6", nodeOpts{methods: gate.Methods()})
	sock := n.dirs.SocketPath()
	waiting := bot.Task{ID: [16]byte{0x40, 0x06, 1}, Context: "c", Caller: "bob1", Owner: "bob@acme.test", Content: []byte("rm -rf the project")}
	id := hex.EncodeToString(waiting.ID[:])
	ended := make(chan error, 1)
	go func() { _, err := gate.Handle(context.Background(), waiting, &countSession{}); ended <- err }()
	g.waitFor("the task to wait for approval", func() bool { return len(gate.List()) == 1 })

	for _, mode := range []string{"attack", "attack-child", "attack-group"} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		res, err := t406CLI(t, mode, t.TempDir(), "PARLEY_T406_SOCK="+sock, "PARLEY_T406_TASK="+id).Handle(ctx, t406Task, &countSession{})
		cancel()
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		var rep attackReport
		if err := json.Unmarshal(res, &rep); err != nil {
			t.Fatalf("%s: %q: %v", mode, res, err)
		}
		if !rep.Status {
			t.Errorf("%s: the bot could not use the socket at all, so its refusals prove nothing: %+v", mode, rep)
		}
		if rep.TTY != ttyconfirm.ErrNoTerminal.Error() {
			t.Errorf("%s: asking the owner's terminal gave the bot %q", mode, rep.TTY)
		}
		if rep.Approve != localsock.CodeNotPermitted || rep.Deny != localsock.CodeNotPermitted {
			t.Errorf("%s: approve answered %q, deny answered %q, want %q for both", mode, rep.Approve, rep.Deny, localsock.CodeNotPermitted)
		}
		if held.ran.Load() != 0 || len(gate.List()) != 1 {
			t.Fatalf("%s: the task was decided by a bot (ran %d, waiting %d)", mode, held.ran.Load(), len(gate.List()))
		}
	}

	// The owner's own process is served, and the task then runs.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	r, err := localsock.Call(ctx, sock, "approve", approval.DecideParams{TaskID: id})
	if err != nil || !r.OK {
		t.Fatalf("the owner's own approval was refused: %+v %v", r, err)
	}
	if err := <-ended; err != nil || held.ran.Load() != 1 {
		t.Errorf("after the owner approved: %v, ran %d", err, held.ran.Load())
	}
}
