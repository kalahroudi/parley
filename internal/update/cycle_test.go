// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package update

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/fsperm"
)

func (r *testRelease) path(name string) string {
	return filepath.Join(r.dir, name+exeSuffix(runtime.GOOS))
}

func (r *testRelease) entries(t *testing.T) []string { return mustReadDir(t, r.dir) }

func TestCycleInstallsOnlyWhenAskedTo(t *testing.T) {
	r := newRelease(t)
	r.publish(t, "v1.1.0", true, r.key, cm("v1.1.0"), newBins("v1.1.0"))
	u := r.updater("v1.0.0", "")
	st := u.Cycle(context.Background(), false)
	if st.State != StateAvailable || st.Available != "v1.1.0" || st.Current != "v1.0.0" || st.Code != "" || st.CheckedAt != testNow.Unix() {
		t.Fatalf("check: %+v", st)
	}
	if r.read(t, "parleyd") != "old parleyd" {
		t.Fatal("a check installed something")
	}
	st = u.Cycle(context.Background(), true)
	if st.State != StateInstalled || st.Available != "v1.1.0" {
		t.Fatalf("install: %+v", st)
	}
	if r.read(t, "parleyd") != "daemon v1.1.0" || len(r.entries(t)) != 2 {
		t.Fatalf("not installed cleanly: %v", r.entries(t))
	}
	u.Current = "v1.1.0"
	if st = u.Cycle(context.Background(), true); st.State != StateUpToDate || st.Available != "" {
		t.Fatalf("up to date: %+v", st)
	}
}

// Nothing is installed from a feed that does not verify, whatever the mode: the install step is only reachable
// through a verified release.
func TestCycleNeverInstallsWhatDoesNotVerify(t *testing.T) {
	ctx := context.Background()
	r := newRelease(t)
	other, _, _ := newKey(t)
	cases := []struct {
		name, code string
		publish    func()
	}{
		{"signed by another key", "signature", func() { r.publish(t, "v1.1.0", true, other, cm("v1.1.0"), newBins("evil")) }},
		{"expired", "expired", func() {
			r.publish(t, "v1.1.0", true, r.key, FormatComment(Version{1, 1, 0}, testNow.Add(-48*time.Hour), testNow.Add(-time.Hour)), newBins("evil"))
		}},
		{"not yet valid", "not_yet", func() {
			r.publish(t, "v1.1.0", true, r.key, FormatComment(Version{1, 1, 0}, testNow.Add(time.Hour), testNow.Add(48*time.Hour)), newBins("evil"))
		}},
	}
	for _, c := range cases {
		c.publish()
		for _, install := range []bool{false, true} {
			st := r.updater("v1.0.0", "").Cycle(ctx, install)
			if st.State != StateError || st.Code != c.code || st.Available != "" {
				t.Errorf("%s install=%v: %+v", c.name, install, st)
			}
		}
		if r.read(t, "parleyd") != "old parleyd" || r.read(t, "parley-cli") != "old parley-cli" {
			t.Errorf("%s: a program changed", c.name)
		}
	}
	// A source that is down is a plain failure.
	r.src.err = errors.New("down")
	if st := r.updater("v1.0.0", "").Cycle(ctx, true); st.State != StateError || st.Code != "failed" {
		t.Fatalf("down: %+v", st)
	}
}

func TestCycleReportsInstallFailureWithoutAvailable(t *testing.T) {
	r := newRelease(t)
	r.publish(t, "v1.1.0", true, r.key, cm("v1.1.0"), newBins("v1.1.0"))
	u := r.updater("v1.0.0", "")
	u.Names = []string{"parleyd", "missing-from-release", "parley-cli"}
	os.WriteFile(r.path("missing-from-release"), []byte("x"), 0o755)
	st := u.Cycle(context.Background(), true)
	if st.State != StateError || st.Code != "failed" || st.Available != "" {
		t.Fatalf("%+v", st)
	}
	if r.read(t, "parleyd") != "old parleyd" {
		t.Fatal("changed")
	}
}

func TestCycleRefusesWhenNotOwnerAndWhenNotARelease(t *testing.T) {
	r := newRelease(t)
	r.publish(t, "v1.1.0", true, r.key, cm("v1.1.0"), newBins("v1.1.0"))
	u := r.updater("v1.0.0", "")
	u.inspect = notOurs
	if st := u.Cycle(context.Background(), true); st.State != StateError || st.Code != "not_owner" {
		t.Fatalf("%+v", st)
	}
	if st := r.updater("dev", "").Cycle(context.Background(), true); st.Code != "not_release" {
		t.Fatalf("%+v", st)
	}
	if st := r.updater("v1.0.0", "bad").Cycle(context.Background(), true); st.Code != "pin" {
		t.Fatalf("%+v", st)
	}
}

// Two updaters never run at once: the second finds the lock taken and does nothing.
func TestCycleHoldsTheLock(t *testing.T) {
	r := newRelease(t)
	r.publish(t, "v1.1.0", true, r.key, cm("v1.1.0"), newBins("v1.1.0"))
	lock := filepath.Join(t.TempDir(), "update.lock")
	release, err := fsperm.Lock(lock)
	if err != nil {
		t.Fatal(err)
	}
	u := r.updater("v1.0.0", "")
	u.LockPath = lock
	asked := len(r.src.asked)
	if st := u.Cycle(context.Background(), true); st.State != StateError || st.Code != "busy" {
		t.Fatalf("%+v", st)
	}
	if len(r.src.asked) != asked || r.read(t, "parleyd") != "old parleyd" {
		t.Fatal("worked while another update held the lock")
	}
	release()
	if st := u.Cycle(context.Background(), true); st.State != StateInstalled {
		t.Fatalf("after release: %+v", st)
	}
	if _, err := os.Stat(lock); err != nil { // the lock file stays; only the lock is released
		t.Fatal(err)
	}
}

// Restart safety. The journal and the ".old" files tell what a crash left; Recover puts the old programs back.
func TestRecoverAfterEachInterruptionPoint(t *testing.T) {
	ext := exeSuffix(runtime.GOOS)
	setup := func(t *testing.T) *testRelease {
		r := newRelease(t)
		os.WriteFile(filepath.Join(r.dir, ".parley-update-123"), []byte("staged"), 0o600)
		return r
	}
	journal := func(r *testRelease, names ...string) {
		os.WriteFile(filepath.Join(r.dir, journalName), []byte(strings.Join(names, "\n")+"\n"), 0o600)
	}
	cases := map[string]func(r *testRelease){
		"journal written, no rename yet": func(r *testRelease) { journal(r, "parleyd"+ext, "parley-cli"+ext) },
		"first program moved aside, new one not in place": func(r *testRelease) {
			journal(r, "parleyd"+ext, "parley-cli"+ext)
			os.Rename(r.path("parleyd"), r.path("parleyd")+".old")
		},
		"first swapped, second untouched": func(r *testRelease) {
			journal(r, "parleyd"+ext, "parley-cli"+ext)
			os.Rename(r.path("parleyd"), r.path("parleyd")+".old")
			os.WriteFile(r.path("parleyd"), []byte("NEW daemon"), 0o755)
		},
		"all swapped, journal not yet removed": func(r *testRelease) {
			journal(r, "parleyd"+ext, "parley-cli"+ext)
			for _, n := range []string{"parleyd", "parley-cli"} {
				os.Rename(r.path(n), r.path(n)+".old")
				os.WriteFile(r.path(n), []byte("NEW "+n), 0o755)
			}
		},
	}
	for name, crash := range cases {
		r := setup(t)
		crash(r)
		if err := r.updater("v1.0.0", "").Recover(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if r.read(t, "parleyd") != "old parleyd" || r.read(t, "parley-cli") != "old parley-cli" {
			t.Errorf("%s: programs are %q and %q", name, r.read(t, "parleyd"), r.read(t, "parley-cli"))
		}
		if got := r.entries(t); len(got) != 2 {
			t.Errorf("%s: leftovers %v", name, got)
		}
		if err := r.updater("v1.0.0", "").Recover(); err != nil { // idempotent
			t.Errorf("%s: second Recover: %v", name, err)
		}
	}
}

// Without a journal the programs are not touched: a finished update's ".old" files (a running program's, on
// Windows) are only cleaned up, and staged downloads are removed.
func TestRecoverWithoutJournalKeepsPrograms(t *testing.T) {
	r := newRelease(t)
	os.WriteFile(r.path("parleyd"), []byte("NEW daemon"), 0o755)
	os.WriteFile(r.path("parleyd")+".old", []byte("old"), 0o755)
	os.WriteFile(filepath.Join(r.dir, ".parley-update-9"), nil, 0o600)
	if err := r.updater("v1.0.0", "").Recover(); err != nil {
		t.Fatal(err)
	}
	if r.read(t, "parleyd") != "NEW daemon" || len(r.entries(t)) != 2 {
		t.Fatalf("%q %v", r.read(t, "parleyd"), r.entries(t))
	}
}

// A journal naming something that is not one of our programs changes nothing but the journal itself.
func TestRecoverIgnoresForeignNamesInJournal(t *testing.T) {
	r := newRelease(t)
	victim := filepath.Join(r.dir, "victim")
	os.WriteFile(victim, []byte("mine"), 0o755)
	os.WriteFile(victim+".old", []byte("other"), 0o755)
	os.WriteFile(filepath.Join(r.dir, journalName), []byte("victim\n../escape\n\nparleyd"+exeSuffix(runtime.GOOS)+"\n"), 0o600)
	// A real interrupted swap is listed after the foreign names and is still repaired.
	os.Rename(r.path("parleyd"), r.path("parleyd")+".old")
	if err := r.updater("v1.0.0", "").Recover(); err != nil {
		t.Fatal(err)
	}
	if r.read(t, "parleyd") != "old parleyd" {
		t.Fatal("a foreign name stopped the repair of the real one")
	}
	if b, _ := os.ReadFile(victim); string(b) != "mine" {
		t.Fatalf("a foreign file was replaced: %q", b)
	}
	if _, err := os.Stat(filepath.Join(r.dir, journalName)); err == nil {
		t.Fatal("journal left")
	}
}

func TestRecoverErrors(t *testing.T) {
	r := newRelease(t)
	u := r.updater("v1.0.0", "")
	u.inspect = notOurs
	if err := u.Recover(); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("not owner: %v", err)
	}
	// An unreadable journal (a directory by that name) is an error, not a silent skip.
	os.Mkdir(filepath.Join(r.dir, journalName), 0o700)
	if err := r.updater("v1.0.0", "").Recover(); err == nil {
		t.Fatal("unreadable journal accepted")
	}
	os.Remove(filepath.Join(r.dir, journalName))
	// A journal that cannot be removed or an old program that cannot be restored is reported.
	os.WriteFile(filepath.Join(r.dir, journalName), []byte("parleyd"+exeSuffix(runtime.GOOS)+"\n"), 0o600)
	os.Remove(r.path("parleyd"))
	os.MkdirAll(filepath.Join(r.path("parleyd")+".old", "x"), 0o700) // a non-empty directory: nothing can replace it by rename onto a file path... and it cannot be moved over an existing dst
	os.MkdirAll(filepath.Join(r.path("parleyd"), "y"), 0o700)        // dst is a non-empty directory, so the rename onto it fails
	if err := r.updater("v1.0.0", "").Recover(); err == nil {
		t.Fatal("failed restore ignored")
	}
}

// A journal that cannot be written stops the update before any program is touched.
func TestApplyStopsWhenJournalCannotBeWritten(t *testing.T) {
	r := newRelease(t)
	r.publish(t, "v1.1.0", true, r.key, cm("v1.1.0"), newBins("v1.1.0"))
	u := r.updater("v1.0.0", "")
	rel, err := u.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	os.Mkdir(filepath.Join(r.dir, journalName), 0o700) // opening a directory for writing fails
	if err := u.Apply(context.Background(), rel); err == nil {
		t.Fatal("expected a failure")
	}
	if r.read(t, "parleyd") != "old parleyd" || r.read(t, "parley-cli") != "old parley-cli" {
		t.Fatal("changed")
	}
	for _, e := range r.entries(t) {
		if strings.HasPrefix(e, ".parley-update-") && e != journalName {
			t.Fatalf("staged file left: %s", e)
		}
	}
}

// A failed swap rolls back and leaves no journal behind.
func TestFailedSwapLeavesNoJournal(t *testing.T) {
	r := newRelease(t)
	r.publish(t, "v1.1.0", true, r.key, cm("v1.1.0"), newBins("v1.1.0"))
	os.MkdirAll(filepath.Join(r.path("parley-cli")+".old", "x"), 0o700)
	if _, err := r.updater("v1.0.0", "").Update(context.Background()); err == nil {
		t.Fatal("expected a failure")
	}
	if _, err := os.Stat(filepath.Join(r.dir, journalName)); err == nil {
		t.Fatal("journal left after rollback")
	}
	if r.read(t, "parleyd") != "old parleyd" {
		t.Fatal("not rolled back")
	}
}

func TestRunReportsEachCycleAndStops(t *testing.T) {
	r := newRelease(t)
	r.publish(t, "v1.1.0", true, r.key, cm("v1.1.0"), newBins("v1.1.0"))
	got := make(chan Status, 8)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	u := r.updater("v1.0.0", "")
	go func() {
		u.Run(ctx, time.Millisecond, 5*time.Millisecond, true, func(s Status) { got <- s })
		close(done)
	}()
	if first := <-got; first.State != StateInstalled {
		t.Fatalf("first: %+v", first)
	}
	r.src.mu.Lock()
	r.src.err = errors.New("down")
	r.src.mu.Unlock()
	var failed Status
	for failed.State != StateError {
		failed = <-got
	}
	if failed.Code != "failed" {
		t.Fatalf("%+v", failed)
	}
	cancel()
	<-done
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	n := len(r.src.asked)
	u.Run(ctx2, time.Hour, time.Hour, true, func(Status) { t.Error("reported after cancel") })
	if len(r.src.asked) != n {
		t.Fatal("checked after cancel")
	}
}

// The helper process for TestApplyReplacesARunningProgram: this test binary, copied to be the installed
// "parleyd", runs until its standard input closes.
func TestHelperRunUntilStdinCloses(t *testing.T) {
	if os.Getenv("PARLEY_UPDATE_TEST_HELPER") != "1" {
		return
	}
	buf := make([]byte, 1)
	os.Stdin.Read(buf)
}

// Windows: a running program is replaced by renaming it aside; the process keeps running and the next cycle
// removes the leftover once it has exited. Elsewhere the same flow must hold.
func TestApplyReplacesARunningProgram(t *testing.T) {
	r := newRelease(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.path("parleyd"), src, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(r.path("parleyd"), "-test.run=^TestHelperRunUntilStdinCloses$")
	cmd.Env = append(os.Environ(), "PARLEY_UPDATE_TEST_HELPER=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var exited atomic.Bool
	waited := make(chan struct{})
	go func() { cmd.Wait(); exited.Store(true); close(waited) }()
	t.Cleanup(func() { stdin.Close(); <-waited })

	r.publish(t, "v1.1.0", true, r.key, cm("v1.1.0"), newBins("v1.1.0"))
	st := r.updater("v1.0.0", "").Cycle(context.Background(), true)
	if st.State != StateInstalled {
		t.Fatalf("replace while running: %+v", st)
	}
	if r.read(t, "parleyd") != "daemon v1.1.0" {
		t.Fatalf("not replaced: %q", r.read(t, "parleyd")[:10])
	}
	time.Sleep(50 * time.Millisecond)
	if exited.Load() {
		t.Fatal("the running program was stopped by the update")
	}
	// Let it exit; the next cycle (here: Recover) clears whatever was left beside the new file.
	stdin.Close()
	<-waited
	if err := r.updater("v1.1.0", "").Recover(); err != nil {
		t.Fatal(err)
	}
	if got := r.entries(t); len(got) != 2 {
		t.Fatalf("leftovers after the program exited: %v", got)
	}
}

// The journal names exactly the programs about to be swapped, and Recover reads it back.
func TestJournalListsTheProgramsAboutToBeSwapped(t *testing.T) {
	r := newRelease(t)
	u := r.updater("v1.0.0", "")
	if err := u.writeJournal([]string{r.path("parleyd"), r.path("parley-cli")}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(r.dir, journalName))
	want := "parleyd" + exeSuffix(runtime.GOOS) + "\nparley-cli" + exeSuffix(runtime.GOOS) + "\n"
	if err != nil || string(b) != want {
		t.Fatalf("%q %v", b, err)
	}
	if fi, _ := os.Stat(filepath.Join(r.dir, journalName)); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
}
