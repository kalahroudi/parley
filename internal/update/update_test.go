// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/release"
)

// fakeSource serves assets by "<version or latest>/<name>" and records what was asked for.
type fakeSource struct {
	mu    sync.Mutex
	files map[string][]byte
	asked []string
	err   error
}

func (f *fakeSource) Fetch(_ context.Context, version, name string, limit int64, w io.Writer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if version == "" {
		version = "latest"
	}
	f.asked = append(f.asked, version+"/"+name)
	if f.err != nil {
		return f.err
	}
	b, ok := f.files[version+"/"+name]
	if !ok {
		return errors.New("not found")
	}
	if int64(len(b)) > limit {
		return errors.New("too large")
	}
	_, err := w.Write(b)
	return err
}

// testNow is the clock of every updater under test; cm gives a manifest header valid around it.
var testNow = time.Unix(1_800_000_000, 0)

func cm(v string) string {
	ver, _ := ParseVersion(v)
	return FormatComment(ver, testNow.Add(-time.Hour), testNow.Add(90*24*time.Hour))
}

type testRelease struct {
	key  release.SecretKey
	pub  release.PublicKey
	src  *fakeSource
	dir  string
	bins map[string][]byte
}

// publish signs a release of version for the test platform, with the given binary contents, and serves it
// under its version and (when latest) as the latest release.
func (r *testRelease) publish(t *testing.T, version string, latest bool, key release.SecretKey, comment string, bins map[string]string) {
	t.Helper()
	var sums bytes.Buffer
	files := map[string][]byte{}
	for name, body := range bins {
		asset := fmt.Sprintf("%s_%s_%s_%s%s", name, version, runtime.GOOS, runtime.GOARCH, exeSuffix(runtime.GOOS))
		sum := sha256.Sum256([]byte(body))
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(sum[:]), asset)
		files[version+"/"+asset] = []byte(body)
	}
	sig, err := key.Sign(sums.Bytes(), comment)
	if err != nil {
		t.Fatal(err)
	}
	files[version+"/SHA256SUMS"] = sums.Bytes()
	files[version+"/SHA256SUMS.minisig"] = sig
	for k, v := range files {
		r.src.files[k] = v
		if latest {
			r.src.files["latest/"+k[len(version)+1:]] = v
		}
	}
}

func newRelease(t *testing.T) *testRelease {
	t.Helper()
	sk, pk, err := release.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	r := &testRelease{key: sk, pub: pk, src: &fakeSource{files: map[string][]byte{}}, dir: dir}
	for _, n := range []string{"parleyd", "parley-cli"} {
		if err := os.WriteFile(filepath.Join(dir, n+exeSuffix(runtime.GOOS)), []byte("old "+n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func (r *testRelease) updater(current, pin string) *Updater {
	return &Updater{Now: func() time.Time { return testNow }, Key: r.pub, Source: r.src, Current: current, Pin: pin, Dir: r.dir,
		Names: []string{"parleyd", "parley-cli"}, OS: runtime.GOOS, Arch: runtime.GOARCH}
}

func (r *testRelease) read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(r.dir, name+exeSuffix(runtime.GOOS)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func newBins(v string) map[string]string {
	return map[string]string{"parleyd": "daemon " + v, "parley-cli": "cli " + v}
}

// JJ-01: an update signed by the pinned key is installed.
func TestJJ01UpdateInstallsReleaseSignedByPinnedKey(t *testing.T) {
	r := newRelease(t)
	r.publish(t, "v1.1.0", true, r.key, cm("v1.1.0"), newBins("v1.1.0"))
	v, err := r.updater("v1.0.0", "").Update(context.Background())
	if err != nil || v.String() != "v1.1.0" {
		t.Fatalf("update: %v %v", v, err)
	}
	if r.read(t, "parleyd") != "daemon v1.1.0" || r.read(t, "parley-cli") != "cli v1.1.0" {
		t.Fatal("binaries not replaced")
	}
	for _, n := range []string{"parleyd", "parley-cli"} {
		if _, err := os.Stat(filepath.Join(r.dir, n+exeSuffix(runtime.GOOS)+".old")); err == nil {
			t.Fatal("old file left behind")
		}
	}
	ents, _ := os.ReadDir(r.dir)
	if len(ents) != 2 {
		t.Fatalf("stray files: %v", ents)
	}
	if fi, _ := os.Stat(filepath.Join(r.dir, "parleyd"+exeSuffix(runtime.GOOS))); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v", fi.Mode())
	}
	// The binaries come from the verified version's own address, not from "latest", which may have moved on.
	for _, a := range r.src.asked[2:] {
		if !strings.HasPrefix(a, "v1.1.0/") {
			t.Fatalf("binary fetched from %s", a)
		}
	}
}

// JJ-01: a release signed by any other key is rejected and nothing is changed.
func TestJJ01UpdateRejectsOtherKeys(t *testing.T) {
	r := newRelease(t)
	other, _, _ := release.GenerateKey()
	r.publish(t, "v1.1.0", true, other, cm("v1.1.0"), newBins("evil"))
	_, err := r.updater("v1.0.0", "").Update(context.Background())
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("got %v", err)
	}
	if r.read(t, "parleyd") != "old parleyd" {
		t.Fatal("binary changed")
	}
	// The same key id with different key material is rejected too.
	other.ID = r.key.ID
	r.publish(t, "v1.1.0", true, other, cm("v1.1.0"), newBins("evil"))
	if _, err := r.updater("v1.0.0", "").Update(context.Background()); !errors.Is(err, ErrSignature) {
		t.Fatalf("got %v", err)
	}
}

// A signature over other content (a different SHA256SUMS) does not authorize these checksums.
func TestUpdateRejectsTamperedChecksums(t *testing.T) {
	r := newRelease(t)
	r.publish(t, "v1.1.0", true, r.key, cm("v1.1.0"), newBins("v1.1.0"))
	for _, p := range []string{"latest/", "v1.1.0/"} {
		r.src.files[p+"SHA256SUMS"] = append([]byte("0"), r.src.files[p+"SHA256SUMS"][1:]...)
	}
	if _, err := r.updater("v1.0.0", "").Update(context.Background()); !errors.Is(err, ErrSignature) {
		t.Fatalf("got %v", err)
	}
}

// A binary that does not match the signed checksum is never installed, and nothing is left half done.
func TestUpdateRejectsSwappedBinary(t *testing.T) {
	r := newRelease(t)
	r.publish(t, "v1.1.0", true, r.key, cm("v1.1.0"), newBins("v1.1.0"))
	asset := fmt.Sprintf("parley-cli_v1.1.0_%s_%s%s", runtime.GOOS, runtime.GOARCH, exeSuffix(runtime.GOOS))
	r.src.files["v1.1.0/"+asset] = []byte("malicious")
	_, err := r.updater("v1.0.0", "").Update(context.Background())
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("got %v", err)
	}
	if r.read(t, "parleyd") != "old parleyd" || r.read(t, "parley-cli") != "old parley-cli" {
		t.Fatal("a binary was replaced")
	}
	if ents, _ := os.ReadDir(r.dir); len(ents) != 2 {
		t.Fatalf("staged file left behind: %v", ents)
	}
}

// The signed comment names the version: an old signed release served as the latest one is not a new version,
// and one claiming a different version than the address asked for is refused.
func TestUpdateBindsChecksumsToVersion(t *testing.T) {
	r := newRelease(t)
	// v1.0.5's genuine files, offered as the latest release: not newer than what runs.
	r.publish(t, "v1.0.5", true, r.key, cm("v1.0.5"), newBins("v1.0.5"))
	if _, err := r.updater("v1.0.5", "").Check(context.Background()); !errors.Is(err, ErrUpToDate) {
		t.Fatalf("got %v", err)
	}
	// Signed for v1.0.5 but offered under the v9.9.9 address, when v9.9.9 is pinned.
	for k, v := range r.src.files {
		if strings.HasPrefix(k, "v1.0.5/") {
			r.src.files["v9.9.9/"+k[len("v1.0.5/"):]] = v
		}
	}
	if _, err := r.updater("v1.0.0", "v9.9.9").Check(context.Background()); !errors.Is(err, ErrSignature) {
		t.Fatalf("got %v", err)
	}
	// Comments that are not exactly the canonical manifest header.
	good := cm("v1.1.0")
	for _, c := range []string{"parley release v1.1.0", "parley release 1.1.0", good + " ", " " + good, "release" + good[len("parley release"):], strings.Replace(good, "v1.1.0", "v1.1", 1),
		"x", strings.Replace(good, "v1.1.0", "v01.1.0", 1), strings.Replace(good, "issued=", "issued=+", 1), strings.Replace(good, "issued=", "since=", 1),
		strings.Replace(good, "expires=", "until=", 1), good + " extra=1", strings.Replace(good, " expires=", "  expires=", 1),
		"parley release v1.1.0 expires=1807776000 issued=1799996400", "parley release v1.1.0 issued=-1 expires=1807776000", "parley release v1.1.0 issued=1799996400 expires=99999999999999", "parley release v1.1.0 issued=x expires=1807776000", "parley release v1.1.0 issued=1799996400 expires=x", "parley release v1.1.0 issued=1799996400 expires=1099511627777"} {
		r.publish(t, "v1.1.0", true, r.key, c, newBins("x"))
		if _, err := r.updater("v1.0.0", "").Check(context.Background()); !errors.Is(err, ErrSignature) {
			t.Fatalf("comment %q: got %v", c, err)
		}
	}
}

// Auto-update never goes backwards; only an explicit pin may select an older version.
func TestUpdateNeverDowngradesButPinMay(t *testing.T) {
	r := newRelease(t)
	r.publish(t, "v1.0.0", true, r.key, cm("v1.0.0"), newBins("v1.0.0"))
	if _, err := r.updater("v2.0.0", "").Update(context.Background()); !errors.Is(err, ErrUpToDate) {
		t.Fatalf("got %v", err)
	}
	if r.read(t, "parleyd") != "old parleyd" {
		t.Fatal("downgraded")
	}
	// Pin to the older version: installed.
	v, err := r.updater("v2.0.0", "1.0.0").Update(context.Background())
	if err != nil || v.String() != "v1.0.0" || r.read(t, "parleyd") != "daemon v1.0.0" {
		t.Fatalf("pin: %v %v", v, err)
	}
}

// JJ-01: pin-to-version holds. With a pin, a newer release is not installed, and the pinned version is the only
// one ever fetched; when it is already running there is nothing to do.
func TestJJ01PinToVersionHolds(t *testing.T) {
	r := newRelease(t)
	r.publish(t, "v1.0.0", false, r.key, cm("v1.0.0"), newBins("v1.0.0"))
	r.publish(t, "v2.0.0", true, r.key, cm("v2.0.0"), newBins("v2.0.0"))
	u := r.updater("v1.0.0", "v1.0.0")
	if _, err := u.Update(context.Background()); !errors.Is(err, ErrUpToDate) {
		t.Fatalf("got %v", err)
	}
	for _, a := range r.src.asked {
		if strings.HasPrefix(a, "latest/") || strings.HasPrefix(a, "v2.0.0/") {
			t.Fatalf("pinned updater asked for %s", a)
		}
	}
	if r.read(t, "parleyd") != "old parleyd" {
		t.Fatal("changed")
	}
	if _, err := r.updater("v1.0.0", "v1.x").Check(context.Background()); !errors.Is(err, ErrVersion) {
		t.Fatalf("got %v", err)
	}
}

func TestUpdateNotARelease(t *testing.T) {
	r := newRelease(t)
	for _, cur := range []string{"dev", "", "v1.2.3-rc1", "(devel)"} {
		if _, err := r.updater(cur, "").Check(context.Background()); !errors.Is(err, ErrNotRelease) {
			t.Fatalf("%q: %v", cur, err)
		}
	}
}

func TestUpdateSourceErrorsAndMalformedSums(t *testing.T) {
	r := newRelease(t)
	r.src.err = errors.New("down")
	if _, err := r.updater("v1.0.0", "").Check(context.Background()); err == nil {
		t.Fatal("source error ignored")
	}
	r.src.err = nil
	// Sums present, signature missing.
	r.src.files["latest/SHA256SUMS"] = []byte("x")
	if _, err := r.updater("v1.0.0", "").Check(context.Background()); err == nil {
		t.Fatal("missing signature ignored")
	}
	// Validly signed but malformed bodies are refused, whoever signed them.
	for _, body := range []string{"", "abc  parleyd\n", strings.Repeat("g", 64) + "  parleyd\n", strings.Repeat("A", 64) + "  parleyd\n",
		strings.Repeat("a", 64) + "  ../parleyd\n", strings.Repeat("a", 64) + "  \n", strings.Repeat("a", 64) + " parleyd\n",
		strings.Repeat("a", 64) + "  a\\b\n", "ab  parleyd\n", strings.Repeat("a", 66) + "  parleyd\n",
		strings.Repeat("a", 64) + "  parleyd\n" + strings.Repeat("a", 64) + "  parleyd\n"} {
		sig, _ := r.key.Sign([]byte(body), cm("v1.1.0"))
		r.src.files["latest/SHA256SUMS"] = []byte(body)
		r.src.files["latest/SHA256SUMS.minisig"] = sig
		if _, err := r.updater("v1.0.0", "").Check(context.Background()); !errors.Is(err, ErrSignature) {
			t.Fatalf("%q: %v", body, err)
		}
	}
}

func TestApplyFailures(t *testing.T) {
	ctx := context.Background()
	// The required binary is not installed in Dir.
	r := newRelease(t)
	r.publish(t, "v1.1.0", true, r.key, cm("v1.1.0"), newBins("v1.1.0"))
	rel, err := r.updater("v1.0.0", "").Check(ctx)
	if err != nil {
		t.Fatal(err)
	}
	u := r.updater("v1.0.0", "")
	u.Dir = t.TempDir()
	if err := u.Apply(ctx, rel); err == nil {
		t.Fatal("missing parleyd accepted")
	}
	// The temp directory cannot be created in (Dir is a file).
	u = r.updater("v1.0.0", "")
	f := filepath.Join(t.TempDir(), "file")
	os.WriteFile(f, nil, 0o600)
	u.Dir = f
	if err := u.Apply(ctx, rel); err == nil {
		t.Fatal("bad dir accepted")
	}
	// The staging file cannot be created.
	u = r.updater("v1.0.0", "")
	u.createTemp = func(string, string) (*os.File, error) { return nil, errors.New("read-only") }
	if err := u.Apply(ctx, rel); err == nil {
		t.Fatal("staging failure ignored")
	}
	// A binary missing from the signed checksums is refused (a release without this platform).
	u = r.updater("v1.0.0", "")
	u.Arch = "plan9" // an unpublished target; OS stays so the install file names match
	if err := u.Apply(ctx, rel); err == nil || !strings.Contains(err.Error(), "not in the signed checksums") {
		t.Fatalf("got %v", err)
	}
	// A download that fails.
	r.src.err = errors.New("down")
	if err := r.updater("v1.0.0", "").Apply(ctx, rel); err == nil {
		t.Fatal("download error ignored")
	}
	if ents, _ := os.ReadDir(r.dir); len(ents) != 2 {
		t.Fatalf("staged file left behind: %v", ents)
	}
}

// parley-cli is optional: a daemon installed without it is still updated.
func TestApplyWithoutOptionalBinary(t *testing.T) {
	r := newRelease(t)
	os.Remove(filepath.Join(r.dir, "parley-cli"+exeSuffix(runtime.GOOS)))
	r.publish(t, "v1.1.0", true, r.key, cm("v1.1.0"), map[string]string{"parleyd": "daemon v1.1.0"})
	if _, err := r.updater("v1.0.0", "").Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.read(t, "parleyd") != "daemon v1.1.0" {
		t.Fatal("not updated")
	}
	if _, err := os.Stat(filepath.Join(r.dir, "parley-cli"+exeSuffix(runtime.GOOS))); err == nil {
		t.Fatal("parley-cli created")
	}
}

// If one swap fails, the ones already done are put back: the two programs never end up on different versions.
func TestApplyRollsBackWhenASwapFails(t *testing.T) {
	r := newRelease(t)
	r.publish(t, "v1.1.0", true, r.key, cm("v1.1.0"), newBins("v1.1.0"))
	rel, err := r.updater("v1.0.0", "").Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// parley-cli.old is a non-empty directory, which cannot be removed or renamed over: the second swap fails
	// after the first has been done.
	cli := filepath.Join(r.dir, "parley-cli"+exeSuffix(runtime.GOOS))
	os.MkdirAll(filepath.Join(cli+".old", "x"), 0o755)
	if err := r.updater("v1.0.0", "").Apply(context.Background(), rel); err == nil {
		t.Fatal("expected a failure")
	}
	if r.read(t, "parleyd") != "old parleyd" {
		t.Fatal("parleyd not rolled back")
	}
	for _, e := range mustReadDir(t, r.dir) {
		if strings.HasPrefix(e, ".parley-update-") || (strings.HasSuffix(e, ".old") && !strings.HasPrefix(e, "parley-cli")) {
			t.Fatalf("leftover %s", e)
		}
	}
}

func mustReadDir(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// The final rename failing puts the old file back.
func TestSwapRestoresOldFileWhenStagedIsMissing(t *testing.T) {
	d := t.TempDir()
	dst := filepath.Join(d, "x")
	os.WriteFile(dst, []byte("old"), 0o755)
	if err := swap(dst, filepath.Join(d, "missing")); err == nil {
		t.Fatal("expected an error")
	}
	if b, _ := os.ReadFile(dst); string(b) != "old" {
		t.Fatalf("old file lost: %q", b)
	}
	if err := swap(filepath.Join(d, "absent"), dst); err == nil {
		t.Fatal("swap of a missing destination accepted")
	}
}

// A file left as <name>.old by an earlier swap does not block the next one.
func TestApplyReplacesStaleOldFile(t *testing.T) {
	r := newRelease(t)
	os.WriteFile(filepath.Join(r.dir, "parleyd"+exeSuffix(runtime.GOOS)+".old"), []byte("stale"), 0o600)
	r.publish(t, "v1.1.0", true, r.key, cm("v1.1.0"), newBins("v1.1.0"))
	if _, err := r.updater("v1.0.0", "").Update(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestLoopReportsAndStops(t *testing.T) {
	r := newRelease(t)
	r.publish(t, "v1.1.0", true, r.key, cm("v1.1.0"), newBins("v1.1.0"))
	type res struct {
		v   Version
		err error
	}
	got := make(chan res, 8)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	u := r.updater("v1.0.0", "")
	go func() {
		u.Loop(ctx, time.Millisecond, 5*time.Millisecond, func(v Version, err error) { got <- res{v, err} })
		close(done)
	}()
	first := <-got
	if first.err != nil || first.v.String() != "v1.1.0" {
		t.Fatalf("first: %+v", first)
	}
	// Later rounds: the running version is now old in this updater's eyes, so it installs again; make the
	// source fail to see an error reported, then up-to-date ones stay silent.
	r.src.mu.Lock()
	r.src.err = errors.New("down")
	r.src.mu.Unlock()
	second := <-got
	if second.err == nil {
		t.Fatalf("second: %+v", second)
	}
	cancel()
	<-done
	// Canceled before the first round: returns without a check.
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	n := len(r.src.asked)
	u.Loop(ctx2, time.Hour, time.Hour, func(Version, error) { t.Error("reported") })
	if len(r.src.asked) != n {
		t.Fatal("checked after cancel")
	}
}

func TestLoopStaysSilentWhenUpToDate(t *testing.T) {
	r := newRelease(t)
	r.publish(t, "v1.0.0", true, r.key, cm("v1.0.0"), newBins("v1.0.0"))
	ctx, cancel := context.WithCancel(context.Background())
	u := r.updater("v1.0.0", "")
	done := make(chan struct{})
	go func() {
		u.Loop(ctx, time.Millisecond, time.Millisecond, func(Version, error) { t.Error("reported") })
		close(done)
	}()
	for i := 0; i < 400; i++ {
		r.src.mu.Lock()
		n := len(r.src.asked)
		r.src.mu.Unlock()
		if n >= 6 { // at least three rounds ran
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
}

func TestExeSuffix(t *testing.T) {
	if exeSuffix("windows") != ".exe" || exeSuffix("linux") != "" || exeSuffix("darwin") != "" {
		t.Fatal("suffix")
	}
}

// An optional binary that is missing does not stop the ones after it in the list.
func TestApplySkipsMissingOptionalBinaryInTheMiddle(t *testing.T) {
	r := newRelease(t)
	r.publish(t, "v1.1.0", true, r.key, cm("v1.1.0"), newBins("v1.1.0"))
	u := r.updater("v1.0.0", "")
	u.Names = []string{"parleyd", "absent", "parley-cli"}
	if _, err := u.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.read(t, "parley-cli") != "cli v1.1.0" {
		t.Fatal("the binary after the missing one was not updated")
	}
}

// publishWindow publishes v1.1.0 as the latest release with a manifest valid from issued to expires.
func (r *testRelease) publishWindow(t *testing.T, issued, expires time.Time) {
	t.Helper()
	r.publish(t, "v1.1.0", true, r.key, FormatComment(Version{1, 1, 0}, issued, expires), newBins("v1.1.0"))
}

// A manifest past its expiry is refused, to the second: a frozen feed cannot keep serving it.
func TestUpdateRefusesExpiredManifest(t *testing.T) {
	r := newRelease(t)
	exp := testNow.Add(24 * time.Hour)
	r.publishWindow(t, testNow.Add(-time.Hour), exp)
	u := r.updater("v1.0.0", "")
	for name, at := range map[string]time.Time{"after": exp.Add(time.Second), "exactly": exp, "long after": exp.Add(1000 * time.Hour)} {
		u.Now = func() time.Time { return at }
		if _, err := u.Update(context.Background()); !errors.Is(err, ErrExpired) {
			t.Fatalf("%s: got %v", name, err)
		}
	}
	if r.read(t, "parleyd") != "old parleyd" {
		t.Fatal("installed from an expired manifest")
	}
	u.Now = func() time.Time { return exp.Add(-time.Second) }
	if _, err := u.Update(context.Background()); err != nil {
		t.Fatalf("one second before expiry: %v", err)
	}
}

// An expired manifest is refused even when it names the running version: that is how a stale feed is noticed.
func TestUpdateExpiredManifestOfTheRunningVersionIsReported(t *testing.T) {
	r := newRelease(t)
	r.publishWindow(t, testNow.Add(-48*time.Hour), testNow.Add(-time.Hour))
	if _, err := r.updater("v1.1.0", "").Check(context.Background()); !errors.Is(err, ErrExpired) {
		t.Fatalf("got %v", err)
	}
	// The pin path is held to the same window.
	if _, err := r.updater("v1.0.0", "v1.1.0").Check(context.Background()); !errors.Is(err, ErrExpired) {
		t.Fatalf("pinned: got %v", err)
	}
}

// A manifest issued in the future (beyond clock skew) is not valid yet; skew inside the tolerance is accepted.
func TestUpdateRefusesManifestNotYetValid(t *testing.T) {
	r := newRelease(t)
	r.publishWindow(t, testNow.Add(maxSkew+time.Second), testNow.Add(24*time.Hour))
	if _, err := r.updater("v1.0.0", "").Check(context.Background()); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("got %v", err)
	}
	r.publishWindow(t, testNow.Add(maxSkew), testNow.Add(24*time.Hour))
	if _, err := r.updater("v1.0.0", "").Check(context.Background()); err != nil {
		t.Fatalf("within skew: %v", err)
	}
}

// A window that is empty, backwards or longer than the maximum is malformed whoever signed it.
func TestUpdateRefusesUnreasonableWindows(t *testing.T) {
	r := newRelease(t)
	for name, w := range map[string][2]time.Time{
		"empty":    {testNow, testNow},
		"backward": {testNow, testNow.Add(-time.Hour)},
		"too long": {testNow.Add(-time.Hour), testNow.Add(-time.Hour).Add(maxValidity + time.Second)},
	} {
		r.publishWindow(t, w[0], w[1])
		if _, err := r.updater("v1.0.0", "").Check(context.Background()); !errors.Is(err, ErrSignature) {
			t.Fatalf("%s: got %v", name, err)
		}
	}
	r.publishWindow(t, testNow.Add(-time.Hour), testNow.Add(-time.Hour).Add(maxValidity))
	if _, err := r.updater("v1.0.0", "").Check(context.Background()); err != nil {
		t.Fatalf("longest allowed window: %v", err)
	}
}

// The validity window cannot be stretched by whoever serves the files: it is inside the signature.
func TestUpdateWindowIsCoveredBySignature(t *testing.T) {
	r := newRelease(t)
	soon := testNow.Add(time.Hour)
	r.publishWindow(t, testNow.Add(-time.Hour), soon)
	forged := strings.Replace(string(r.src.files["latest/SHA256SUMS.minisig"]), fmt.Sprintf("expires=%d", soon.Unix()), fmt.Sprintf("expires=%d", soon.Add(1000*time.Hour).Unix()), 1)
	r.src.files["latest/SHA256SUMS.minisig"] = []byte(forged)
	u := r.updater("v1.0.0", "")
	u.Now = func() time.Time { return soon.Add(time.Minute) }
	if _, err := u.Check(context.Background()); !errors.Is(err, ErrSignature) {
		t.Fatalf("got %v", err)
	}
}

// Versions only go forward: neither an older release nor a replay of the running one is installed by auto-update,
// even with a fresh manifest.
func TestUpdateVersionIsMonotonic(t *testing.T) {
	r := newRelease(t)
	r.publish(t, "v1.0.0", true, r.key, cm("v1.0.0"), newBins("v1.0.0"))
	for _, cur := range []string{"v1.0.0", "v1.0.1", "v1.1.0", "v2.0.0"} {
		if _, err := r.updater(cur, "").Check(context.Background()); !errors.Is(err, ErrUpToDate) {
			t.Fatalf("running %s: got %v", cur, err)
		}
	}
	if _, err := r.updater("v0.9.9", "").Check(context.Background()); err != nil {
		t.Fatalf("running older: %v", err)
	}
}

func TestParseCommentRoundTrip(t *testing.T) {
	m, err := ParseComment(FormatComment(Version{1, 2, 3}, time.Unix(100, 0), time.Unix(200, 0)))
	if err != nil || m.Version != (Version{1, 2, 3}) || m.Issued.Unix() != 100 || m.Expires.Unix() != 200 {
		t.Fatalf("%+v %v", m, err)
	}
	for _, edge := range []string{"parley release v1.2.3 issued=0 expires=1", "parley release v1.2.3 issued=1 expires=1099511627776"} { // the ends of the accepted range
		if _, err := ParseComment(edge); err != nil {
			t.Fatalf("%s: %v", edge, err)
		}
	}
	for _, bad := range []string{"parley release v1.2.3 issued=-1 expires=5", "parley release v1.2.3 issued=1 expires=1099511627777"} { // just outside it
		if _, err := ParseComment(bad); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
	if _, err := ParseComment("parley release v1.2.3 issued=0100 expires=200"); err == nil {
		t.Fatal("leading zero accepted")
	}
}

// Without a test clock the updater uses the real one.
func TestUpdateUsesTheRealClockByDefault(t *testing.T) {
	r := newRelease(t)
	r.publishWindow(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	u := r.updater("v1.0.0", "")
	u.Now = nil
	if _, err := u.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.publishWindow(t, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	if _, err := u.Check(context.Background()); !errors.Is(err, ErrExpired) {
		t.Fatalf("got %v", err)
	}
}

// scripts/release.sh writes this exact text (tests/release.test.mjs); the updater only accepts this spelling.
func TestFormatCommentIsThePublishedFormat(t *testing.T) {
	if got := FormatComment(Version{1, 2, 3}, time.Unix(1800000000, 0), time.Unix(1802592000, 0)); got != "parley release v1.2.3 issued=1800000000 expires=1802592000" {
		t.Fatal(got)
	}
}

// The window edges, to the millisecond: expiry is exclusive (no skew allowance, so a slow clock never extends a
// manifest past what was signed), and an issue time is accepted up to maxSkew ahead and refused one ms beyond it.
func TestUpdateWindowBoundariesToTheMillisecond(t *testing.T) {
	ms := time.Millisecond
	r := newRelease(t)
	exp := testNow.Add(24 * time.Hour)
	r.publishWindow(t, testNow.Add(-time.Hour), exp)
	u := r.updater("v1.0.0", "")
	for name, c := range map[string]struct {
		at   time.Time
		want error
	}{
		"1ms before expiry": {exp.Add(-ms), nil},
		"at expiry":         {exp, ErrExpired},
		"1ms after expiry":  {exp.Add(ms), ErrExpired},
	} {
		u.Now = func() time.Time { return c.at }
		if _, err := u.Check(context.Background()); !errors.Is(err, c.want) {
			t.Fatalf("%s: got %v, want %v", name, err, c.want)
		}
	}
	issued := testNow.Add(time.Hour)
	r.publishWindow(t, issued, issued.Add(24*time.Hour))
	for name, c := range map[string]struct {
		at   time.Time
		want error
	}{
		"1ms before the skew edge": {issued.Add(-maxSkew).Add(ms), nil},
		"at the skew edge":         {issued.Add(-maxSkew), nil},
		"1ms beyond the skew edge": {issued.Add(-maxSkew).Add(-ms), ErrNotYetValid},
	} {
		u.Now = func() time.Time { return c.at }
		if _, err := u.Check(context.Background()); !errors.Is(err, c.want) {
			t.Fatalf("%s: got %v, want %v", name, err, c.want)
		}
	}
}

// An expired manifest never installs, even when every binary matches its signed checksum.
func TestUpdateExpiredManifestInstallsNothingEvenWithMatchingHashes(t *testing.T) {
	r := newRelease(t)
	r.publishWindow(t, testNow.Add(-48*time.Hour), testNow.Add(-time.Hour))
	if _, err := r.updater("v1.0.0", "").Update(context.Background()); !errors.Is(err, ErrExpired) {
		t.Fatalf("got %v", err)
	}
	if r.read(t, "parleyd") != "old parleyd" || r.read(t, "parley-cli") != "old parley-cli" {
		t.Fatal("installed from an expired manifest")
	}
}

// The manifest is read only after its signature verifies: a forged, unsigned or foreign-key header yields
// ErrSignature and never ErrExpired/ErrNotYetValid/ErrUpToDate, whatever it claims.
func TestUpdateSignatureIsCheckedBeforeAnyManifestField(t *testing.T) {
	r := newRelease(t)
	other, _, _ := release.GenerateKey()
	r.publish(t, "v1.1.0", true, other, FormatComment(Version{1, 0, 0}, testNow.Add(-48*time.Hour), testNow.Add(-time.Hour)), newBins("x"))
	if _, err := r.updater("v1.0.0", "").Check(context.Background()); !errors.Is(err, ErrSignature) || errors.Is(err, ErrExpired) {
		t.Fatalf("got %v", err)
	}
}

// FuzzParseComment: the parser never panics, and what it accepts is exactly the canonical text, inside the
// timestamp bounds, so it round-trips.
func FuzzParseComment(f *testing.F) {
	f.Add("parley release v1.2.3 issued=1800000000 expires=1802592000")
	f.Add("parley release v1.2.3 issued=0 expires=1099511627776")
	f.Add("parley release v1.2.3 issued=+1 expires=2")
	f.Add("parley release v1.2.3 issued=01 expires=2")
	f.Add("parley release v1.2.3 issued=1 expires=2 ")
	f.Add("parley release v1.2.3 issued=1 expires=2\nparley release v9.9.9 issued=1 expires=2")
	f.Add("parley release v1.2.3 issued=-1 expires=99999999999999999999")
	f.Add("parley release v1.2.3  issued=1 expires=2")
	f.Add("parley release v1.2.3 expires=2 issued=1")
	f.Add("")
	f.Fuzz(func(t *testing.T, c string) {
		m, err := ParseComment(c)
		if err != nil {
			if !errors.Is(err, ErrSignature) {
				t.Fatalf("unexpected error kind: %v", err)
			}
			return
		}
		if FormatComment(m.Version, m.Issued, m.Expires) != c {
			t.Fatalf("accepted a non-canonical comment %q", c)
		}
		if m.Issued.Unix() < 0 || m.Issued.Unix() > maxUnix || m.Expires.Unix() < 0 || m.Expires.Unix() > maxUnix {
			t.Fatalf("timestamp out of bounds in %q", c)
		}
		if err := m.checkValidity(time.Unix(1_800_000_000, 0)); err != nil && !errors.Is(err, ErrSignature) && !errors.Is(err, ErrExpired) && !errors.Is(err, ErrNotYetValid) {
			t.Fatalf("unexpected validity error: %v", err)
		}
	})
}
