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
	return &Updater{Key: r.pub, Source: r.src, Current: current, Pin: pin, Dir: r.dir,
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
	r.publish(t, "v1.1.0", true, r.key, "parley release v1.1.0", newBins("v1.1.0"))
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
	r.publish(t, "v1.1.0", true, other, "parley release v1.1.0", newBins("evil"))
	_, err := r.updater("v1.0.0", "").Update(context.Background())
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("got %v", err)
	}
	if r.read(t, "parleyd") != "old parleyd" {
		t.Fatal("binary changed")
	}
	// The same key id with different key material is rejected too.
	other.ID = r.key.ID
	r.publish(t, "v1.1.0", true, other, "parley release v1.1.0", newBins("evil"))
	if _, err := r.updater("v1.0.0", "").Update(context.Background()); !errors.Is(err, ErrSignature) {
		t.Fatalf("got %v", err)
	}
}

// A signature over other content (a different SHA256SUMS) does not authorize these checksums.
func TestUpdateRejectsTamperedChecksums(t *testing.T) {
	r := newRelease(t)
	r.publish(t, "v1.1.0", true, r.key, "parley release v1.1.0", newBins("v1.1.0"))
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
	r.publish(t, "v1.1.0", true, r.key, "parley release v1.1.0", newBins("v1.1.0"))
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
	r.publish(t, "v1.0.5", true, r.key, "parley release v1.0.5", newBins("v1.0.5"))
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
	// Comments that are not exactly "parley release vX.Y.Z".
	for _, c := range []string{"parley release 1.1.0", "parley release v1.1.0 ", "release v1.1.0", "parley release v1.1", "x", "parley release v01.1.0"} {
		r.publish(t, "v1.1.0", true, r.key, c, newBins("x"))
		if _, err := r.updater("v1.0.0", "").Check(context.Background()); !errors.Is(err, ErrSignature) {
			t.Fatalf("comment %q: got %v", c, err)
		}
	}
}

// Auto-update never goes backwards; only an explicit pin may select an older version.
func TestUpdateNeverDowngradesButPinMay(t *testing.T) {
	r := newRelease(t)
	r.publish(t, "v1.0.0", true, r.key, "parley release v1.0.0", newBins("v1.0.0"))
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
	r.publish(t, "v1.0.0", false, r.key, "parley release v1.0.0", newBins("v1.0.0"))
	r.publish(t, "v2.0.0", true, r.key, "parley release v2.0.0", newBins("v2.0.0"))
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
		sig, _ := r.key.Sign([]byte(body), "parley release v1.1.0")
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
	r.publish(t, "v1.1.0", true, r.key, "parley release v1.1.0", newBins("v1.1.0"))
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
	r.publish(t, "v1.1.0", true, r.key, "parley release v1.1.0", map[string]string{"parleyd": "daemon v1.1.0"})
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
	r.publish(t, "v1.1.0", true, r.key, "parley release v1.1.0", newBins("v1.1.0"))
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
	r.publish(t, "v1.1.0", true, r.key, "parley release v1.1.0", newBins("v1.1.0"))
	if _, err := r.updater("v1.0.0", "").Update(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestLoopReportsAndStops(t *testing.T) {
	r := newRelease(t)
	r.publish(t, "v1.1.0", true, r.key, "parley release v1.1.0", newBins("v1.1.0"))
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
	r.publish(t, "v1.0.0", true, r.key, "parley release v1.0.0", newBins("v1.0.0"))
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
	r.publish(t, "v1.1.0", true, r.key, "parley release v1.1.0", newBins("v1.1.0"))
	u := r.updater("v1.0.0", "")
	u.Names = []string{"parleyd", "absent", "parley-cli"}
	if _, err := u.Update(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.read(t, "parley-cli") != "cli v1.1.0" {
		t.Fatal("the binary after the missing one was not updated")
	}
}
