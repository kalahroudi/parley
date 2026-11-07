// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type sealed struct {
	ct   []byte
	sum  [HashSize]byte
	size uint64
}

// capBuffer is a destination for EncryptFile that refuses more than maxCiphertext bytes. A mutant of the chunk loop that
// never ends would otherwise write into memory without limit: the mutation run's runner dies of it before its time limit
// counts the mutant as killed (it did, on Linux). With the cap the encryption fails at once and the mutant is killed.
type capBuffer struct{ bytes.Buffer }

const maxCiphertext = 1 << 27

var errCapped = errors.New("test destination full")

func (c *capBuffer) Write(p []byte) (int, error) {
	if c.Len()+len(p) > maxCiphertext {
		return 0, errCapped
	}
	return c.Buffer.Write(p)
}

func encrypt(t testing.TB, key, pt []byte) sealed {
	t.Helper()
	var ct capBuffer
	sum, size, err := EncryptFile(key, bytes.NewReader(pt), &ct)
	if err != nil {
		t.Fatal(err)
	}
	return sealed{ct.Bytes(), sum, size}
}

func (s sealed) open(key []byte, ct []byte) error {
	return decryptFile(key, bytes.NewReader(ct), io.Discard, s.sum, s.size)
}

func fileKey(t testing.TB) []byte {
	t.Helper()
	k, err := NewFileKey()
	if err != nil {
		t.Fatal(err)
	}
	return k[:]
}

func TestFileBucket(t *testing.T) {
	for _, c := range []struct{ in, out uint64 }{
		{0, 4096}, {1, 4096}, {4096, 4096}, {4097, 8192}, {65536, 65536}, {65537, 131072},
		{MaxFileSize - 1, MaxFileSize}, {MaxFileSize, MaxFileSize},
	} {
		if got, err := FileBucket(c.in); err != nil || got != c.out {
			t.Errorf("FileBucket(%d) = %d, %v; want %d", c.in, got, err, c.out)
		}
	}
	if _, err := FileBucket(MaxFileSize + 1); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("got %v", err)
	}
}

func TestFileRoundTripSizes(t *testing.T) {
	key := fileKey(t)
	for _, n := range []int{0, 1, 4095, 4096, 4097, FileChunkSize - 1, FileChunkSize, FileChunkSize + 1, 3 * FileChunkSize, 3*FileChunkSize + 7, 5 * FileChunkSize} {
		pt := make([]byte, n)
		rand.Read(pt)
		s := encrypt(t, key, pt)
		bucket, _ := FileBucket(uint64(n))
		chunks := (bucket + FileChunkSize - 1) / FileChunkSize
		if want := bucket + chunks*gcmTag; uint64(len(s.ct)) != want {
			t.Fatalf("n=%d: ciphertext %d, want %d", n, len(s.ct), want)
		}
		if s.sum != sha256.Sum256(pt) || s.size != uint64(n) {
			t.Fatalf("n=%d: wrong hash or size %d", n, s.size)
		}
		var out bytes.Buffer
		if err := decryptFile(key, bytes.NewReader(s.ct), &out, s.sum, s.size); err != nil || !bytes.Equal(out.Bytes(), pt) {
			t.Fatalf("n=%d: %v", n, err)
		}
	}
}

// Files in the same bucket are indistinguishable by object size.
func TestFileSizeHiddenWithinBucket(t *testing.T) {
	key := fileKey(t)
	a := encrypt(t, key, make([]byte, 70000))
	b := encrypt(t, key, make([]byte, 131072))
	if len(a.ct) != len(b.ct) {
		t.Fatalf("sizes %d %d", len(a.ct), len(b.ct))
	}
}

func TestFileCiphertextHidesContent(t *testing.T) {
	canary := strings.Repeat("CANARY-FILE-CONTENT ", 10)
	s := encrypt(t, fileKey(t), []byte(canary))
	if bytes.Contains(s.ct, []byte("CANARY")) {
		t.Fatal("plaintext visible in ciphertext")
	}
}

func TestFileTamperingRejected(t *testing.T) {
	key := fileKey(t)
	pt := make([]byte, 3*FileChunkSize+100) // bucket 4 chunks
	rand.Read(pt)
	s := encrypt(t, key, pt)
	ct := s.ct
	cs := FileChunkSize + gcmTag
	flip := append([]byte(nil), ct...)
	flip[5] ^= 1
	swap := append([]byte(nil), ct...)
	copy(swap[:cs], ct[cs:2*cs])
	copy(swap[cs:2*cs], ct[:cs])
	for name, c := range map[string][]byte{
		"bit flip":          flip,
		"reordered":         swap,
		"truncated at edge": ct[:2*cs],
		"truncated mid":     ct[:len(ct)-1],
		"dropped chunk":     append(append([]byte(nil), ct[:cs]...), ct[2*cs:]...),
		"duplicated chunk":  append(append([]byte(nil), ct[:cs]...), ct[:cs]...),
		"extra after final": append(append([]byte(nil), ct...), ct[:cs]...),
		"empty":             nil,
	} {
		if err := s.open(key, c); !errors.Is(err, ErrFileOpen) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

// A chunk lifted from another file (even one under the same key) must not open
// in place, since the swap breaks the hash or the padding check.
func TestFileChunkSwapBetweenFiles(t *testing.T) {
	key := fileKey(t)
	a := make([]byte, 2*FileChunkSize)
	b := make([]byte, 2*FileChunkSize)
	rand.Read(a)
	rand.Read(b)
	sa, sb := encrypt(t, key, a), encrypt(t, key, b)
	cs := FileChunkSize + gcmTag
	mix := append(append([]byte(nil), sa.ct[:cs]...), sb.ct[cs:]...)
	if err := sa.open(key, mix); !errors.Is(err, ErrFileHash) {
		t.Fatalf("got %v", err)
	}
	// Different keys: the swapped chunk does not authenticate at all.
	sc := encrypt(t, fileKey(t), b)
	mix = append(append([]byte(nil), sa.ct[:cs]...), sc.ct[cs:]...)
	if err := sa.open(key, mix); !errors.Is(err, ErrFileOpen) {
		t.Fatalf("got %v", err)
	}
}

func TestFileSizeAndPaddingEnforced(t *testing.T) {
	key := fileKey(t)
	pt := make([]byte, 5000)
	rand.Read(pt)
	s := encrypt(t, key, pt)
	// A size claiming a different bucket makes the object the wrong length.
	for name, size := range map[string]uint64{"larger bucket": 9000, "smaller bucket": 100} {
		if err := decryptFile(key, bytes.NewReader(s.ct), io.Discard, s.sum, size); !errors.Is(err, ErrFileOpen) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Same bucket, wrong size: the hash catches it.
	if err := decryptFile(key, bytes.NewReader(s.ct), io.Discard, s.sum, 5001); !errors.Is(err, ErrFileHash) {
		t.Errorf("same bucket: %v", err)
	}
	if err := decryptFile(key, bytes.NewReader(s.ct), io.Discard, s.sum, MaxFileSize+1); !errors.Is(err, ErrFileTooLarge) {
		t.Errorf("too large: %v", err)
	}
	// Nonzero padding is a covert channel: seal a file whose padding is not zero.
	aead, _ := fileAEAD(key)
	body := make([]byte, MinBucket)
	body[MinBucket-1] = 1
	bad := aead.Seal(nil, chunkNonce(0, true), body, chunkAAD(0, true))
	if err := decryptFile(key, bytes.NewReader(bad), io.Discard, sha256.Sum256(nil), 0); !errors.Is(err, ErrFileOpen) {
		t.Errorf("nonzero padding: %v", err)
	}
}

// A hostile object longer than its bucket is cut off at the first chunk past it,
// not read to the end.
func TestFileReadStopsAtBucket(t *testing.T) {
	key := fileKey(t)
	s := encrypt(t, key, make([]byte, 8*FileChunkSize))
	cr := &countReader{r: bytes.NewReader(s.ct)}
	err := decryptFile(key, cr, io.Discard, s.sum, FileChunkSize)
	if !errors.Is(err, ErrFileOpen) {
		t.Fatalf("got %v", err)
	}
	if limit := 2*(FileChunkSize+gcmTag) + 4096; cr.n > limit {
		t.Fatalf("read %d bytes, want at most %d", cr.n, limit)
	}
}

type countReader struct {
	r io.Reader
	n int
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func TestFileTooLargeOnEncrypt(t *testing.T) {
	// Zeros stream: no allocation beyond one chunk.
	r := io.LimitReader(zeros{}, MaxFileSize+1)
	if _, _, err := EncryptFile(fileKey(t), r, io.Discard); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("got %v", err)
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestFileWrongKeyAndHash(t *testing.T) {
	key := fileKey(t)
	s := encrypt(t, key, []byte("hello"))
	if err := s.open(fileKey(t), s.ct); !errors.Is(err, ErrFileOpen) {
		t.Fatalf("wrong key: %v", err)
	}
	s.sum[0] ^= 1
	if err := s.open(key, s.ct); !errors.Is(err, ErrFileHash) {
		t.Fatalf("wrong hash: %v", err)
	}
}

func TestFileBadKey(t *testing.T) {
	var sum [HashSize]byte
	// 16 bytes is a valid AES key but not a valid file key.
	if _, _, err := EncryptFile(make([]byte, 16), strings.NewReader("x"), io.Discard); !errors.Is(err, ErrFileKey) {
		t.Fatalf("aes-128 length: %v", err)
	}
	if _, _, err := EncryptFile(make([]byte, 5), strings.NewReader("x"), io.Discard); !errors.Is(err, ErrFileKey) {
		t.Fatalf("encrypt: %v", err)
	}
	if err := decryptFile(make([]byte, 5), strings.NewReader("x"), io.Discard, sum, 1); !errors.Is(err, ErrFileKey) {
		t.Fatalf("decrypt: %v", err)
	}
}

var errBoom = errors.New("boom")

type errReader struct{ after int }

func (e *errReader) Read(p []byte) (int, error) {
	if e.after <= 0 {
		return 0, errBoom
	}
	n := min(len(p), e.after)
	e.after -= n
	return n, nil
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errBoom }

func TestFileIOErrors(t *testing.T) {
	key := fileKey(t)
	if _, _, err := EncryptFile(key, &errReader{after: 10}, io.Discard); !errors.Is(err, errBoom) {
		t.Fatalf("read: %v", err)
	}
	if _, _, err := EncryptFile(key, strings.NewReader("x"), errWriter{}); !errors.Is(err, errBoom) {
		t.Fatalf("encrypt write: %v", err)
	}
	s := encrypt(t, key, []byte("x"))
	if err := decryptFile(key, &errReader{}, io.Discard, s.sum, s.size); !errors.Is(err, errBoom) {
		t.Fatalf("decrypt read: %v", err)
	}
	if err := decryptFile(key, bytes.NewReader(s.ct), errWriter{}, s.sum, s.size); !errors.Is(err, errBoom) {
		t.Fatalf("decrypt write: %v", err)
	}
	// A full chunk followed by a read error: the error surfaces on the next chunk.
	if _, _, err := EncryptFile(key, &errReader{after: FileChunkSize}, io.Discard); !errors.Is(err, errBoom) {
		t.Fatalf("lookahead: %v", err)
	}
}

// FuzzDecryptFile feeds arbitrary ciphertext and claimed sizes to the chunk
// reader. Nothing may panic or run past one bucket, and a genuine object with
// its genuine size and hash must still open.
func FuzzDecryptFile(f *testing.F) {
	key := make([]byte, FileKeySize)
	for _, pt := range [][]byte{nil, []byte("hello"), make([]byte, 5000)} {
		s := encrypt(f, key, pt)
		f.Add(s.ct, s.size)
		f.Add(s.ct[:len(s.ct)/2], s.size)
		f.Add(s.ct, s.size+1)
	}
	f.Add([]byte{}, uint64(0))
	f.Add([]byte{1, 2, 3}, uint64(MaxFileSize+1))
	f.Fuzz(func(t *testing.T, ct []byte, size uint64) {
		var out bytes.Buffer
		err := decryptFile(key, bytes.NewReader(ct), &out, [HashSize]byte{}, size)
		if err == nil {
			t.Fatal("opened with an all-zero hash")
		}
		if uint64(out.Len()) > size {
			t.Fatal("wrote more than the claimed size")
		}
	})
}

// leftovers lists everything in dir, so a test can assert that nothing (no
// destination, no temp file) remains after a failure.
func leftovers(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range es {
		names = append(names, e.Name())
	}
	return names
}

func TestDecryptFileToSuccess(t *testing.T) {
	dir := t.TempDir()
	key := fileKey(t)
	pt := make([]byte, 2*FileChunkSize+5)
	rand.Read(pt)
	s := encrypt(t, key, pt)
	dst := filepath.Join(dir, "out.bin")
	// An existing file is replaced atomically.
	if err := os.WriteFile(dst, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := DecryptFileTo(dst, key, bytes.NewReader(s.ct), s.sum, s.size); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("content mismatch: %v", err)
	}
	if names := leftovers(t, dir); len(names) != 1 {
		t.Fatalf("leftovers: %v", names)
	}
}

// Every failure mode must leave nothing on disk, and must leave an existing
// destination untouched.
func TestDecryptFileToFailuresLeaveNothing(t *testing.T) {
	key := fileKey(t)
	pt := make([]byte, 3*FileChunkSize+100)
	rand.Read(pt)
	s := encrypt(t, key, pt)
	cs := FileChunkSize + gcmTag
	flip := append([]byte(nil), s.ct...)
	flip[2*cs+5] ^= 1 // a late chunk, so earlier plaintext has already been written
	swap := append([]byte(nil), s.ct...)
	copy(swap[cs:2*cs], s.ct[2*cs:3*cs])
	copy(swap[2*cs:3*cs], s.ct[cs:2*cs])
	wrongHash := s.sum
	wrongHash[0] ^= 1
	good := func(w io.Writer) io.Writer { return w }
	failSecondWrite := func(w io.Writer) io.Writer { return &failAfter{w: w, left: 1} }
	cases := []struct {
		name string
		ct   []byte
		sum  [HashSize]byte
		size uint64
		key  []byte
		src  io.Reader
		wrap func(io.Writer) io.Writer
		want error
	}{
		{name: "tampered chunk", ct: flip, want: ErrFileOpen},
		{name: "truncated at edge", ct: s.ct[:3*cs], want: ErrFileOpen},
		{name: "truncated mid", ct: s.ct[:len(s.ct)-1], want: ErrFileOpen},
		{name: "extended", ct: append(append([]byte(nil), s.ct...), s.ct[:cs]...), want: ErrFileOpen},
		{name: "reordered", ct: swap, want: ErrFileOpen},
		{name: "wrong key", ct: s.ct, key: fileKey(t), want: ErrFileOpen},
		{name: "wrong hash", ct: s.ct, sum: wrongHash, want: ErrFileHash},
		{name: "wrong size", ct: s.ct, size: 1, want: ErrFileOpen},
		{name: "too large", ct: s.ct, size: MaxFileSize + 1, want: ErrFileTooLarge},
		{name: "bad key", ct: s.ct, key: []byte{1}, want: ErrFileKey},
		{name: "read error", src: io.MultiReader(bytes.NewReader(s.ct[:cs+10]), &errReader{}), want: errBoom},
		{name: "write error", ct: s.ct, wrap: failSecondWrite, want: errBoom},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			dst := filepath.Join(dir, "out.bin")
			if err := os.WriteFile(dst, []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			k, sum, size, wrap, src := key, s.sum, s.size, good, c.src
			if c.key != nil {
				k = c.key
			}
			if c.sum != ([HashSize]byte{}) {
				sum = c.sum
			}
			if c.size != 0 {
				size = c.size
			}
			if c.wrap != nil {
				wrap = c.wrap
			}
			if src == nil {
				src = bytes.NewReader(c.ct)
			}
			if err := decryptTo(dst, wrap, k, src, sum, size); !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if names := leftovers(t, dir); len(names) != 1 || names[0] != "out.bin" {
				t.Fatalf("leftovers: %v", names)
			}
			if b, _ := os.ReadFile(dst); string(b) != "old" {
				t.Fatalf("destination changed: %q", b)
			}
		})
	}
}

// failAfter passes the first `left` writes through, then fails.
type failAfter struct {
	w    io.Writer
	left int
}

func (f *failAfter) Write(p []byte) (int, error) {
	if f.left <= 0 {
		return 0, errBoom
	}
	f.left--
	return f.w.Write(p)
}

func TestDecryptFileToFilesystemErrors(t *testing.T) {
	key := fileKey(t)
	s := encrypt(t, key, []byte("hello"))
	// No such directory: nothing can be created.
	if err := DecryptFileTo(filepath.Join(t.TempDir(), "no", "out"), key, bytes.NewReader(s.ct), s.sum, s.size); err == nil {
		t.Fatal("expected an error")
	}
	// A directory in the way: the rename fails after a fully valid decrypt, and
	// the temp file is still removed.
	dir := t.TempDir()
	dst := filepath.Join(dir, "out")
	if err := os.Mkdir(dst, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := DecryptFileTo(dst, key, bytes.NewReader(s.ct), s.sum, s.size); err == nil {
		t.Fatal("expected an error")
	}
	if names := leftovers(t, dir); len(names) != 1 || names[0] != "out" {
		t.Fatalf("leftovers: %v", names)
	}
}
