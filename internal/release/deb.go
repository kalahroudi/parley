// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// debArch maps Go architectures to Debian's.
var debArch = map[string]string{"amd64": "amd64", "arm64": "arm64"}

// debEpoch is the fixed modification time inside packages, so that building twice gives identical bytes.
var debEpoch = time.Unix(0, 0)

// debControl is the control file of the package for a Debian version and architecture, with the installed size in
// KiB (omitted when 0). The apt index repeats these fields (apt.go).
func debControl(version, arch string, sizeKB int64) string {
	installed := ""
	if sizeKB > 0 {
		installed = fmt.Sprintf("Installed-Size: %d\n", sizeKB)
	}
	return fmt.Sprintf(`Package: parley
Version: %s
Architecture: %s
Maintainer: Parley Authors <https://github.com/kalahroudi/parley/issues>
%sSection: net
Priority: optional
Homepage: %s
Description: Secure agent-to-agent tasks between the bots of an organisation
 parleyd is the background daemon and parley-cli the user command. Task content is
 end-to-end encrypted; the hosted gateway sees only metadata. Updates come from the
 package manager, not from the programs themselves.
`, version, arch, installed, Homepage)
}

// BuildDeb builds the Debian package of the release tagged tag for Go architecture goarch from the Linux
// binaries in dir (named as scripts/release.sh names them). The package holds /usr/bin/parleyd and
// /usr/bin/parley-cli and runs no maintainer scripts; it starts nothing, and a user enrolls and starts the daemon
// themselves. The bytes depend only on the inputs.
func BuildDeb(tag, goarch, dir string) ([]byte, error) {
	version, err := debVersion(tag)
	if err != nil {
		return nil, err
	}
	arch, ok := debArch[goarch]
	if !ok {
		return nil, fmt.Errorf("release: no Debian architecture for %q", goarch)
	}
	type file struct {
		path string
		data []byte
	}
	var files []file
	var size int64
	for _, cmd := range []string{"parleyd", "parley-cli"} {
		data, err := os.ReadFile(filepath.Join(dir, fmt.Sprintf("%s_%s_linux_%s", cmd, tag, goarch)))
		if err != nil {
			return nil, err
		}
		files = append(files, file{"./usr/bin/" + cmd, data})
		size += int64(len(data))
	}
	var data bytes.Buffer
	dataTar := newTar(&data)
	dataTar.add("./usr/", nil, 0o755)
	dataTar.add("./usr/bin/", nil, 0o755)
	for _, f := range files {
		dataTar.add(f.path, f.data, 0o755)
	}
	var control bytes.Buffer
	controlTar := newTar(&control)
	controlTar.add("./control", []byte(debControl(version, arch, (size+1023)/1024)), 0o644)
	// Writing to memory does not fail; the archives report it at close all the same.
	derr, cerr := dataTar.close(), controlTar.close()
	var ar bytes.Buffer
	ar.WriteString("!<arch>\n")
	arMember(&ar, "debian-binary", []byte("2.0\n"))
	arMember(&ar, "control.tar.gz", control.Bytes())
	arMember(&ar, "data.tar.gz", data.Bytes())
	return ar.Bytes(), errors.Join(derr, cerr)
}

// gzTar writes a gzip-compressed tar with fixed owners and times. Errors are collected and returned by close, so
// callers write a whole archive and check once.
type gzTar struct {
	gz  *gzip.Writer
	tw  *tar.Writer
	err error
}

func newTar(w *bytes.Buffer) *gzTar {
	gz := gzip.NewWriter(w) // the header carries no name or time
	return &gzTar{gz: gz, tw: tar.NewWriter(gz)}
}

// add writes a directory when data is nil, otherwise a file.
func (t *gzTar) add(name string, data []byte, mode int64) {
	h := &tar.Header{Name: name, Mode: mode, Size: int64(len(data)), ModTime: debEpoch, Uname: "root", Gname: "root", Format: tar.FormatGNU, Typeflag: tar.TypeReg}
	if data == nil {
		h.Typeflag = tar.TypeDir
	}
	herr := t.tw.WriteHeader(h)
	_, werr := t.tw.Write(data)
	t.err = errors.Join(t.err, herr, werr)
}

func (t *gzTar) close() error { return errors.Join(t.err, t.tw.Close(), t.gz.Close()) }

// arMember appends one member to a Debian (ar) archive: a 60 byte header, the data, and a newline of padding to
// an even length.
func arMember(b *bytes.Buffer, name string, data []byte) {
	fmt.Fprintf(b, "%-16s%-12d%-6d%-6d%-8o%-10d`\n", name, 0, 0, 0, 0o100644, len(data))
	b.Write(data)
	if len(data)%2 == 1 {
		b.WriteByte('\n')
	}
}
