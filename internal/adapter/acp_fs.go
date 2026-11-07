// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package adapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// fs serves fs/read_text_file and fs/write_text_file. Without a gate the capability was not offered, so the request is
// "method not found". Otherwise the path must lie in the session's directory and be printable text (so that what the owner is
// shown is the path that is used), the owner must allow this one call, and only then is the file touched, through an
// os.Root of the directory, which no ".." and no symbolic link can leave.
func (c *acpConv) fs(ctx context.Context, params json.RawMessage, write bool) (any, *rpcError, error) {
	if c.gate == nil {
		return nil, errNoMethod, c.ignore()
	}
	var p struct {
		SessionID string  `json:"sessionId"`
		Path      string  `json:"path"`
		Content   *string `json:"content"`
		Line      *int    `json:"line"`
		Limit     *int    `json:"limit"`
	}
	rel, ok := "", json.Unmarshal(params, &p) == nil && p.SessionID == c.session() && (p.Content != nil) == write
	if ok {
		rel, ok = c.relative(p.Path)
	}
	if !ok || (write && len(*p.Content) > MaxACPFile) || (p.Line != nil && *p.Line < 1) || (p.Limit != nil && *p.Limit < 0) {
		return nil, errInvalid, c.count()
	}
	tool, args := ToolACPRead, []string{p.Path}
	if write {
		sum := sha256.Sum256([]byte(*p.Content))
		tool, args = ToolACPWrite, []string{p.Path, strconv.Itoa(len(*p.Content)), hex.EncodeToString(sum[:])}
	}
	allowed, err := c.ask(ctx, tool, args...)
	if err != nil {
		return nil, nil, err
	}
	if !allowed {
		return nil, errDenied, nil
	}
	if write {
		return json.RawMessage("null"), writeFile(c.dir, rel, *p.Content), nil
	}
	text, rerr := readFile(c.dir, rel, p.Line, p.Limit)
	if rerr != nil {
		return nil, rerr, nil
	}
	return map[string]string{"content": text}, nil, nil
}

// relative is the path inside the session's directory that path names, and whether it names one: an absolute path of
// printable text, at most maxACPPath bytes, in the directory (lexically; os.Root makes that hold for what is on disk).
func (c *acpConv) relative(path string) (string, bool) {
	if len(path) > maxACPPath || !filepath.IsAbs(path) || !utf8.ValidString(path) {
		return "", false
	}
	for _, r := range path {
		if r != ' ' && !unicode.IsPrint(r) {
			return "", false
		}
	}
	rel, err := filepath.Rel(c.dir, filepath.Clean(path))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return rel, true
}

// readFile reads a regular text file of at most MaxACPFile bytes, from line (1-based) for limit lines when they are given.
func readFile(dir, rel string, line, limit *int) (string, *rpcError) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", errFile
	}
	defer root.Close()
	f, err := root.OpenFile(rel, openFlags(false), 0)
	if err != nil {
		return "", errFile
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return "", errFile
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxACPFile+1))
	if err != nil {
		return "", errFile
	}
	if len(b) > MaxACPFile {
		return "", errTooBig
	}
	if !utf8.Valid(b) {
		return "", errNotText
	}
	text := string(b)
	if line == nil && limit == nil {
		return text, nil
	}
	lines := strings.SplitAfter(text, "\n")
	from := 0
	if line != nil {
		from = min(*line-1, len(lines))
	}
	to := len(lines)
	if limit != nil {
		to = min(from+*limit, len(lines))
	}
	return strings.Join(lines[from:to], ""), nil
}

// writeFile writes content to a regular file in the directory, creating it (mode 0600) or replacing it.
func writeFile(dir, rel, content string) *rpcError {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return errFile
	}
	defer root.Close()
	f, err := root.OpenFile(rel, openFlags(true), 0o600)
	if err != nil {
		return errFile
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return errFile
	}
	if err := f.Truncate(0); err != nil {
		return errFile
	}
	if _, err := f.WriteString(content); err != nil {
		return errFile
	}
	return nil
}
