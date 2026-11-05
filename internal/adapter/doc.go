// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package adapter connects the daemon to the bot a customer brings. Adapters
// implement bot.Bot. This change has the API adapter (the bot is an HTTP
// service; each task is a POST to one configured URL); the CLI and ACP adapters
// come as separate changes and speak the same line protocol.
//
// Host (package bot) owns everything the daemon promises about a task: limits,
// the one final message, timeouts, redaction of errors. The adapters only
// carry a task to the bot and its answers back, and they hold the line a hostile
// or broken bot must not cross:
//
//   - what a bot says is bounded (one line is at most about one maximal result;
//     at most MaxStatuses status messages and MaxQuestions questions per task);
//   - nothing the bot or its transport says becomes the caller's error text
//     unless the bot sent it as an explicit error message (and Host cuts that);
//   - the API adapter follows no redirect, uses no proxy and sends its bearer
//     token only to the configured URL.
//
// # Line protocol "parley-bot/1"
//
// Adapters speak newline-delimited JSON (one object per
// line, UTF-8, at most MaxLine bytes). Binary content is base64 (standard
// alphabet, padded).
//
// To the bot:
//
//	{"v":1,"type":"task","id":"<32 hex>","context":"..","caller":"..","owner":"..","expires":"<RFC 3339 UTC>","content":"<base64>"}
//	{"v":1,"type":"answer","id":"<32 hex>","turn":N,"content":"<base64>"}   the caller's answer to question N (1, 2, ..)
//	{"v":1,"type":"cancel","id":"<32 hex>"}                                 HTTP only, best effort: the task ended without a final message
//
// From the bot (a turn ends with a question, result or error):
//
//	{"type":"status","content":"<base64>"}     any number up to MaxStatuses
//	{"type":"question","content":"<base64>"}   the caller's answer follows as an "answer" line
//	{"type":"result","content":"<base64>"}     final
//	{"type":"error","message":"text for the caller"}   final; no task content or secrets
//
// API: the task is the body of one POST; the answer to a question is the body
// of the next POST to the same URL (the service correlates by id) and its
// response continues the task. Every response is 200 with this stream; any other
// status fails the task. Canceling a task closes the connection; if no request
// is open the adapter sends the cancel line.
//
// What this package cannot do: the bot receives the plaintext and keeps what it
// likes; it is outside Parley's guarantees. Scrubbing of the buffers this
// package builds is best effort (Go gives no guarantee).
package adapter
