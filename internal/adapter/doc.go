// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

// Package adapter connects the daemon to the bot a customer brings. Adapters
// implement bot.Bot. There are three: the API adapter (the bot is an HTTP service;
// each task is a POST to one configured URL), the CLI adapter (the bot is a
// program run once per task) and the ACP adapter (the bot is a program that speaks
// the Agent Client Protocol, run once per task like a CLI bot). The API and CLI
// adapters speak the line protocol below; the ACP adapter speaks ACP (see ACP).
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
//   - the API adapter follows no redirect, uses no proxy, sends its bearer
//     token only to the configured URL and, for plain http, dials only a
//     loopback address (checked after name resolution);
//   - the CLI adapter runs an absolute path directly (no shell, no PATH lookup),
//     puts nothing from a task on its command line or in its environment (which
//     is only what the configuration lists, never the daemon's), discards its
//     standard error, and kills and reaps it, with everything it started (a
//     process group on Unix, a job object on Windows), when the task ends for
//     any reason, the final message included;
//   - lines are parsed strictly: unknown fields, a second value or trailing text
//     are protocol errors.
//
// Tool requests: at most MaxToolRequests per task, MaxToolArgs arguments each. The adapter does not run anything: it hands
// the request to Tools (internal/toolgate decides, the owner approves the exact call, internal/toolrun runs it in a
// sandbox) and writes the reply. outcome is ok, exit (the tool ran and exited nonzero), denied (the owner said no or did not
// answer, or a grant was revoked), refused (the request broke the manifest or a limit), failed or timeout; content is the
// tool's output, cut, neutralised and framed by a random boundary (it is always data, never instructions), and is only there
// if the tool ran. The caller sees a status while a request waits for the owner. RunContained gives a tool the same
// containment as a CLI bot: own session or job, registered so it can never approve anything, killed and reaped with its tree.
//
// Everything in a task line is data from a remote caller (content, context, and
// the caller and owner names from its binding): a bot that gives it to a model
// must treat it as untrusted data and never as instructions or tool calls. The
// adapters pass it as JSON string and base64 fields only, never mixed into text
// that a bot would read as its own instructions.
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
//	{"v":1,"type":"tool_result","id":"<32 hex>","turn":N,"outcome":"..","exit":N,"truncated":bool,"untrusted":true,"content":"<base64>"}
//	                                                                       CLI only: the reply to tool request N (see below)
//
// From the bot (a turn ends with a question, result or error):
//
//	{"type":"status","content":"<base64>"}     any number up to MaxStatuses
//	{"type":"question","content":"<base64>"}   the caller's answer follows as an "answer" line
//	{"type":"tool","tool":"name","args":["a","b"]}   CLI only, and only if the adapter was given Tools: a request for a
//	                                           tool the skill declared; the tool_result line follows. Without Tools a
//	                                           request is a protocol error and ends the task (the bot is tool-less).
//	{"type":"result","content":"<base64>"}     final
//	{"type":"error","message":"text for the caller"}   final; no task content or secrets
//
// API: the task is the body of one POST; the answer to a question is the body
// of the next POST to the same URL (the service correlates by id) and its
// response continues the task. Every response is 200 with this stream; any other
// status fails the task. Canceling a task closes the connection; if no request
// is open the adapter sends the cancel line.
//
// CLI: the task line, then each answer line, go to the program's standard input;
// its standard output carries the bot's lines. There is no cancel line: the end
// of the task is the end of the process.
//
// # ACP
//
// The ACP adapter starts the program exactly as the CLI adapter does (same containment, same registration, same
// environment rules) and speaks JSON-RPC 2.0, one message per line (at most MaxLine bytes), as an ACP client: initialize
// (protocol version 1 only), session/new (rooted in the configured directory, no MCP servers), and one session/prompt.
// The task content, which must be valid UTF-8 or the task fails with TextACPNotText, is the prompt's single text block;
// the caller, owner, context and expiry travel as JSON fields in the request's _meta, never inside text. The result is the
// text of the agent's message chunks once it stops with end_turn; any other stop reason fails the task, and a reply larger
// than a result may be is cut as soon as it is, the agent killed. The envelope of every message is read strictly (unknown
// fields, trailing data, a wrong id, a long request id are protocol errors); the contents of params and result are read
// leniently, because ACP lets either side add fields.
//
// Nothing is granted to the agent: the client offers no file system and no terminal, answers any request it receives with
// "method not found", and denies every permission request (the reject option the agent offered, or "cancelled"), so an agent
// cannot ask its way into acting on the machine through the client. What the agent does by itself, with its own tools, is
// the customer's configuration and is a tool-using skill (owner approval; unsupported on Windows). Thoughts, plans,
// tool progress and non-text blocks are dropped, at most MaxACPIgnored of them (and MaxACPPermissions permission requests)
// per task. ACP has no question to the caller, and no status text that is not also the agent's thinking, so the caller sees
// no status and no INPUT_REQUIRED from an ACP bot. The end of the task is the end of the process (no session/cancel).
//
// What this package cannot do: the bot receives the plaintext and keeps what it
// likes; it is outside Parley's guarantees. Scrubbing of the buffers this
// package builds is best effort (Go gives no guarantee). On Windows a
// grandchild started in the instant between the start of the command and its
// assignment to the job object is not contained.
package adapter
