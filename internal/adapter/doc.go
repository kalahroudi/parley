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
// (protocol version 1 only), session/new (rooted in the configured directory, no MCP servers) and session/prompt. The task
// content, which must be valid UTF-8 or the task fails with TextACPNotText, is the prompt's single text block; the caller,
// owner, context and expiry travel as JSON fields in the request's _meta, never inside text. The envelope of every message is
// read strictly (unknown, duplicate and miscased keys, trailing data, a wrong id and a long request id are protocol errors);
// the contents of params and result are read leniently, because ACP lets either side add fields.
//
// What the bot contract's three side channels are in ACP:
//
//   - Result: the text of the agent's message chunks of the last turn, when the turn ends with end_turn. A reply larger
//     than a result may be is cut as soon as it is, and the agent killed.
//   - Status: a plan update (session/update, sessionUpdate "plan") is the status text of its first entry in progress, cut to
//     MaxACPStatus bytes of printable text; a repeat of the last status, an entry-less plan and any plan past MaxStatuses are
//     dropped. Thoughts, tool progress and non-text blocks are dropped (at most MaxACPIgnored of them per task).
//   - Question (INPUT_REQUIRED): a turn that ends with end_turn and "_meta":{"parley":{"inputRequired":true}} in the prompt
//     reply makes the turn's text a question to the caller; the caller's answer (text only) is the next session/prompt of the
//     same session, with "_meta":{"parley":{"task":..,"answer":true}}. At most MaxQuestions per task. An agent that does not
//     know this extension never asks a question.
//   - Declared failure: an error reply to a prompt whose error.data is {"parley":"failure"} makes error.message the failure
//     text for the caller; the stop reason "refusal" is the fixed failure TextACPRefused. Every other error, and every error
//     of initialize or session/new, is an error of the task whose text goes nowhere; so is every other stop reason.
//   - Cancel: when the task ends (cancel, expiry, timeout) the agent is sent session/cancel, has 250 ms to end itself, and
//     is then killed with everything it started.
//
// What the agent may ask of us, and what it is given. The client offers no terminal and answers any terminal request, and
// any other request it does not know, with "method not found". Without a Gate in the configuration every permission request is
// denied and no file capability is offered. With one, each of these goes to the owner, who answers on the terminal path (the
// daemon's tool_calls / tool_approve / tool_deny commands, which a bot's process cannot reach), and only the owner's yes
// lets it through:
//
//   - a permission request (session/request_permission): the owner sees the kind and the title of the agent's tool call, as
//     printable text cut to a fixed length (the title is the agent's words and is untrusted). Yes selects the allow_once option
//     the agent offered, never allow_always; no, an offer without allow_once, and every other outcome select the reject option
//     the agent offered, or "cancelled". The owner is not asked when there is no allow_once option to select.
//   - a file read or write (fs/read_text_file, fs/write_text_file): the path must be absolute, printable text inside the
//     session's directory (otherwise "invalid params" without asking); the owner sees the exact path, and for a write the size
//     and the SHA-256 of the content. Only after a yes is the file touched, through an os.Root of the directory (no ".." and no
//     symbolic link leaves it), at most MaxACPFile bytes, a regular text file only, opened without blocking so that a file
//     swapped for a named pipe cannot hang the task. A written file is created with mode 0600. The agent is told "denied",
//     "file operation failed", "file too large", "not a text file" or "invalid params", never an OS error or a path.
//
// At most MaxACPPermissions requests per task are put to the owner (refused ones included), and the broker limits the calls
// per task and the calls waiting. The owner may grant a call's tool for the rest of the task (scope "task"), as for any tool.
// What the agent does by itself, with its own tools and its own access to the machine, is outside this: it is the
// customer's configuration and is a tool-using skill (owner approval; unsupported on Windows). No terminal means that an agent
// that needs to run programs through the client cannot.
//
// What this package cannot do: the bot receives the plaintext and keeps what it
// likes; it is outside Parley's guarantees. Scrubbing of the buffers this
// package builds is best effort (Go gives no guarantee). On Windows a
// grandchild started in the instant between the start of the command and its
// assignment to the job object is not contained.
package adapter
