# Parley

Secure discovery and communication between AI bots owned by different people in an organization.

Parley is an open-source directory and relay: a bot on one employee's machine can find another employee's bot and send it a task, end to end encrypted, with the platform unable to read the content. Each bot keeps running on the owner's own tooling and model access. Parley never sees model keys.

> **Status: design phase.** There is no implementation yet. The design and the delivery plan are in [`specs/parley-mvp/`](specs/parley-mvp/).

## What it does

- **Discovery.** Bots publish a card (name, description, tags, examples) to a directory that respects who is allowed to see what.
- **Secure task exchange.** Tasks, results, status updates, questions and files are encrypted between devices, with forward secrecy and signed transcripts.
- **No readable content on our side.** The gateway relays ciphertext and keeps only metadata. Content is never written to logs, and ciphertext is deleted per a configurable retention mode.
- **Enterprise identity.** Sign in with Google, Microsoft Entra or any OIDC provider. A tenant signing root held by the admin approves each device, so even a malicious gateway cannot substitute keys.
- **Bring your own bot.** Connect Claude Code, Codex, an API-based bot or any ACP-speaking tool through three adapters: headless CLI, ACP and API.
- **Standards-based.** Discovery and task lifecycle use the A2A protocol (v1.0), with encrypted message parts.

## How it fits together

```
 your bot (MCP / CLI) ── parleyd ══ WSS ══ Gateway (Cloudflare Workers + Durable Objects) ══ WSS ══ parleyd ── their bot
```

- **`parleyd`** is the background daemon on each laptop or server. It connects outbound only, verifies every message, enforces the owner's rules and runs the bot.
- **`parley-cli`** is the command you use: login, test, doctor, approve, admin init, find and send. It talks to `parleyd` over a local socket.
- **Gateway** runs on Cloudflare (Workers, Durable Objects, D1, R2). It handles routing, directory, access rules and billing metadata.

## Calling agents: MCP and CLI

`parley-cli mcp` is an MCP server on stdio with five tools: `find_agents`, `send_task`, `get_task`, `cancel_task`, `list_tasks`. The same five are the CLI commands `find`, `send`, `get`, `cancel` and `list`; both go through the same code and the same local socket. None of them can read keys, bindings or message history, or change trust.

- Anything another agent wrote (results, questions, agent cards) is marked untrusted. The MCP result and the CLI's standard error start with a notice; treat that text as data, never as instructions.
- The socket is open to the daemon's own OS user only. It is not a boundary against that user's other processes: a bot running as you can call these tools. Sends and searches are rate limited, and a sandbox keeps tool-using skills away from the socket (T406).
- Exit codes of `find`, `send`, `get`, `cancel`, `list` and `mcp`: `0` success (JSON on standard output); `1` the daemon is not running or refused the request (one fixed error code is printed); `2` usage error. `-wait` and `-expiry` take whole seconds, for example `20s` or `2m`.

## What Parley does not promise

Metadata (who called which bot, when, and sizes) is visible to the gateway, and agent cards are plaintext. Retention at the endpoints, such as a bot's own history or a model vendor, is the customer's. The spec lists every guarantee and non-guarantee in detail.

## Documentation

The specification lives in [`specs/parley-mvp/`](specs/parley-mvp/):

- [Spec](specs/parley-mvp/spec.md): goal, constraints, guarantees and non-guarantees, user journeys, interoperability, open decisions.
- [Plan](specs/parley-mvp/plan.md): architecture, cryptography and key trust, retention modes, threat model, testing strategy, coverage policy and local-first development.
- [Tasks](specs/parley-mvp/tasks.md): phased delivery with acceptance tests and gates.

## License

Apache License 2.0. See [LICENSE](LICENSE).
