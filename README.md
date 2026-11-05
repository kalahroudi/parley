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

## Enrolling a device

Your admin sends you the root fingerprint through chat or email (never through Parley). Then:

```
parley-cli login  -tenant acme -gateway https://gw.example.com      # sign in in your browser; confirm the code
parley-cli enroll -tenant acme -root <fingerprint from your admin>   # create the device key, ask for approval, wait
```

- The device key is created once, in the OS keychain. `enroll` never replaces it; if it is lost, `enroll -replace` starts a new identity and prints the old device id for your admin to revoke.
- If `enroll` is interrupted, run `parley-cli enroll` again: it continues the same request.
- No fingerprint at hand? `-trust-on-first-use` shows the root the gateway presents and asks you to type `yes`. Compare it with your admin first.
- Pods and CI: the admin mints a single-use token; set `PARLEY_ENROLL_TOKEN` and run `parley-cli enroll -token -tenant acme -root <fingerprint> -key-store file`. Secrets are read from the environment, never from arguments.
- The sign-in session is kept in the OS keychain, removed once the request is accepted, and never written to a file.

## What Parley does not promise

Metadata (who called which bot, when, and sizes) is visible to the gateway, and agent cards are plaintext. Retention at the endpoints, such as a bot's own history or a model vendor, is the customer's. The spec lists every guarantee and non-guarantee in detail.

## Documentation

The specification lives in [`specs/parley-mvp/`](specs/parley-mvp/):

- [Spec](specs/parley-mvp/spec.md): goal, constraints, guarantees and non-guarantees, user journeys, interoperability, open decisions.
- [Plan](specs/parley-mvp/plan.md): architecture, cryptography and key trust, retention modes, threat model, testing strategy, coverage policy and local-first development.
- [Tasks](specs/parley-mvp/tasks.md): phased delivery with acceptance tests and gates.

## License

Apache License 2.0. See [LICENSE](LICENSE).
