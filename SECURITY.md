# Security

oathkey is built so an AI agent can use your API keys without being handed them. It reduces risk. It does not remove it. No independent security review has been done yet.

## What it defends against
- **An AI reading a key out of chat, a prompt or tool output.** The tool adds the key itself. Replies and program output are scrubbed for the key in many disguises (encoded, escaped, split by spaces). If a disguised key is still detected, the whole reply is withheld.
- **A prompt-injected AI sending your key to another server.** The destination comes from the saved service profile, never from the AI. Private and internal addresses are refused, the connection goes to the address we checked, redirects are not followed, proxies are ignored, and odd path tricks are refused.
- **An AI making changes you did not approve.** Anything other than a read asks you first, in a pop-up window (or, with no window available, on the console with a code shown only on screen). The pop-up shows the method, address, every query parameter and the whole body (anything too long to show in full is refused). Three refusals stop further requests. The call limit and the three-refusal stop are counted separately by each running oathkey program (MCP server, web door, `call`), not across all of them.
- **Accidental or casual edits to the activity log.** Each entry carries the hash of the one before it (`oathkey audit verify`).
- **An AI turning a harmless-looking read into new credentials.** For AWS, only plain look-ups are allowed (`GetCallerIdentity` for STS; `Describe*`/`List*` elsewhere); actions that create keys (`GetSessionToken`, `AssumeRole`, ...) are refused.
- **A request padded to hide what it does.** The approval window lists every query parameter and shows the whole body with its size and hash; a query value over 200 characters or a body over 400 bytes is refused, never shown cut off. The pop-up program is found by its full system path, never through PATH or the current folder.
- **A planted recipe that sends a built-in service's key somewhere else.** A recipe in your own recipes folder cannot redirect a built-in service (or reuse its key name) to a different server.
- **Dangerous ssh options** passed to `remote`.
- **Web pages and rebinding tricks** against the local web door (`serve`): loopback only, secret token, exact Host check, Origin refused, no CORS.

## What it does NOT defend against
- **Malware, or an AI agent that can run programs as you.** Anything running as you can read your keychain or `.env` directly, edit the activity log (it has no secret key), or drive the screen to click a pop-up. The broker protects against an AI that only uses the tool, not one with full control of your computer. Run risky agents in a separate account or container.
- **`run` and `remote` handed to an AI that can run commands.** They give the key to a program you name; a program can print its own environment, and a terminal-style session is not scrubbed. Give AIs the MCP tool or `call` only.
- **A key left where an AI can simply read the file** (`.env`, shell history, AI-tool settings). `oathkey scan` finds these; prefer `--store keychain`.
- **The sign-in request for OAuth services** (the token fetch). It checks the address is public, ignores proxy settings and never follows redirects, but unlike ordinary calls it is not pinned to the address it checked.
- **Log flooding.** Refused requests count toward the call limit and are logged with a clipped path, but a patient attacker with a few dozen refused calls can still push older lines out of the default `audit show` view; use `--last`.
- **Harmful actions inside what a key is allowed to do.** GET requests are treated as reads, but some services let a GET change things. Limit each key at the provider (read-only keys, narrow scopes).
- **What the AI company sees.** Replies from the API go to the AI. If you let the AI read your email through this tool, the AI vendor sees that email.
- **The approval window cannot show everything.** It shows the first part of a body, not all of it.
- **Secrets we have not thought of how to disguise.** The scrubber is best effort; Python also cannot reliably erase secrets from memory.
- **A compromised service**, or one that logs or leaks your key itself.
- **The clipboard.** Copy-and-go (`oathkey get`) empties the clipboard right after taking the key, but other programs and clipboard-history tools can read it while it is there and may keep their own copy. If that worries you, use `--no-clipboard` (hidden typing instead).
- **A tamper-proof log.** The activity log is tamper-evident, not tamper-proof. Edits, deleted lines, a cut-off end and a deleted file are detected (a small second file remembers how many entries there should be), but someone running as you can rewrite both files. Nothing is anchored outside your account yet.

## Check it yourself

- `oathkey selftest` attacks oathkey with a made-up key and a pretend server (no network, no real key) and prints PASS or FAIL for each attack. It checks the rules listed above only; it cannot show that nothing else can go wrong.
- The package uses only Python's standard library, no outside code. A test (`tests/test_stdlib_only.py`) fails if that ever changes.

## Report a problem
Report privately at https://github.com/calasdan-sketch/oathkey/security/advisories/new (GitHub private vulnerability reporting). Please do not open a public issue or post a working exploit first. We aim to reply within 7 days.
