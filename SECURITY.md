# Security

oathkey is built so an AI agent can use your API keys without being handed them. It reduces risk. It does not remove it. No independent security review has been done yet.

## What it defends against
- **An AI reading a key out of chat, a prompt or tool output.** The tool adds the key itself. Replies and program output are scrubbed for the key in many disguises (encoded, escaped, split by spaces). If a disguised key is still detected, the whole reply is withheld.
- **A prompt-injected AI sending your key to another server.** The destination comes from the saved service profile, never from the AI. Private and internal addresses are refused, the connection goes to the address we checked, redirects are not followed, proxies are ignored, and odd path tricks are refused.
- **An AI making changes you did not approve.** Anything other than a read asks you first, in a pop-up window (or, with no window available, on the console with a code shown only on screen). The pop-up shows the method, address, query and the start of the body. Three refusals stop further requests.
- **Accidental or casual edits to the activity log.** Each entry carries the hash of the one before it (`oathkey audit verify`).
- **Dangerous ssh options** passed to `remote`.
- **Web pages and rebinding tricks** against the local web door (`serve`): loopback only, secret token, exact Host check, Origin refused, no CORS.

## What it does NOT defend against
- **Malware, or an AI agent that can run programs as you.** Anything running as you can read your keychain or `.env` directly, edit the activity log (it has no secret key), or drive the screen to click a pop-up. The broker protects against an AI that only uses the tool, not one with full control of your computer. Run risky agents in a separate account or container.
- **A key left where an AI can simply read the file** (`.env`, shell history, AI-tool settings). `oathkey scan` finds these; prefer `--store keychain`.
- **Harmful actions inside what a key is allowed to do.** GET requests are treated as reads, but some services let a GET change things. Limit each key at the provider (read-only keys, narrow scopes).
- **What the AI company sees.** Replies from the API go to the AI. If you let the AI read your email through this tool, the AI vendor sees that email.
- **The approval window cannot show everything.** It shows the first part of a body, not all of it.
- **Secrets we have not thought of how to disguise.** The scrubber is best effort; Python also cannot reliably erase secrets from memory.
- **A compromised service**, or one that logs or leaks your key itself.

## Report a problem
Contact address to be published before launch. Please do not post a working exploit publicly first. We aim to reply within 7 days.
