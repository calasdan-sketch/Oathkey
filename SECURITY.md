# Security

safeeasyapi is built so an AI agent can use your API keys without ever holding them. It reduces risk. It does not make risk zero, and no independent security review has been done yet.

## What it defends against
- An AI reading a key out of chat, a prompt, or tool output: keys are added by the tool itself and scrubbed (many encodings) from anything returned.
- A prompt-injected AI sending your key to another server: the destination host comes from the saved recipe, never from the AI. Private/internal addresses are refused, the connection is pinned to the checked address, redirects are not followed, and proxies are ignored.
- An AI making changes you did not approve: anything other than read requests asks you on the real terminal. Piped input cannot answer.
- Silent tampering with the activity log: each entry carries the hash of the one before (`safeeasyapi audit verify`).
- Dangerous ssh options passed to `remote`.
- Browser pages and rebinding tricks against the local web door (`serve`): loopback only, secret token, exact Host check, Origin refused, no CORS.

## What it does NOT defend against
- Malware or another program already running as you on your computer.
- A key left in a `.env` file or shell history where an AI can simply read the file (`safeeasyapi scan` finds these; prefer `--store keychain`).
- A service that itself leaks or logs your key, or a compromised service.
- You approving everything without looking.
- A harmful but permitted action inside an allowed API (an AI allowed to read can still read a lot). Limit what each key can do at the provider.
- Secrets Python cannot erase from memory; the scrubber is best-effort against encodings we did not think of.

## Report a problem
Email the maintainer (address to be published before launch). Please do not post a working exploit publicly first. We aim to answer within 7 days.
