# SafeEasyAPI (`safeeasyapi`)

The safe tunnel for API keys. Connecting a website tool usually means 40
minutes of hunting through dashboards, imprecise docs, and fumbling a
secret into the right file. `safeeasyapi` turns it into one command:

```bash
safeeasyapi connect github
```

It opens the exact key page, walks the precise saved steps, takes the key
with hidden input, **validates it with a test API call**, and writes it
straight to `.env` with owner-only permissions — or, with
`--store keychain`, into your OS keychain. The key is never displayed,
never logged, never in shell history.

## Install

Zero dependencies — Python 3.10+ stdlib only.

```bash
pip install git+https://github.com/calasdan-sketch/safeeasyapi
safeeasyapi --version
```

That installs the `safeeasyapi` command (`py -m safeeasyapi` / `python -m
safeeasyapi` works too). From a checkout: `pip install .`

**Windows:** run it from PowerShell or Windows Terminal. Under Git Bash /
mintty the hidden key prompt (`getpass`) may echo what you type or appear
to hang, because mintty is not a Windows console; if you must use Git
Bash, prefix the command with `winpty` (`winpty safeeasyapi connect
stripe`).

## Commands

```bash
safeeasyapi list                        # services with saved recipes
safeeasyapi connect <service>           # guided key setup -> .env
safeeasyapi connect <service> --env-file /path/to/.env
safeeasyapi connect <service> --store keychain   # OS keychain instead of .env
safeeasyapi run <service> -- <command>  # run with a keychain-stored key in its env
safeeasyapi rotate <service>            # replace a stored key
safeeasyapi forget <service>            # remove the key: OS keychain entry + .env line(s)
safeeasyapi add                         # capture a new service recipe interactively
safeeasyapi find <query>                # find free public APIs for a task
safeeasyapi mcp                         # stdio MCP server (for Claude Code)
```

Output can be piped (`safeeasyapi list | head -1`): when the reader
stops early the command ends quietly with exit status 1 — no traceback,
no "Exception ignored" noise at exit. On Windows Python reports that
closed pipe as a plain `OSError` 22 instead of `BrokenPipeError` (a
short output only fails when it is flushed); that is recognised too, for
every command and for the MCP server.

## A connect, annotated

```bash
$ safeeasyapi connect stripe

  Connect Stripe  (key opens in your browser)        # 1. your browser opens
                                                     #    the exact key page
    1. If it asks, make sure you are in the right mode: Test keys start
       with sk_test_, live keys with sk_live_
    ...
  Key page: https://dashboard.stripe.com/apikeys

  This key will be validated with: GET https://api.stripe.com/v1/balance
                                                       # 2. EXACT validation
                                                       #    endpoint shown BEFORE
                                                       #    you ever paste the key

  Paste your API key (hidden):                         # 3. hidden paste —
  validating…                                          #    key never displayed
  ✓ added STRIPE_SECRET_KEY in .env (mode 0600 - never displayed, never logged)
```

(On Windows the line says `owner-only ACL` instead of `mode 0600` — see
*Where the key goes*.)

The validation preview is the security hinge: you see exactly where the
key will be sent, and the recipe must use `https://` for both the key page
and the validation URL (a plain-`http://` recipe is rejected). If the
validation URL belongs to a **different owner** than the key page,
`safeeasyapi` stops and requires you to type `yes` — anything else aborts,
and no key is ever asked for or sent:

```bash
  This key will be validated with: GET https://third-party-validator.example/check
  ⚠ The validation URL is on a DIFFERENT domain than the key page above (third-party-validator.example vs acme.test).
    Your key will be sent to both domains. Make sure you trust both.
  Type 'yes' to continue:                            # Enter alone aborts
```

"Different owner" means a different **registrable domain**, not a
different hostname: `dashboard.stripe.com` and `api.stripe.com` are both
`stripe.com`, so Stripe, GitHub (`github.com` / `api.github.com`) and
Resend connect without a prompt — the transcript above is the whole
flow. Multi-part public suffixes are understood (`a.co.uk` and `b.co.uk`
are two owners; so are `a.github.io` and `b.github.io`). Case, a trailing
dot, a port and `user@` in front of the host never change the answer, and
names with non-English letters are compared in their `xn--` (punycode)
form, so `bücher.example` and `xn--bcher-kva.example` are one owner. When
the domains differ and either one is such a name, the warning shows both
spellings (`аpple.com [xn--pple-43d.com] vs apple.com`, where the first
`а` is Cyrillic) so a look-alike letter cannot hide. A few vendors
genuinely keep their API on a second domain (Anthropic's console is
`platform.claude.com`, its API `api.anthropic.com`; Mailgun `.com` /
`.net`; Google AI Studio / `googleapis.com`; Notion `.so` / `.com`):
their **built-in** recipes name that host in `validate.trusted_hosts`
and connect without a prompt, with a one-line note. Only recipes shipped
inside the package get that shortcut — a recipe from
`~/.safeeasyapi/recipes` (yours, or one somebody sent you) always prompts
when the domains differ, whatever it claims.

In the transcript above the key is shown as `sk-…` — in reality it is
never printed at all, not even redacted.

If the validation endpoint **redirects** somewhere else — another host,
another port, or from `https://` down to `http://` — the credential
header is stripped before the redirect is followed (what browsers and
`requests` do) and the connect stops with *validation endpoint redirected
to a different origin* instead of guessing from a response that proves
nothing about the key. A redirect within the same origin (`/me` →
`/me/`) is followed normally.

**Run it on your own computer.** The check only means something when it
is sent straight from your machine. Cloud coding agents, sandboxes and
some company proxies add their own credentials to outgoing requests, so
the API can answer "valid" for any key, even a made-up one. If a key you
know is wrong gets accepted, that is the likely reason: run
`safeeasyapi connect` in a terminal on your own computer instead.

## Where the key goes

**`.env` file (default).** `ENV_VAR=<key>` is written to `.env` (or
`--env-file`; a missing folder is created), private from the first byte:
the content goes into a randomly named temp file created with
`O_CREAT|O_EXCL` and mode `0600` in the same directory, is fsync'd, and
is then atomically renamed over the target. No reader ever sees a
half-written or world-readable key, a crash leaves the old file
untouched, and a file somebody pre-planted at a guessable name is never
written through. An existing `ENV_VAR=` or `export ENV_VAR=` line is
replaced in place (keeping `export`); a value with anything outside
`A-Z a-z 0-9 _ . + / = : -` is written double-quoted with `"` and `\`
escaped, so Node dotenv, python-dotenv, docker compose and a shell
`source` all read the whole key back (an unquoted `ab#c d"e` would have
been silently truncated). If the file cannot be written (`--env-file` in
a folder that is a file, or unwritable), the connect ends with
`✗ the key was validated but could NOT be saved` and exit 1 — the key is
never printed, and nothing is written.

If the same variable is set more than once in the file, the **last**
line is the one that is updated: python-dotenv, Node dotenv, docker
compose and a shell `source` all let the last assignment win, so
changing the first would save a key that never takes effect. Earlier
lines are left exactly as they were, and the success line says so
(`ACME_API_KEY appears twice in .env; I updated the one that takes
effect`).

Only your key's line changes; every other byte of an existing file is
kept exactly as it was. A file saved in a Windows code page (cp1252: an
accented comment from Notepad) is not valid UTF-8, and a key is still
saved into it without complaint. A CRLF file stays CRLF and an LF file
stays LF: the line that is added or changed uses the file's own style, a
missing final newline is added in that style, and a brand-new file uses
LF. The byte-order mark that PowerShell and some Windows editors put at
the start of a UTF-8 file is kept, and does not hide a key on the first
line. Two things are refused with one plain sentence and exit 1,
**before** the browser opens or any key is asked for: a `.env` that is a
**link** to another file (a key is never written through a link, and a
link is never silently replaced — name the real file with `--env-file`
if you mean it), and a file that is not plain text, such as the UTF-16
that Windows PowerShell's `>` creates (appending UTF-8 to it would wreck
it — re-save it as UTF-8).

- Linux / macOS: the file is `chmod 0600` (owner read/write only).
- Windows: POSIX mode bits don't exist, so the file's ACL is reduced to
  the current user (`icacls <file> /inheritance:r /grant:r <user>:(F)`,
  best effort). The success line says `owner-only ACL` only when `icacls`
  actually succeeded; otherwise it says `could not restrict ACL` so you
  know the file has the folder's default permissions.

`safeeasyapi forget <service>` undoes a connect: it deletes the keychain
entry (when this OS has a keychain) and removes the `ENV_VAR=` line from
`.env` (`--env-file` to point elsewhere), and says what it removed. If
the variable is set more than once, every one of those lines goes —
otherwise an older one would take over again — and it says how many.

**OS keychain (`--store keychain`).** No `keyring` package; each OS
uses what it ships with, and the key never goes through `argv`:

| OS      | backend                                                            | how |
|---------|--------------------------------------------------------------------|-----|
| macOS   | login Keychain, via the `security` command                         | commands fed over stdin (`security -i`), generic password `safeeasyapi:<service>` / account `<ENV_VAR>` |
| Windows | Credential Manager (Windows Vault), via `ctypes` → `advapi32` `CredWriteW`/`CredReadW`/`CredDeleteW` | generic credential `safeeasyapi:<service>`, persisted for the local machine, UTF-16-LE blob like `cmdkey` |
| Linux   | Secret Service (GNOME Keyring / KWallet) via `secret-tool`, when installed | key on stdin; attributes `service=safeeasyapi account=<ENV_VAR> slug=<service>` |
| anything else, or the tool is missing | — | falls back to the `.env` file and says so |

A keychain-stored key is consumed with `safeeasyapi run <service> --
<command>`: the key is read back and placed in that one child process's
environment, never printed. (Your app does not need to change — it
still reads `$STRIPE_SECRET_KEY`.) Without a keychain backend `run`
exits 1 and tells you the key lives in `.env`.

## Find public APIs

SafeEasyAPI is also a discovery front door. `safeeasyapi find` searches the public
APIs directory (~2,100 free APIs, cached locally for 7 days):

```bash
safeeasyapi find "weather" --auth No        # only keyless APIs
safeeasyapi find "crypto price" --limit 5
```

APIs needing a key point straight back at the tunnel:

```
    Weatherstack [apiKey]
      Real-time weather
      https://weatherstack.com/  (Weather)
      needs a key — save its recipe with `safeeasyapi add`.
```

### MCP co-work skills

The MCP server exposes the directory to Claude Code as tools, so the agent
discovers free APIs instead of improvising or reaching for paid services:

- `find_public_apis {query, auth?, category?, limit?}` — search the directory
- `get_public_api {name}` — details plus wiring: no-auth APIs get a
  call-it-directly note; `apiKey` APIs get the exact `safeeasyapi add` +
  `safeeasyapi connect` flow (the agent never asks the user to paste a key)

No secrets ever pass through MCP — only public how-to.

## Why it exists

Agents (and humans) forget per-service key flows and improvise imprecise
steps. Recipes are the memory: plain JSON files with the key URL, the
exact click path, scopes, and a validation endpoint. Teach it once with
`safeeasyapi add`, use it forever — and Claude Code can pull the exact recipe via
`safeeasyapi mcp` instead of guessing.

Ships with 29 recipes inside the package (so `pip install` carries
them), each checked against the provider's own docs for the key page,
the validation endpoint and the auth header, and smoke-tested live with
a fake key (every one answers with a clean "key rejected"):

| area | services |
|---|---|
| LLM / AI | `openai`, `anthropic`, `google-gemini`, `groq`, `mistral`, `cohere`, `huggingface`, `together`, `openrouter`, `replicate` |
| speech | `elevenlabs`, `deepgram`, `assemblyai` |
| infra | `github`, `supabase` (Management API token), `vercel`, `netlify`, `cloudflare`, `pinecone` |
| email / payments | `stripe`, `resend`, `sendgrid`, `mailgun`, `postmark` (server token) |
| productivity / search | `notion`, `airtable`, `discord` (bot token), `tavily`, `brave-search` |

Each validation call is a free, read-only request (list models, "who am
I", verify token) — except `brave-search`, whose only authenticated
endpoint is the search itself, so validating costs one tiny query (the
recipe says so). Not included because the shape does not fit a
one-key/one-GET check: Twilio (Account SID + token pair), Slack (`auth.test`
answers HTTP 200 even to a bad token), Linear (GraphQL needs a POST
body), Shopify (per-store URL), Perplexity/Exa/Serper (no free GET
endpoint), Fireworks (the documented list-models URL is per account).

`safeeasyapi add` walks you through capturing your own (Headroom, RPX,
Ponytail…); those are saved to `~/.safeeasyapi/recipes/`
(`%USERPROFILE%\.safeeasyapi\recipes\` on Windows) and override a
built-in recipe with the same slug. `--recipes-dir` writes elsewhere.
A slug is `[a-z0-9][a-z0-9_-]{0,63}` — it becomes the file name, so
`../../evil` is refused — and the expected status codes must be numbers
(`200,201`). Besides `bearer` / `header` / `basic`, a recipe's
`validate` block may set `auth.scheme` (`Token` for Deepgram, `Bot` for
Discord), `auth.username` for Basic auth with the key as the password
(Mailgun's `api:<key>`), static `headers` (`anthropic-version`,
`Notion-Version`), and `reject` — the statuses that mean "bad key" when
a provider does not answer 401/403 (Google and Resend say 400, Brave
422).

## The MCP server

Add to Claude Code (`claude mcp add`) or `~/.claude.json`:

```json
{ "mcpServers": { "safeeasyapi": {
  "command": "python", "args": ["-m", "safeeasyapi", "mcp"] } } }
```

(`python` is the Windows launcher's name; on macOS/Linux use whatever
runs your Python 3.) Tools: `list_services`, `get_recipe`,
`find_public_apis`, `get_public_api`. The recipe tells the agent the
exact steps and ends with: run `safeeasyapi connect <service>` in a
terminal — never ask the user to paste the key into chat. The server
speaks JSON-RPC 2.0 properly: notifications (`notifications/cancelled`,
`notifications/initialized`, anything without an `id`) are never
answered, a non-object message gets `-32600 Invalid Request`, bad JSON
`-32700 Parse error`, and `params` that is not an object (`null`, a list,
a string…), `arguments` that is not an object, or a missing or wrongly
typed required argument gets `-32602 Invalid params` — never a crash or
`-32603` — after which the server simply carries on. (A tool-level miss,
such as a service that has no recipe, is an ordinary result with
`isError`.)

## Security model

- Key input via `getpass` (no echo); never printed, never logged.
- `.env` written atomically through a random, exclusive, `0600` temp
  file + rename (owner-only ACL on Windows); keychain storage never
  passes the key on a command line.
- A `.env` that is a link is refused, never written through or replaced,
  and the permission step (chmod / icacls) never follows a link to change
  something else.
- Validation is a single minimal HTTPS call; only the status is read,
  response bodies are discarded. The credential never follows a
  redirect to another origin or to plain `http://`.
- Rejected keys are scrubbed immediately; 3 failed attempts aborts.
- The exact validation URL and HTTP method are printed BEFORE the key is
  asked for; a validation URL under another registrable domain needs a
  typed `yes` (built-in recipes may declare their vendor's second API
  domain; user recipes cannot).
- A reply that is not HTTP at all (a captive portal, a TLS mismatch, a
  non-HTTP service on the port) is reported as a validation error, not a
  traceback.
- Recipes must use `https://` for the key page and the validation URL —
  plain-`http://` recipes (and ones whose URL is malformed) are rejected
  at load time.
- Recipes contain no secrets — only public how-to.

## Testing

```bash
python -m unittest discover -s tests -v
python -m pytest -q                    # same suite
```

249 tests, stdlib only, no network beyond 127.0.0.1: recipe schema,
HTTPS-URL rejection and malformed URLs, slug validation, every shipped
recipe (parses, https, file name = slug, credential header built),
`.env` create/update/permissions (random exclusive temp file, crash
safety, never world-readable, value quoting round-trip, `export` lines,
an unwritable path, a cp1252 file, a byte-order mark, CRLF/LF/mixed
endings and a variable set twice (the last line wins) kept
byte-for-byte, a UTF-16 file and a symbolic link refused, permissions
that never follow a link), redirect credential stripping against a local
redirecting server pair, full connect flow against a local fake HTTP
service (bearer/header/basic auth, custom schemes and static headers,
401 rejection, custom reject statuses, network failure, a non-HTTP
reply), validation-URL preview ordering, registrable-domain matching
(punycode names, trailing dots, ports, `user@`, a look-alike letter
shown in the warning) and typed-`yes` on a real mismatch, keychain
dispatch for every OS with the real keychain faked (the Windows path
through a fake `advapi32`), the `.env` fallback, `forget`, the honest
Windows ACL line, MCP provenance labels and quarantine of poisoned
directory entries, JSON-RPC notification, invalid-request and
invalid-params handling, MCP protocol round-trip over real stdio, a
wheel build that must contain the recipes, the package metadata and one
version number everywhere, output into a pipe that closes early (the
real thing, and the different error Windows gives, simulated), and
never-log assertions on every output path. Tests point
`HOME`/`USERPROFILE`/`APPDATA` at a throwaway directory, so they never
read your real `~/.safeeasyapi` or `.env`.

Windows 11 is a first-class target: the wire format of the MCP server
is UTF-8 bytes regardless of console code page, console output is
reconfigured to replace unencodable characters instead of crashing, and
every text file is opened as UTF-8.

## Scope / limits (v0.3.1)

- Keychain storage is best effort and opt-in (`--store keychain`); the
  `.env` file is the default and the fallback. No Doppler / Vault
  backends.
- Recipe catalog is curated manually — verify a new service's key URL and
  validation endpoint before trusting it. Provider dashboards move:
  if a key page URL redirects, follow it and send a fix.
- `safeeasyapi mcp` returns recipes; the interactive key paste stays in the
  terminal by design.
