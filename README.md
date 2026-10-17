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
git clone <repo> && cd safeeasyapi
# no-install alias (run from the repo root):
alias seapi="python3 -m safeeasyapi"  # or just use the `safeeasyapi` binary
# or: pip install .   # provides the `safeeasyapi` console script
```

## Commands

```bash
safeeasyapi list                        # services with saved recipes
safeeasyapi connect <service>           # guided key setup -> .env
safeeasyapi connect <service> --env-file /path/to/.env
safeeasyapi connect <service> --store keychain   # OS keychain instead of .env
safeeasyapi run <service> -- <command>  # run with a keychain-stored key in its env
safeeasyapi rotate <service>            # replace a stored key
safeeasyapi add                         # capture a new service recipe interactively
safeeasyapi find <query>                # find free public APIs for a task
safeeasyapi mcp                         # stdio MCP server (for Claude Code)
```

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
validation URL is on a **different domain** than the key page, `safeeasyapi` stops
and requires you to type `yes` — anything else aborts, and no key is ever
asked for or sent:

```bash
  This key will be validated with: GET https://third-party-validator.example/check
  ⚠ The validation URL is on a DIFFERENT domain than the key page above.
    Your key will be sent to both domains. Make sure you trust both.
  Type 'yes' to continue:                            # Enter alone aborts
```

In the transcript above the key is shown as `sk-…` — in reality it is
never printed at all, not even redacted.

If the validation endpoint **redirects** somewhere else — another host,
another port, or from `https://` down to `http://` — the credential
header is stripped before the redirect is followed (what browsers and
`requests` do) and the connect stops with *validation endpoint redirected
to a different origin* instead of guessing from a response that proves
nothing about the key. A redirect within the same origin (`/me` →
`/me/`) is followed normally.

## Where the key goes

**`.env` file (default).** `ENV_VAR=<key>` is written to `.env` (or
`--env-file`), private from the first byte: the content goes into a
randomly named temp file created with `O_CREAT|O_EXCL` and mode `0600`
in the same directory, is fsync'd, and is then atomically renamed over
the target. No reader ever sees a half-written or world-readable key, a
crash leaves the old file untouched, and a file somebody pre-planted at
a guessable name is never written through.

- Linux / macOS: the file is `chmod 0600` (owner read/write only).
- Windows: POSIX mode bits don't exist, so the file's ACL is reduced to
  the current user (`icacls <file> /inheritance:r /grant:r <user>:(F)`,
  best effort) and the success line says `owner-only ACL`.

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

Ships with verified recipes for **GitHub**, **Stripe**, **Resend** and
**OpenRouter**, inside the package (so `pip install .` carries them).
`safeeasyapi add` walks you through capturing your own (Headroom, RPX,
Ponytail…); those are saved to `~/.safeeasyapi/recipes/`
(`%USERPROFILE%\.safeeasyapi\recipes\` on Windows) and override a
built-in recipe with the same slug. `--recipes-dir` writes elsewhere.

## The MCP server

Add to Claude Code (`claude mcp add`) or `~/.claude.json`:

```json
{ "mcpServers": { "safeeasyapi": {
  "command": "python3", "args": ["-m", "safeeasyapi", "mcp"],
  "cwd": "/path/to/safeeasyapi" } } }
```

Tools: `list_services`, `get_recipe`. The recipe tells the agent the exact
steps and ends with: run `safeeasyapi connect <service>` in a terminal — never ask
the user to paste the key into chat.

## Security model

- Key input via `getpass` (no echo); never printed, never logged.
- `.env` written atomically through a random, exclusive, `0600` temp
  file + rename (owner-only ACL on Windows); keychain storage never
  passes the key on a command line.
- Validation is a single minimal HTTPS call; only the status is read,
  response bodies are discarded. The credential never follows a
  redirect to another origin or to plain `http://`.
- Rejected keys are scrubbed immediately; 3 failed attempts aborts.
- The exact validation URL and HTTP method are printed BEFORE the key is
  asked for; a different-domain validation URL needs a typed `yes`.
- Recipes must use `https://` for the key page and the validation URL —
  plain-`http://` recipes are rejected at load time.
- Recipes contain no secrets — only public how-to.

## Testing

```bash
python3 -m unittest discover -s tests -v
python3 -m pytest -q                    # same suite
```

112 tests, stdlib only, no network beyond 127.0.0.1: recipe schema and
HTTPS-URL rejection, `.env` create/update/permissions (random exclusive
temp file, crash safety, never world-readable), redirect credential
stripping against a local redirecting server pair, full connect flow
against a local fake HTTP service (bearer/header/basic auth, 401
rejection, network failure), validation-URL preview ordering,
typed-`yes` on domain mismatch, keychain dispatch for every OS with the
real keychain faked (the Windows path through a fake `advapi32`), the
`.env` fallback, MCP provenance labels and quarantine of poisoned
directory entries, MCP protocol round-trip over real stdio, a wheel
build that must contain the recipes, and never-log assertions on every
output path. Tests point `HOME`/`USERPROFILE`/`APPDATA` at a throwaway
directory, so they never read your real `~/.safeeasyapi` or `.env`.

Windows 11 is a first-class target: the wire format of the MCP server
is UTF-8 bytes regardless of console code page, console output is
reconfigured to replace unencodable characters instead of crashing, and
every text file is opened as UTF-8.

## Scope / limits (v0.2.0)

- Keychain storage is best effort and opt-in (`--store keychain`); the
  `.env` file is the default and the fallback. No Doppler / Vault
  backends.
- Recipe catalog is curated manually — verify a new service's key URL and
  validation endpoint before trusting it.
- `safeeasyapi mcp` returns recipes; the interactive key paste stays in the
  terminal by design.
