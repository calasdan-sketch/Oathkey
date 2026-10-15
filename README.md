# SafeEasyAPI (`safeeasyapi`)

The safe tunnel for API keys. Connecting a website tool usually means 40
minutes of hunting through dashboards, imprecise docs, and fumbling a
secret into the right file. `safeeasyapi` turns it into one command:

```bash
safeeasyapi connect github
```

It opens the exact key page, walks the precise saved steps, takes the key
with hidden input, **validates it with a test API call**, and writes it
straight to `.env` with `0600` permissions. The key is never displayed,
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
  ✓ added STRIPE_SECRET_KEY in .env (mode 0600 — never displayed, never logged)
```

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

Ships with verified recipes for **GitHub**, **Stripe**, and **Resend**.
`safeeasyapi add` walks you through capturing your own (Headroom, RPX, Ponytail…).

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
- `.env` written atomically (temp file + rename) with mode `0600`.
- Validation is a single minimal HTTPS call; only the status is read,
  response bodies are discarded.
- Rejected keys are scrubbed immediately; 3 failed attempts aborts.
- The exact validation URL and HTTP method are printed BEFORE the key is
  asked for; a different-domain validation URL needs a typed `yes`.
- Recipes must use `https://` for the key page and the validation URL —
  plain-`http://` recipes are rejected at load time.
- Recipes contain no secrets — only public how-to.

## Testing

```bash
python3 -m unittest discover -s tests -v
```

83 tests: recipe schema and HTTPS-URL rejection, `.env`
create/update/permissions, full connect flow against a local fake HTTP
service (bearer/header/basic auth, 401 rejection, network failure),
validation-URL preview ordering, typed-`yes` on domain mismatch
(accepts `yes`, aborts on anything else, never prompts for the key first),
MCP provenance labels and quarantine of poisoned directory entries, MCP
protocol round-trip over real stdio, and never-log assertions on every
output path.

## Scope / limits (v0.1.0)

- `.env` file storage only for now; OS keychain / Doppler / Vault backends
  are the natural next step.
- Recipe catalog is curated manually — verify a new service's key URL and
  validation endpoint before trusting it.
- `safeeasyapi mcp` returns recipes; the interactive key paste stays in the
  terminal by design.
