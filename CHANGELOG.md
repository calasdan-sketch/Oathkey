# Changelog

## 0.6.3

- **Security / UX.** The question after a key was taken from the clipboard
  ("Is that the key?") echoed whatever was typed or pasted, and a person who
  pasted the key there saw it on screen and had it accepted. Now:
  - the question is read without echo (a password-style read; from a pipe it
    shows nothing either), and the rest of a multi-line paste is discarded;
  - only Enter, y and n answer it; anything long or key-shaped is refused with
    "That looked like a key. Do not paste it here. Nothing was saved.", is not
    kept, and the question is asked again (three tries, then cancelled);
  - the wording says the key is already taken, hidden, and not to paste.
  - the same reader is used for the y/N questions that can follow a key: the
    plain-text `.env` fallback of `--store keychain`, `export`, and
    `scan --validate`.
  - the hidden paste prompt drops terminal paste markers and leftover lines.

## 0.6.2

Fixes for what the test matrix (Linux, macOS, Windows; Python 3.10-3.14) found.

- `run`: Ctrl-C that lands while the output readers are still starting no
  longer ends in "could not acquire lock for <stdout> at interpreter shutdown"
  (exit -6) or a traceback; the interrupt is held until the readers are up,
  every reader is finished before `run` leaves, and the child is never left
  running. Exit status is 130 as documented.
- MCP: JSON nested more than 200 levels deep is a Parse error (-32700) on every
  Python version; before, Python 3.14 could parse it and the reply was
  Invalid params (-32602). A reply nested deeper than that is likewise an
  Internal error on every Python (macOS 3.14 could write it).
- Hook: a `safeeasyapi` program in the current folder is never used as the hook
  command, also when the folder has another spelling (macOS `/var` and
  `/private/var`, links, Windows case and short names).
- `detect` does not read a symbolic link on Windows (no `O_NOFOLLOW` there).
- Tests only: Windows-aware hook, symlink, file-mode and own-recipe tests.

## 0.6.1

Fixes from an independent review of 0.6.0.

**Security**
- A redirect from a query-auth check (OpenWeather, your own recipes) no longer
  prints the address with the key in it: only scheme, host and path are shown,
  and every validation error is scrubbed of the key and its encodings.
- The hook also refuses `safeeasyapi run --no-redact`, keychain readers
  (`secret-tool`, `security find-generic-password`, `cmdkey`, `Get-Secret`,
  `keyring`), `/proc/*/environ` and `~/.safeeasyapi`. `run --no-redact` is
  refused unless input and output are a terminal. Agent-facing text now says
  "ask the person to run it". README states plainly what an agent that can
  use `run` can still do.
- `.env` writes take a lock (20 parallel writers used to leave 7 keys), the
  read no longer follows a link swapped in after the check, and a result is
  re-read after writing.
- A manifest's `env_file` must be a `.env`-style name inside the project;
  `safeeasyapi.json` is only looked for up to the git project's top folder
  (or the folder itself); `--project-dir` names it explicitly. `connect`,
  `rotate`, `forget` and `export` use the manifest's env file like `run`.
- The MCP output guard blanks only secret-looking values (not ordinary
  settings) and never member names. `needs_keys` stays inside the project;
  `request_connect` opens at most 3 key pages a minute in all.
- Recipe patterns that could run for ages on crafted input are refused.
- `doctor-recipes` never visits private addresses (also not through a
  redirect), and each service has a time budget. The weekly workflow pins its
  actions by commit.
- A recipe that sends the key to localhost or a private network asks you to
  confirm first. `export` names the repository / Vercel project it will send
  to, taken from the git remote / `.vercel`, and uses it explicitly.

**Behaviour**
- Copy-and-go: a stale key-shaped value is emptied, a second identical Copy is
  noticed, Ctrl-C cancels, the clipboard is emptied after the prompt fallback,
  host:port, paths, e-mail addresses and plain words are not taken as keys,
  and a key with no documented shape is confirmed (length only).
- AWS: a clock more than 5 minutes off is reported as that, not as a dead key.
- OpenAI: a 403 is "real key with limits", not a dead one.
- Redaction also catches upper and lower case forms.
- `safeeasyapi skill install` copies the agent skill (now shipped in the wheel).

## 0.6.0

One flow from the vendor's key page into your project, and the agent never
touches a key.

**Recipes (all 36 re-checked against the vendors' own documentation)**
- Two separate ideas for a key's shape: `accept` (what `--clipboard` will
  take: only documented shapes, matched from the start, so a valid key is never
  refused - removed for Groq, Hugging Face, OpenAI, OpenRouter, SendGrid, Tavily,
  GitHub, Vercel and Cloudflare) and `detect` (what `scan` looks for: the
  commonly used shapes are kept, labelled "format is a guess"). The old
  `pattern` still works. Fixes a bug where a prefix-only gate would have been
  matched against the whole key.
- Keys that are real but limited are no longer "dead": `validate.limited` (a
  403 from a Stripe restricted key, a Supabase / Vercel / GitHub fine-grained /
  SendGrid token without that permission) and `validate.body_rules` (Resend's
  401 `restricted_api_key`). `connect` stores the key and says what it cannot do.
- `least_privilege` (shown by `connect`) and `unverified` (parts the docs do
  not confirm, shown by `connect`) on the recipes.
- Corrections: AWS uses the documented STS POST; OpenRouter checks `/api/v1/key`
  and wants a credit limit; eBay and Spotify are judged by the token call alone;
  Cohere `/v1/models`; PayPal live and `paypal-sandbox` are separate; Mailgun asks
  for the main account key; Postmark a server token; GitHub recommends
  fine-grained tokens; ElevenLabs, Vercel and Notion key pages; many "starts
  with ..." claims the vendors never made are gone; OpenWeather's two-hour
  delay and Brave's plan requirement are said plainly.
- `scan` also finds Supabase `sb_secret_` keys.

**New commands**
- `doctor-recipes`: visits each recipe's key page, docs and test server over
  HTTPS with no key and reports moved or gone pages (exit 1 on rot). A weekly
  GitHub Action keeps one issue up to date. `CONTRIBUTING.md` and a pull
  request template ask for a docs link and a fake-key test. A real run found
  three moved pages, now fixed.
- `init`, `setup`, `status` and `safeeasyapi.json` (names only, committed):
  detect the services a project uses (never opening a real `.env`), connect every
  missing one in order (skipping those already stored, resumable), and list where
  each key lives and how old it is, with a rotate hint after 90 days (a small
  local record holds dates, never keys).
- `run` reads the keychain or the `.env` file, `--all` injects every service in
  the manifest, and the program's output is scrubbed of the key by default
  (`--redact`; exact value, base64, hex, URL- and JSON-encoded forms;
  `--no-redact` to turn it off). The limits are in the README.
- `export <service> --to github|vercel`: through `gh secret set` / `vercel env
  add`, with the key on standard input only, never in a command line.
- MCP tools `request_connect` and `needs_keys`: the agent asks, the person runs
  `safeeasyapi connect` in their own terminal. Answers hold names and statuses
  only; a second filter blanks any reachable secret. The hook message and the new
  `skills/safeeasyapi/SKILL.md` point agents at this.
- Windows: `--clipboard` falls back to the hidden prompt when clipboard history
  (Win+V) is on, because the history keeps a copy this tool cannot remove
  (`--allow-clipboard-history` overrides).
- Error messages no longer repeat an unknown service or tool name that is long
  or odd (it could be a key pasted in the wrong place).

**Tests** run with no real network at all: any connection that is not to
127.0.0.1 fails the test.

## 0.5.2

- The hook now also covers `Edit`, `Write`, `MultiEdit` and `NotebookEdit`:
  they are refused for a real `.env` file (a key the agent writes has passed
  through the agent, and a `Write` can overwrite yours). Templates
  (`.env.example` ...) stay writable. The agent is told "Claude can't write to
  .env - your keys stay out of the chat. Run: safeeasyapi connect <service>
  (or edit the file yourself)."
- `SAFEEASYAPI_HOOK_ALLOW_WRITE=1` (in Claude Code's environment) allows
  those writes; reads stay refused.
- `hook install` upgrades an older install's matcher in place (only our own
  entry); `hook status` says OUTDATED when the matcher is the old one.

## 0.5.1

Fixes from a security review of 0.5.0.

- `scan` can no longer be made to hang: the `NAME=value` pattern was
  quadratic (20,000 `A`s on one line took 9-26 seconds, a 1 MB file ten
  minutes). Every pattern now runs on bounded pieces of a line, each file has
  a 10-second budget, and a long minified line is scanned in 8 KB pieces
  instead of being cut off after 20,000 characters.
- `scan` no longer says "no keys found" after a partial look. Only files that
  will be read count toward the limits (an agent file behind 50,000 empty
  files is found), build output (`target`, `build`, `dist`, `.next` ...) is
  skipped, and when any limit is hit (too many files or folders, too deep, a
  folder or agent file that could not be read, out of time) the report says
  `INCOMPLETE` and the exit status is 2 (`--fail-on` never gives a clean 0).
  JSON has `incomplete`; SARIF has a notification.
- `scan --validate`: a key found only by its variable name is no longer sent
  to the service its name suggests unless it has that service's key format
  (a wrong guess used to send a key to the wrong vendor and then say "delete
  the line"). Only a 401 means rejected, now worded "rejected ... may not be
  an X key; rotate it if you are unsure"; a 403 is "could not be checked".
  Names with `webhook`, `anon`, `maps` or `public` are never matched to a
  service. With no terminal and no `--yes` the report is still printed (keys
  "not checked") instead of being dropped.
- `scan` uses only the recipes shipped in the package. Your own recipes in
  `~/.safeeasyapi/recipes` (their regular expression and the host a key is
  sent to) are used only with the new `--my-recipes`, under a timer, and with
  `--validate` they need a typed `y` every time, even with `--yes`.
- `scan` finds more: a PEM private key on one line inside JSON, a password in
  a connection URL, `*_PASSWORD` names, an unnamed `Bearer <token>`, Slack and
  Discord webhook URLs, Stripe `whsec_` secrets, and UTF-16 `.env` files
  (what PowerShell's `>` writes). A stand-in is recognised by word, not by
  letters inside a key, so real keys containing `abc123` or `fake` are no
  longer thrown away. Trailing `.`, `-`, `_` are no longer part of a match
  ("the key is sk-...abc." redacts and validates the key, not the full stop).
  The same file reached through a link is reported once, under its real path;
  the "skipped" line states the real reasons.
- `hook status` no longer runs a command read from a settings file (a cloned
  repository's `.claude/settings.json` could run anything). It tests only the
  command this installation would write, without a shell.
- The hook now also covers PowerShell and Monitor (it missed both). `hook
  check` reads all of its input however big; input too big or not JSON is
  searched for a `.env` name as text. New `hook install --fail-closed`
  (`onFailure: block`, Claude Code 2.1.295+).
- The hook is recognised by a `statusMessage` marker or by the exact command
  0.5.0 wrote, not by "ends with hook check". It always installs into a group
  of its own; another group's matcher and handlers are never edited.
- Windows: the hook is written in the documented exec form (`command` +
  `args`) so a backslash or space in the path survives Git Bash and
  PowerShell; `--shell-form` is the fallback for an older Claude Code. The
  self-test starts the hook the way Claude Code does (no shell). Not run on a
  real Windows machine - see the README.
- Settings are written through a symbolic link; every change gets its own
  backup in `~/.safeeasyapi/backups` (not once, and not inside the project).
- The release workflow now requires the tagged commit to be on `main`, the
  tests to pass first, the sdist's own tests to pass, and has time limits.
- README: what the hook does NOT stop; what `--fail-on live` does with keys
  that could not be checked.

## 0.5.0

- New: `safeeasyapi scan [PATH]` finds API keys that leaked into files an AI
  agent can read (`.env*`, `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`,
  `.cursorrules`, the `.claude` folder, `.mcp.json`) and says, for each one,
  where it is and what to do. Offline by default; a key is shown as at most
  its first 4 and last 2 characters; stand-in values are ignored. It skips
  `.git`, `node_modules`, binaries, files over 1 MB, pipes, devices and links
  leading outside the folder.
- `scan --validate` asks each key's own service whether it still works
  (`live` / `dead` / `unknown`). It prints the host first and needs a `y` or
  `--yes`; https only; a check on another domain still needs a typed `yes`.
- `scan --json`, `--sarif` (SARIF 2.1.0), `--fail-on live|any`, `--all`.
  Exit status 0 clean, 1 keys found, 2 could not run.
- New: `safeeasyapi hook install | uninstall | status` adds a Claude Code
  PreToolUse hook that refuses Read, Grep and Bash calls touching `.env`
  files (templates like `.env.example` are allowed). It merges into
  `~/.claude/settings.json` (or `--project`), never overwrites other hooks,
  and is safe to run twice. `hook check` is the hook itself.
- The built-in key formats are now also used to recognise a key anywhere in
  a file, not only on the clipboard.

## 0.4.2

- Safer on Windows: `icacls` is started from the Windows System32 folder and
  `gh` (for `--via-cli`) by its full path, never from the current folder, so a
  cloned repository cannot slip in a program of its own.
- The `.env` file is locked to its owner before the key is written into it,
  not after.
- After saving to `.env`, a warning if the file is inside a git repository and
  not ignored by it.
- `--store keychain` no longer falls back to a plain-text `.env` on its own:
  it asks `[y/N]` (default no) and, with no terminal to ask on, saves nothing
  and exits 1. A key stored in the keychain is read back to confirm it is there.
- A recipe of your own in `~/.safeeasyapi/recipes` that replaces a built-in
  one is now announced in `list` and at the start of `connect`.
- Copy-and-go never takes a link as the key, says plainly that the clipboard
  is emptied, and 8 built-in recipes (OpenAI, Anthropic, Groq, Hugging Face,
  Replicate, SendGrid, Tavily, OpenRouter) recognise their own key format.
- A folder named `.env` is refused before the browser opens.
- Packaging: GitHub Actions run the tests on Linux, Windows and macOS (Python
  3.10, 3.12, 3.14) and build the package; tagged releases publish to PyPI.
  `.gitattributes` keeps line endings consistent. Python 3.14 and the three
  operating systems are listed in the package metadata.

## 0.4.1

- The public-API list ignores a cache dated in the future.
- Recipes saved with a byte-order mark load.
- Windows device names (`nul`, `con`, ...) are refused as recipe names.
- `forget` looks the Secret Service entry up first.
- HTTP error responses are closed.

## 0.4.0

- Copy-and-go (`--clipboard`), two-value credentials, every common check
  (headers, basic, field, query, OAuth2 client credentials, AWS SigV4),
  `--via-cli`, 6 new recipes.

## 0.3.3

- Recipes may contain non-breaking spaces and emoji; closed standard streams
  give one line; `forget` says what it removed.

## 0.3.2

- `.env` values that are safe to `source`; hostile recipe text is escaped;
  validation uses GET/HEAD only; keychain timeouts; public-suffix heuristics.

## 0.3.1

- Byte-exact `.env` saves, no writes through links, CRLF and duplicate keys,
  international host names, MCP error codes, closed pipes on Windows.

## 0.3.0

- Registrable-domain comparison, safer key saving, `forget`, 25 verified
  recipes.

## 0.2.0

- Stops redirect key leaks, private `.env` writes, install layout fix, OS
  keychain storage.
