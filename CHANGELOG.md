# Changelog

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
