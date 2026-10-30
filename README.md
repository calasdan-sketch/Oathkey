# oathkey

**Let your AI use your API keys without ever holding them.**

- The key sits in your computer's own keychain. When your AI needs an API, it asks oathkey to make the call.
- The reply is cleaned of the key, anything that changes data needs your click, and every call is written to a log.
- Plain Python, nothing else to install. No account, no server, no cloud. MIT license.

## Try it in 60 seconds

```
pipx install git+https://github.com/calasdan-sketch/oathkey
oathkey get github            # opens the key page; you click Copy; oathkey tests it and saves it
oathkey call github GET /user # a window asks once to allow github reads: click Yes. Prints the answer, never the key
oathkey selftest              # watch oathkey attack itself; prints how many attacks it stopped
oathkey install               # plug it into Claude, Cursor or VS Code, then restart that app
```

Now ask your AI: *"Who am I on GitHub?"* It uses your key through oathkey and never holds it.
To see what it did: `oathkey audit show`.

> No `pipx`? `pip install git+https://github.com/calasdan-sketch/oathkey` works too.
> Needs Python 3.10 or newer. If your computer says `oathkey` is not found, close the window and open a new one, or run `python -m oathkey`.

## Why not just put the key in a `.env` file?

AI coding tools read files in your project, and they paste what they read into a chat that someone else's computer sees. A key in a file, a chat or a config can leak in seconds. With oathkey your AI never receives the key: it stays in your computer's keychain and oathkey adds it to the request itself. `oathkey get` will not leave a key in a file in your project folder.

## How it works

1. **You save a key once** (`oathkey get <service>`). It goes into the Windows, Mac or Linux keychain. oathkey tests it with a harmless call first.
2. **Your AI asks for an action**, not a key: "GET /user on GitHub". It can only name the service, the method, the path and the data.
3. **oathkey makes the call itself**, to the service's real address only, adds the key, and hands back the answer with any trace of the key removed.

Reads are allowed after one "yes" per AI session (a window asks the first time). Anything that creates, changes or deletes pops up a window and waits for you. `oathkey call` is you making the same brokered call by hand, with no AI involved.

## Check it yourself (don't trust us)

| Command | What it shows |
|---|---|
| `oathkey selftest` | Runs oathkey's rules against simulated attacks, using a made-up key and a pretend server: a server that echoes the key in disguise, tricky addresses, names that point inside your network, writes without permission, edits to the log. Prints how many it stopped (`--verbose` lists each) and exits with an error if any gets through. It does not test the live network layer, so treat it as a check of the rules, not a security audit. |
| `oathkey doctor` | One-paste health check: keychain, activity log, which AI tools it is plugged into, and a quick self-attack run. |
| `oathkey scan` | Finds API keys lying in your project files, AI-tool settings and shell history (`--git` also checks git history). It never prints a whole key. |
| `oathkey audit verify` | Checks the activity log was not edited, cut short or deleted. If it did not check out, `audit reset` starts a fresh log and keeps the old one. |

oathkey uses only Python's own standard library, and a test in the repository ([tests/test_stdlib_only.py](tests/test_stdlib_only.py)) fails if that ever changes.

## Commands

**Start**

- `get <service>` - one command: opens the key page, takes the key when you click Copy (then empties the clipboard), tests it, saves it in the keychain. `--no-clipboard` uses hidden typing instead.
- `start` - a short guided tour: what is connected and what to do next.
- `install` / `uninstall` - plug oathkey into (or remove it from) Claude Desktop, Cursor, Claude Code and VS Code.
- `list` - the services it knows.

**Daily**

- `call <service> <METHOD> <path>` - make one brokered call yourself (`--query name=value`, `--data '{...}'`, `--json`).
- `status` - what is connected.
- `audit show` - the last calls, with a warning if the log does not check out.
- `rotate <service>` - replace a stored key.
- `forget <service>` - remove a stored key.

**Security**

- `selftest`, `doctor`, `scan` (with `--git`, `--staged`, `--install-hook`) as above.

**Advanced**

- `serve` - a local web door for AI tools that cannot use MCP (OpenAI-style functions, Ollama, scripts).
- `mcp` - the MCP server your AI app starts for you.
- `run <service> -- <command>` - run a program with the key in its environment. For you, not for an AI with a shell: a program you start can print its own environment.
- `remote`, `trust-server`, `deploy` - use a key on your own server over ssh.
- `add` - make your own service recipe. `find` - look for free public APIs.

Many commands accept `--json` (try `list`, `status`, `selftest`, `doctor`, `audit`). Exit codes: 0 fine, 1 problem, 2 wrong usage, 3 service not found, 5 refused by policy, 7 network problem.

## Services

35 services are built in, from GitHub and Stripe to OpenAI and AWS. `oathkey list` shows them all.

Not listed? `oathkey add` makes a recipe in a minute. A recipe cannot send a built-in service's key to a different server.

## What oathkey does not stop

It reduces risk; it does not remove it, and no independent security review has been done yet.

- **Malware, or an AI that can run programs as you.** Anything running as you can read your keychain. Run risky agents in a separate account or container.
- **Harmful things a key is allowed to do.** Give each key only the permissions it needs, at the provider.
- **The clipboard.** `get` empties it right away, but other programs or clipboard-history tools may see the key while it is there.
- **A log that can't be rewritten.** The log shows accidents and casual edits. Someone running as you could rewrite it.

The full list is in [SECURITY.md](SECURITY.md). The longer user guide (every flag, where keys are stored, two-value keys, testing) is in [docs/guide.md](docs/guide.md).

## License

MIT. See LICENSE.
