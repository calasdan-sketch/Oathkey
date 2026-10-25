---
name: safeeasyapi
description: Use when a project needs an API key or token (OpenAI, Stripe, GitHub, Resend ...). Ask the person to connect it with safeeasyapi; never read, write, request or print a key yourself.
---

# API keys: ask, never touch

A key you see ends up in your memory and the conversation log. So you never
handle one. You ASK; the person's own terminal and browser do the rest.

## What to do

1. Find out what is missing: call the `needs_keys` tool (optionally with the
   project folder). It returns service names, variable names and a status
   (`present`, `missing`, `unknown`). It never returns a value.
2. For one service, call `request_connect` with the service name (set
   `open_key_page` to true to open the vendor's key page in the person's own
   browser). It returns `{service, env_var, status, instructions}`.
3. Tell the person, in one sentence, to run the command in `instructions` in
   their own terminal, usually `safeeasyapi connect <service>`, or
   `safeeasyapi setup` for everything the project needs. They click the
   vendor's Copy button (or paste into a hidden prompt); the key is tested
   and stored. You are not involved.
4. Write code that uses the environment variable by NAME (for example
   `os.environ["OPENAI_API_KEY"]`). To run it with the key, ask the person
   to start it: `safeeasyapi run <service> -- <command>` (or `--all`). Do
   not run it yourself with a stored key: a program started that way can
   print or reshape the key, and safeeasyapi cannot stop that.
5. Call `request_connect` again to confirm the status is `present`.

## Never

- Ask the person to paste a key into the chat.
- Read, print, grep, copy or edit `.env` files, shell history, the keychain
  or any file that holds a key. (A hook may block this; do not look for a
  way around it.)
- Put a key in code, a command line, a config file, a commit or a log.
- Write a key into `.env` yourself. Use `.env.example` for variable names.

## If something goes wrong

- `status: unknown` means the key is kept in the OS keychain, which is not
  checked from here. Trust the person's word or run the program.
- A key reported "real, but limited" works for the permissions it was given;
  if a call returns 403 later, ask the person to make a key with that
  permission through `safeeasyapi rotate <service>`.
- A key you may have seen by accident: tell the person to rotate it
  (`safeeasyapi rotate <service>`).
