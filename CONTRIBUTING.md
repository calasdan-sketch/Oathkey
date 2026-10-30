# Contributing

Thank you. A few rules keep oathkey small and trustworthy:

- **Standard library only.** No new dependencies; a test enforces this.
- **Run the checks** before you open a pull request: `python -m unittest discover -s tests` and `oathkey selftest`.
- **One change per pull request**, with a test that fails without it.
- **Never paste a real API key** into an issue, a test or a log.
- **Security problems go in private:** https://github.com/calasdan-sketch/oathkey/security/advisories/new
