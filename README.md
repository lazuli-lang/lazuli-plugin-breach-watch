# @plugin/breach-watch

Blocks reuse of breached credentials at signup/password-change.

This plugin uses Have-I-Been-Pwned's k-anonymity range API: the adapter hashes
the candidate password locally, sends only the first 5 SHA-1 hex characters,
and compares the returned suffixes in-process. The password never leaves the
process.

## Status

Go adapter: in development.
