# Security Policy

## Reporting a Vulnerability

We take security reports seriously. If you find a vulnerability in
`mcp-tool-sanitizer`, please report it privately.

**Contact:** amurlaniakea@gmail.com

Use encrypted mail if possible (PGP available on request). Do **not** open a
public issue for security-sensitive reports.

## What to expect

- **Best effort** response. We aim to acknowledge receipt within a few days,
  but this is a volunteer-maintained project with no SLA — there is no
  guaranteed response time.
- We will try to triage and, if confirmed, fix on `main` as soon as
  feasible. We will credit reporters unless they prefer to stay anonymous.
- Coordinated disclosure: please give us reasonable time to ship a fix before
  public release. "Reasonable" is best-effort, not a contractual window.

## Supported versions

- **Only `main` is covered.** There are no tagged releases or stable branches
  yet, so fixes land on `main` and are not backported.
- If you are running an old commit, update to `main` before reporting — the
  issue may already be fixed.

## Scope

This tool sanitizes MCP tool metadata (TAG-block / zero-width / bidi
concealment codepoints) and provides a byte-faithful approval-view compare.
Out of scope: the MCP server runtime itself, model behavior, and anything
outside the sanitizer's own code.
