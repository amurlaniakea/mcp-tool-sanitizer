# Contributing

Thanks for wanting to improve `mcp-tool-sanitizer`.

## Setup

```bash
git clone https://github.com/amurlaniakea/mcp-tool-sanitizer.git
cd mcp-tool-sanitizer
python3 -m venv .venv
. .venv/bin/activate
.venv/bin/python -m pip install -e ".[testing]"
```

## Run the checks

```bash
.venv/bin/ruff check mcp_tool_sanitizer tests
.venv/bin/python -m pytest -m "not slow"          # fast suite
.venv/bin/python -m pytest tests/test_fuzz.py     # hypothesis fuzzing (3 + 1 invariants, 1000 examples each)
```

`hypothesis` is a **test-only** dependency — the package itself has **zero
runtime dependencies** (stdlib only). Keep it that way.

## Before opening a PR

- All PRs must pass CI: `lint` + `test-fast` + `test-slow`.
- Keep `dependencies = []` intact; add test deps only under
  `[project.optional-dependencies].testing`.
- If you add behavior, add a test (including a fuzz invariant when it touches
  `sanitize` / `bytefiel`).

## External review

This project undergoes periodic **external security audit** (independent
review of the sanitizer's claims and gaps). We do not promise one for every
change, but substantive changes are typically reviewed before or shortly after
merge. Treat the `KNOWN_ISSUES.md` and README "Limitations" sections as the
honest baseline, not marketing.
