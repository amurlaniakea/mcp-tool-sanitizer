# RESEARCH — mcp-tool-sanitizer

## Thesis (the problem)

The Model Context Protocol lets LLM agents discover and invoke external tools.
A server advertises each tool through a `tools/list` handshake returning a name,
natural-language description, and JSON input schema. The client renders this
metadata once in a one-time approval dialog, then injects it verbatim into the
model's context every turn. **Nothing in the protocol requires the rendered
approval view and the bytes delivered to the model to match.** This gap is a
single structural mechanism — *concealment encoding* — that lets a hostile
server smuggle instructions the human reviewer cannot see.

## Primary source

- **arXiv:2607.05744** — "Unicode TAG-Block Concealment of Tool-Metadata
  Payloads in the Model Context Protocol: An Approval-View Fidelity Gap Across
  Three Independent Server Implementations" (Rashidi, 2026-07-07).
  - Core claim: Unicode's TAG block (U+E0000–U+E007F) has no assigned glyph in
    any mainstream terminal/chat/IDE renderer, so a payload written there is
    absent from what a human reviewer sees while surviving byte-for-byte into
    the model's tokenizer.
  - The paper documents 8 concealment techniques across 5 MCP surfaces; it
    states **4/8 already evade a typical string-matching sanitizer**.
  - The structural fix it identifies as missing: the approval view must be
    **byte-faithful**, not merely "visually plausible".

## Honest positioning vs competition

- [`pantheon-tool-sanitizer`](https://github.com/Igfray/pantheon-tool-sanitizer)
  (Igfray, Apache-2.0, PyPI, 0★/0 forks as of 2026-08-25) implements the same
  string-matching filter (TAG/zero-width/bidi) and explicitly scopes itself as
  "covert-channel control, not a prompt-injection defence." We do not claim
  "no competition exists." Our differentiator is **Fase 2: approval-view
  byte-fidelity** — comparing the hash/bytes of what is rendered against what
  is delivered to the model — which pantheon does not implement and which the
  paper marks as the missing fix.

## Feature → framework mapping

| Feature | Framework mapping |
|---------|-------------------|
| Detect invisible codepoints before approval | OWASP Agentic AI Top 10 (ASI0x) — tool/instruction poisoning surface |
| Covert channel in metadata | NIST SP 800-204 / Zero-Trust: never trust externally-supplied tool text |
| Fase 2 byte-fidelity | Supply-chain integrity: provenance of what the model actually consumes |

## What Fase 1 does NOT claim

Fase 1 is a deterministic, stdlib-only filter over concealment **codepoint
ranges**. It does NOT close the full paper (4/8 evasion techniques). Those
require Unicode normalization (NFKC/NFKD) and byte-fidelity comparison, scoped
to Fase 2. The Spec ACs measure only the per-range vectors, never "100% of the
8 techniques."

## Fase 2 — what it ADDS (and what it does NOT)

Fase 2 (`bytefiel.py`) implements the paper's missing structural fix: the
approval view must be byte-faithful. It models two views — `rendered` (what the
human perceives: NFKC + homoglyph map + hidden stripped) and `delivered` (raw
bytes the model receives) — and rejects the tool if their canonical hashes
diverge.

**Covered by Fase 2 (verified by spike + tests):**
- NFKC compatibility collapse (circled/fullwidth/math-bold → ASCII base).
- Homoglyph divergence: cyrillic/greek look-alikes (e.g. `а` vs `a`, `ο` vs `o`)
  are distinct codepoints; the human sees the Latin base, the model receives the
  confusable. `verify_tool` flags this.
- Hidden codepoints that survive only in the delivered context.

**NOT covered (honest limitations, registered as KI-6 / KI-7):**
- **KI-6 — bidi visual reorder**: `render_bidi()` is a minimal LTR/RTL segment
  reversal using `unicodedata.bidirectional`, NOT the full UAX#9 layout
  algorithm. It covers the paper's override case but not arbitrary typographic
  reordering. A true client-side shim (capturing the actual rendered glyph
  order) is out of scope.
- **KI-7 — homoglyph map exhaustiveness**: `HOMOGLYPH_MAP` is a curated set
  (common typosquatting + paper vectors), NOT the full Unicode confusables
  database (e.g. Unicode TR39). It is a detector, not a complete confusable
  resolver. Extending it is a future task, not a claim of completeness.
- **KI-9 — false positive on legitimate Cyrillic/Greek (CLOSED, 2026-08-25):**
  `HOMOGLYPH_MAP` originally translated ANY common Cyrillic/Greek letter to its
  Latin base unconditionally. Because `rendered = canonical(...)` applied that
  map while `delivered` stayed raw, ANY tool whose `name`/`description` was in
  Russian/Bulgarian/Serbian/Greek diverged and was rejected with no real attack
  (the map could not tell "a confusable slipped into Latin text" from "text
  normally written in another alphabet"). Reproduced: `name="Показать"` → DIVERGE.
  **Fix (design, not cosmetic):** `verify_tool` now uses a mixed-script
  heuristic — the homoglyph map is applied ONLY when the dominant script is
  Latin with a few confusables intercalated (the real typosquatting pattern);
  text consistently in one non-Latin script is left intact (no divergence).
  Tests: legitimate Cyrillic/Greek phrases → conforming; Latin word with 1–2
  Cyrillic/Greek chars intercalated → rejected. Coverage: 60 passed.
