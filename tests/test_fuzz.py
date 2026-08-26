"""Fuzzing con hypothesis (Bloque A).

Solo dependencia de TEST, no runtime. Tres invariantes sobre el filtro de
ocultamiento:
  Inv1: texto sin codepoints ocultos -> find_hidden([]) siemprevacia.
  Inv2: texto con >=1 oculto inyectado -> find_hidden longitud >= 1.
  Inv3: idempotencia de sanitize_text para cualquier texto y modo.

Si hypothesis encuentra un Falsifying example, NO se silencia: el runner lo
muestra y se espera revision antes de tocar el codigo.
"""
from hypothesis import given, settings
from hypothesis import strategies as st

from mcp_tool_sanitizer.ranges import HIDDEN_CODEPOINTS
from mcp_tool_sanitizer.sanitize import find_hidden, sanitize_text

# Strategy de texto que NO contiene ningun codepoint oculto.
VISIBLE_TEXT = st.text(
    alphabet=st.characters(
        # excluir toda la zona oculta: TAG block, ZW, bidi override
        blacklist_categories=(),
        blacklist_characters="".join(chr(c) for c in HIDDEN_CODEPOINTS),
    ),
    min_size=0,
    max_size=200,
)

# Un solo codepoint oculto muestreado del set real.
HIDDEN_CHAR = st.sampled_from([chr(c) for c in HIDDEN_CODEPOINTS])


@settings(max_examples=1000, deadline=None)
@given(text=VISIBLE_TEXT)
def test_inv1_find_hidden_empty_on_clean_text(text):
    # texto generado que NO tiene ocultos -> find_hidden debe ser []
    assert find_hidden(text) == []


@settings(max_examples=1000, deadline=None)
@given(base=VISIBLE_TEXT, hidden=HIDDEN_CHAR, pos=st.integers(min_value=0, max_value=200))
def test_inv2_find_hidden_detects_injected(base, hidden, pos):
    # inyectar 1 oculto en posicion aleatoria dentro del texto base
    insert_at = min(pos, len(base))
    injected = base[:insert_at] + hidden + base[insert_at:]
    findings = find_hidden(injected)
    # SIEMPRE debe detectar al menos el oculto inyectado
    assert len(findings) >= 1


@settings(max_examples=1000, deadline=None)
@given(
    text=st.text(min_size=0, max_size=200),
    mode=st.sampled_from(["strip", "replace"]),
)
def test_inv3_sanitize_text_idempotent(text, mode):
    once = sanitize_text(text, mode)
    twice = sanitize_text(once, mode)
    assert twice == once


# Bloque B: texto consistentemente de UN SOLO script no-latino (cirilico o
# griego puro, sin mezcla) nunca debe diverger en verify_tool.
from mcp_tool_sanitizer.bytefiel import verify_tool

CYRILLIC_TEXT = st.text(
    alphabet=st.characters(min_codepoint=0x0400, max_codepoint=0x04FF),
    min_size=0, max_size=100,
)
GREEK_TEXT = st.text(
    alphabet=st.characters(min_codepoint=0x0370, max_codepoint=0x03FF),
    min_size=0, max_size=100,
)


@settings(max_examples=1000, deadline=None)
@given(
    name=CYRILLIC_TEXT,
    description=GREEK_TEXT,
    schema=st.sampled_from([{}, {"type": "object"}]),
)
def test_inv4_single_script_nonlatin_never_diverges(name, description, schema):
    tool = {"name": name, "description": description, "input_schema": schema}
    res = verify_tool(tool)
    assert res["conforming"] is True, f"no-latino puro no debe diverger: {name!r} / {description!r}"
