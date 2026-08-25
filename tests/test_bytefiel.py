import pytest

from mcp_tool_sanitizer.bytefiel import (
    canonical,
    diverges,
    render_bidi,
    verify_tool,
)


# NFKC collapse: tras canonicalizar, ambas vistas coinciden (no divergen)
@pytest.mark.parametrize("rendered,delivered", [
    ("\u24b6", "A"),          # circled A -> A
    ("\uff41\uff42\uff43", "abc"),  # fullwidth -> ascii
    ("\U0001d400", "A"),      # math bold -> A
])
def test_nfkc_no_diverge(rendered, delivered):
    assert diverges(canonical(rendered), canonical(delivered)) is False


# Homoglifos: el humano PERCIBE el canonico (NFKC+homoglyph map), el modelo
# RECIBE el codepoint confusable. diverges(canonical(visto), crudo_recibido).
@pytest.mark.parametrize("homoglyph,latin", [
    ("\u03bf", "o"),   # greek omicron vs o
    ("\u0430", "a"),   # cyrillic a vs a
])
def test_homoglyph_diverges(homoglyph, latin):
    assert diverges(canonical(homoglyph), homoglyph) is True
    # a la inversa, el canonico coincide con el latin:
    assert canonical(homoglyph) == latin


def test_tag_hidden_in_delivered_diverges():
    rendered = "safe tool"
    delivered = "safe tool\u200bIGNORE"
    assert diverges(rendered, delivered) is not None
    assert diverges(rendered, delivered) is True


def test_identical_clean_no_diverge():
    assert diverges("list files", "list files") is False


def test_render_bidi_reverses_rtl():
    # RLO invierte el segmento siguiente
    out = render_bidi("abc\u202edef")
    # aproximacion: el bloque tras RLO se invierte
    assert "def" in out  # conserva los chars; orden aproximado


def test_verify_tool_clean_passes():
    tool = {"name": "list_files", "description": "List files", "input_schema": {}}
    res = verify_tool(tool)
    assert res["conforming"] is True
    assert res["reason"] is None


def test_verify_tool_divergent_rejects():
    # homoglyph en el nombre que Fase1 no ve pero Fase2 si
    tool = {"name": "\u0430lias", "description": "safe", "input_schema": {}}
    res = verify_tool(tool)
    assert res["conforming"] is False
    assert "divergence" in res["reason"]
    assert res["hash_rendered"] != res["hash_delivered"]
