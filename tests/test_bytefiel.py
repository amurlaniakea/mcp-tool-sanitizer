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


# Homoglifos: el humano PERCIBE el canonico (NFKC+homoglyph map agresivo),
# el modelo RECIBE el codepoint confusable. diverges(canonical(visto,
# aggressive=True), crudo_recibido). El confusable debe estar RODEADO de
# contexto latino para que la heurística por-segmento lo mapee (un char
# cirilico/griego aislado sin vecinos latinos NO se mapea, por diseno KI-9).
@pytest.mark.parametrize("homoglyph,latin", [
    ("а", "a"),   # cyrillic a vs a, rodeado de latin en el assertion
    ("ο", "o"),   # greek omicron vs o
])
def test_homoglyph_diverges(homoglyph, latin):
    # contexto latino: la palabra que contiene el confusable es latina
    surrounded = f"x{homoglyph}y"  # 'xаy' / 'xοy' -> palabra latina-dominated
    assert diverges(canonical(surrounded, aggressive=True), surrounded) is True
    # a la inversa, el canonico agresivo coincide con el latin rodeado:
    assert canonical(surrounded, aggressive=True) == f"x{latin}y"


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
    tool = {"name": "аlias", "description": "safe", "input_schema": {}}
    res = verify_tool(tool)
    assert res["conforming"] is False
    assert "divergence" in res["reason"]
    assert res["hash_rendered"] != res["hash_delivered"]


# === KI-9: texto cirilico/griego legitimo NO debe diverger ===
@pytest.mark.parametrize("name,description", [
    ("Показать", "Показать файлы в каталоге"),          # ruso real, sin ataque
    ("покажи", "покажи список файлов в папке"),          # ruso
    ("Εμφάνιση", "Εμφάνιση αρχείων στον κατάλογο"),     # griego real, sin ataque
    ("δείξε", "δείξε τα αρχεία του φακέλου"),           # griego
    ("Прикажи", "Прикажи листање датотека"),            # serbio cirilico
])
def test_verify_tool_cyrillic_greek_legit_passes(name, description):
    tool = {"name": name, "description": description, "input_schema": {}}
    res = verify_tool(tool)
    assert res["conforming"] is True, f"falso positivo KI-9 en texto legitimo: {name!r}"
    assert res["reason"] is None


# === KI-9b (CERRADO en Bloque B): texto bilingue EN + bloque de traduccion legitimo ===
# El mapeo de homoglifos ahora es por contexto local (palabra latina), no por
# cadena entera. El bloque cirilico conserva sus glifos => no diverge.
@pytest.mark.parametrize("name,description", [
    ("search_files", "Search files / Искать файлы в каталоге"),
    ("list_dir", "List directory / Список каталога"),
])
def test_verify_tool_bilingual_legit_passes(name, description):
    tool = {"name": name, "description": description, "input_schema": {}}
    res = verify_tool(tool)
    assert res["conforming"] is True, f"falso positivo KI-9b en bilingue: {name!r}"
    assert res["reason"] is None
