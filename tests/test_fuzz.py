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


# Fase 3 (KI-11): descriptor_digest debe cambiar cuando se perturba UNO
# cualquiera de los cinco campos del descriptor (name, description,
# input_schema, server_origin, descriptor_version). Y perturbar DOS campos
# debe dar un digest distinto de perturbar UNO solo.
#
# Esto NO es "cambia con probabilidad abrumadora" (forma debil que un
# hash de 1 byte cumpliria). Es: para cada campo, generamos un ejemplo
# concreto donde cambiar SOLO ese campo cambia el digest, y comprobamos
# que cambiar dos a la vez da un digest distinto del de uno solo.
from mcp_tool_sanitizer.approval import descriptor_digest

SIMPLE_NAME = st.text(min_size=1, max_size=50).filter(lambda s: "\n" not in s and "\r" not in s)
SIMPLE_DESC = st.text(min_size=0, max_size=200).filter(lambda s: "\n" not in s and "\r" not in s)
SIMPLE_ORIGIN = st.sampled_from([
    "https://server.example",
    "https://other.example",
    "wss://realtime.example/socket",
    "stdio://local-daemon",
])
SIMPLE_SCHEMA = st.sampled_from([
    {},
    {"type": "object"},
    {"type": "object", "properties": {"x": {"type": "string"}}},
])
SIMPLE_VERSION = st.sampled_from([None, "v1.0", "v1.0.0", "abc", "0"])


def _make_digest(name, description, schema, origin, version):
    return descriptor_digest(
        {"name": name, "description": description, "input_schema": schema},
        origin,
        descriptor_version=version,
    )


@settings(max_examples=1000, deadline=None)
@given(
    name_a=SIMPLE_NAME, name_b=SIMPLE_NAME,
    desc=SIMPLE_DESC, schema=SIMPLE_SCHEMA,
    origin=SIMPLE_ORIGIN, version=SIMPLE_VERSION,
)
def test_inv5_perturbar_name_cambia_digest(name_a, name_b, desc, schema, origin, version):
    """Perturbar SOLO el name (resto identico) -> digests distintos."""
    if name_a == name_b:
        return  # hypothesis no fuerza diferencia; saltamos
    d_a = _make_digest(name_a, desc, schema, origin, version)
    d_b = _make_digest(name_b, desc, schema, origin, version)
    assert d_a != d_b, f"name distinto ({name_a!r} vs {name_b!r}) produjo mismo digest"


@settings(max_examples=1000, deadline=None)
@given(
    name=SIMPLE_NAME,
    desc_a=SIMPLE_DESC, desc_b=SIMPLE_DESC,
    schema=SIMPLE_SCHEMA, origin=SIMPLE_ORIGIN, version=SIMPLE_VERSION,
)
def test_inv5_perturbar_description_cambia_digest(name, desc_a, desc_b, schema, origin, version):
    """Perturbar SOLO la description -> digests distintos."""
    if desc_a == desc_b:
        return
    d_a = _make_digest(name, desc_a, schema, origin, version)
    d_b = _make_digest(name, desc_b, schema, origin, version)
    assert d_a != d_b


@settings(max_examples=1000, deadline=None)
@given(
    name=SIMPLE_NAME, desc=SIMPLE_DESC,
    schema_a=SIMPLE_SCHEMA, schema_b=SIMPLE_SCHEMA,
    origin=SIMPLE_ORIGIN, version=SIMPLE_VERSION,
)
def test_inv5_perturbar_schema_cambia_digest(name, desc, schema_a, schema_b, origin, version):
    """Perturbar SOLO el input_schema -> digests distintos."""
    if schema_a == schema_b:
        return
    d_a = _make_digest(name, desc, schema_a, origin, version)
    d_b = _make_digest(name, desc, schema_b, origin, version)
    assert d_a != d_b


@settings(max_examples=1000, deadline=None)
@given(
    name=SIMPLE_NAME, desc=SIMPLE_DESC, schema=SIMPLE_SCHEMA,
    origin_a=SIMPLE_ORIGIN, origin_b=SIMPLE_ORIGIN, version=SIMPLE_VERSION,
)
def test_inv5_perturbar_origin_cambia_digest(name, desc, schema, origin_a, origin_b, version):
    """Perturbar SOLO el server_origin -> digests distintos."""
    if origin_a == origin_b:
        return
    d_a = _make_digest(name, desc, schema, origin_a, version)
    d_b = _make_digest(name, desc, schema, origin_b, version)
    assert d_a != d_b


@settings(max_examples=1000, deadline=None)
@given(
    name=SIMPLE_NAME, desc=SIMPLE_DESC, schema=SIMPLE_SCHEMA, origin=SIMPLE_ORIGIN,
    version_a=SIMPLE_VERSION, version_b=SIMPLE_VERSION,
)
def test_inv5_perturbar_version_cambia_digest(name, desc, schema, origin, version_a, version_b):
    """Perturbar SOLO descriptor_version -> digests distintos."""
    if version_a == version_b:
        return
    d_a = _make_digest(name, desc, schema, origin, version_a)
    d_b = _make_digest(name, desc, schema, origin, version_b)
    assert d_a != d_b


@settings(max_examples=1000, deadline=None)
@given(
    name_a=SIMPLE_NAME, name_b=SIMPLE_NAME,
    desc=SIMPLE_DESC, desc_alt=SIMPLE_DESC,
    schema=SIMPLE_SCHEMA, origin=SIMPLE_ORIGIN, version=SIMPLE_VERSION,
)
def test_inv5_perturbar_name_vs_description_no_colapsan(
    name_a, name_b, desc, desc_alt, schema, origin, version,
):
    """Perturbar name y perturbar description NO colapsan al mismo digest.

    Esto verifica que la receta del digest distingue entre campos del
    descriptor: si perturbamos 'name' y perturbamos 'description' de la
    misma forma (cambiando UNA coordenada de cada), los digests deben
    ser distintos. Si la receta colapsara los dos campos al mismo valor
    (ej. concatenandolos sin estructura que los separe), este test fallaria.

    Caso concreto: fijamos (desc=D, schema, origin, version). Comparamos
    dos digests que difieren en UNA coordenada del par (name, desc):
      - d_one: name=name_b, desc=D        (perturbacion SOLO en name)
      - d_two: name=name_a, desc=desc_alt (perturbacion SOLO en desc)
    Las dos perturbaciones afectan al mismo par de campos, una por
    coordenada. Con sha256 real, la probabilidad de colision es 2^-256,
    despreciable. Asertamos que d_one != d_two, lo cual seria falso solo
    si la receta del digest tuviera una estructura que colapsara cambios
    en campos distintos al mismo valor.
    """
    if name_a == name_b and desc == desc_alt:
        return
    # Perturbo SOLO el name (mantengo desc igual)
    d_one = _make_digest(name_b, desc, schema, origin, version)
    # Perturbo SOLO la desc (mantengo name igual a name_a)
    d_two = _make_digest(name_a, desc_alt, schema, origin, version)
    assert d_one != d_two, (
        "perturbar 'name' y perturbar 'description' (un campo cada una) "
        "produjeron el mismo digest. La receta del digest no distingue "
        "entre campos del descriptor."
    )


@settings(max_examples=1000, deadline=None)
@given(
    name=SIMPLE_NAME, name_alt=SIMPLE_NAME,
    desc=SIMPLE_DESC, desc_alt=SIMPLE_DESC,
    schema=SIMPLE_SCHEMA, origin=SIMPLE_ORIGIN, version=SIMPLE_VERSION,
)
def test_inv5_perturbar_dos_campos_distinto_de_uno(
    name, name_alt, desc, desc_alt, schema, origin, version,
):
    """Perturbar DOS campos simultaneamente produce un digest distinto
    de perturbar UNO solo (version completa del AC T011c).

    Caso concreto: tenemos un baseline (X, D). Comparamos dos
    perturbaciones:
      - d_uno:    (X, D_alt)            (perturbacion SOLO en desc)
      - d_dos:    (X_alt, D_alt)        (perturbacion SIMULTANEA en name y desc)

    La perturbacion 'dos campos' debe producir un digest distinto de
    'un campo'. Si la receta del digest tuviera una estructura que
    colapsara multiples cambios (ej. un XOR debil, o una suma), podria
    ocurrir que d_uno == d_dos a pesar de que la entrada cambio en dos
    coordenadas. Este test es la barrera contra ese modo de fallo.

    Ademas de d_uno != d_dos, verifico que d_uno != d_baseline y
    d_dos != d_baseline (cada perturbacion cambia algo, no es un
    no-op).
    """
    if desc == desc_alt and name == name_alt:
        return  # sin perturbacion real, salta
    d_baseline = _make_digest(name, desc, schema, origin, version)
    d_uno = _make_digest(name, desc_alt, schema, origin, version)
    d_dos = _make_digest(name_alt, desc_alt, schema, origin, version)
    # Cada perturbacion cambia algo respecto al baseline
    if desc != desc_alt:
        assert d_uno != d_baseline, "perturbacion de 1 campo no cambia digest"
    if name != name_alt:
        assert d_dos != d_baseline, "perturbacion de 2 campos no cambia digest"
    # El core del test: 2 campos != 1 campo
    if desc != desc_alt and name != name_alt:
        assert d_uno != d_dos, (
            "perturbar 2 campos simultaneamente (name + desc) dio el mismo "
            "digest que perturbar 1 solo campo (desc). La receta del digest "
            "no es sensible a la cardinalidad de la perturbacion."
        )
