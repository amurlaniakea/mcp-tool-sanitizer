"""Approval-view byte-fiel (Fase 2).

Garantiza que los bytes que el cliente renderiza en el dialogo de aprobacion
sean identicos a los que se entregan al modelo. Modela dos vistas:
  - rendered: lo que el humano VE (glifo en pantalla)
  - delivered: lo que el modelo RECIBE (string crudo en contexto)

El paper 2607.05744: el protocolo no obliga a que coincidan. Nosotros
comparan un hash canonico (NFKC + ocultos quitados) de ambas vistas.

0 dependencias runtime (solo stdlib). Limite honesto en KI-6: el bidi visual
reorder real requiere layout completo de Unicode; aqui se aproxima.
"""
import hashlib
import unicodedata


def _is_hidden(cp: int) -> bool:
    if 0xE0000 <= cp <= 0xE007F:
        return True
    if cp in {0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064}:
        return True
    if 0x202A <= cp <= 0x202E:
        return True
    return 0x2066 <= cp <= 0x2069


# Homoglifos comunes (confusables visuales) -> su base latina.
# NO es exhaustivo (KI-7): cubre los del paper y los mas usados en ataques
# de typosquatting/homoglyph. NFKC no los colapsa (son codepoints distintos).
HOMOGLYPH_MAP = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0455": "s", "\u0456": "i", "\u0457": "i",
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u039a": "K", "\u039c": "M",
    "\u039f": "O", "\u03a1": "P", "\u03a4": "T", "\u03a5": "Y", "\u03a7": "X",
    "\u03bf": "o", "\u03c1": "p", "\u03c5": "y", "\u03c7": "x",
}


def canonical(text: str) -> str:
    """Forma canonica: NFKC + mapa de homoglifos + eliminacion de ocultos."""
    n = unicodedata.normalize("NFKC", text)
    out = []
    for ch in n:
        cp = ord(ch)
        if _is_hidden(cp):
            continue
        out.append(HOMOGLYPH_MAP.get(ch, ch))
    return "".join(out)


def canon_hash(text: str) -> str:
    """Hash de la forma YA canonica que se le pase.

    NO canonicaliza internamente: quien llama decide que lado es el canonico.
    Asi `verify_tool` puede hashear `canonical(rendered)` vs `delivered` crudo
    y que la divergencia (homoglyph/bidi) se mantenga.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def diverges(rendered: str, delivered: str) -> bool:
    """rendered y delivered deben venir ya en la forma a comparar.

    Uso tipico: diverges(canonical(vista_humano), bytes_crudos_modelo).
    """
    return canon_hash(rendered) != canon_hash(delivered)


def render_bidi(text: str) -> str:
    """Aproximacion de reordenamiento bidi (KI-6).

    No es el algoritmo UAX#9 completo: reordena segmentos por nivel RTL
    basico usando unicodedata.bidirectional. Cubre el caso del paper
    (override que invierte el orden visual) pero NO el layout tipografico.
    """
    out = []
    rtl_buffer = []
    for ch in text:
        b = unicodedata.bidirectional(ch)
        if b in ("R", "RLE", "RLO", "AL"):
            rtl_buffer.append(ch)
        elif b in ("L", "LRE", "LRO"):
            if rtl_buffer:
                rtl_buffer.reverse()
                out.extend(rtl_buffer)
                rtl_buffer = []
            out.append(ch)
        else:
            if rtl_buffer:
                rtl_buffer.append(ch)
            else:
                out.append(ch)
    if rtl_buffer:
        rtl_buffer.reverse()
        out.extend(rtl_buffer)
    return "".join(out)


def verify_tool(tool: dict) -> dict:
    """Compara la vista renderizada vs la entregada (byte-fiel).

    rendered = lo que el humano PERCIBE = canonical(name/desc/schema)
        (NFKC colapsa homoglifos a su base latino: cirilico 'a' -> 'a').
    delivered = los bytes CRUDOS que el modelo recibe (sin canonicalizar).
    Si divergen => el tool engaña al revisor (ve X, modelo recibe Y).
    """
    name = tool.get("name", "")
    description = tool.get("description", "")
    schema = tool.get("input_schema", {})

    rendered = canonical(f"{name}\n{description}\n{schema!s}")
    delivered = f"{name}\n{description}\n{schema!s}"

    # rendered ya es canonico (NFKC + homoglyph + ocultos); delivered es crudo.
    h_r = canon_hash(rendered)
    h_d = canon_hash(delivered)
    ok = h_r == h_d
    return {
        "conforming": ok,
        "reason": None if ok else "approval-view byte divergence (rendered != delivered)",
        "hash_rendered": h_r,
        "hash_delivered": h_d,
    }
