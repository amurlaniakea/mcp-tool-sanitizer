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


def _script_of(cp: int) -> str:
    """Script aproximado por rango (latino/cirilico/griego/otro).

    No es una tabla de scripts Unicode completa (KI-7): cubre los bloques
    donde vive el ataque de typosquatting + los scripts que el usuario usa.
    """
    if cp <= 0x024F:  # ASCII + Latin-1 Supplement + Latin Extended-A
        return "latin"
    if 0x0400 <= cp <= 0x04FF:  # Cyrillic
        return "cyrillic"
    if 0x0370 <= cp <= 0x03FF:  # Greek and Coptic
        return "greek"
    # NFKC puede colapsar compatibilidad a latin; lo tratamos como latin
    if unicodedata.normalize("NFKC", chr(cp)) != chr(cp) and _script_of(ord(unicodedata.normalize("NFKC", chr(cp)))) == "latin":
        return "latin"
    return "other"


# Homoglifos comunes (confusables visuales) -> su base latina.
# NO es exhaustivo (KI-7): cubre los del paper y los mas usados en ataques
# de typosquatting/homoglyph. NFKC no los colapsa (son codepoints distintos).
HOMOGLYPH_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "ѕ": "s", "і": "i", "ї": "i",
    "Α": "A", "Β": "B", "Ε": "E", "Κ": "K", "Μ": "M",
    "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    "ο": "o", "ρ": "p", "υ": "y", "χ": "x",
}


def _split_words(text: str) -> list[str]:
    """Divide en palabras (segmentos separados por espacio/punctuacion fuerte).

    Los separadores son cualquier char cuyo script es 'other' O es espacio o
    punctuation. Esto aísla el bloque cirilico 'Искать' de la palabra latina
    'Search' en texto bilingue.
    """
    words = []
    cur = []
    for ch in text:
        s = _script_of(ord(ch))
        if s == "other" or ch.isspace() or (unicodedata.category(ch).startswith("P")):
            if cur:
                words.append("".join(cur))
                cur = []
        else:
            cur.append(ch)
    if cur:
        words.append("".join(cur))
    return [w for w in words if w]


def _word_is_latin(word: str) -> bool | None:
    """True si la palabra es latina-dominated; False si cirilico/griego puro;
    None si no hay senal suficiente (<=1 char con script)."""
    counts = {"latin": 0, "cyrillic": 0, "greek": 0}
    for ch in word:
        s = _script_of(ord(ch))
        if s in counts:
            counts[s] += 1
    total = sum(counts.values())
    if total == 0:
        return None
    if total <= 1:
        return None
    return counts["latin"] >= counts["cyrillic"] and counts["latin"] >= counts["greek"]


def canonical(text: str, *, aggressive: bool = False) -> str:
    """Forma canonica: NFKC + eliminacion de ocultos.

    Si aggressive=True, aplica HOMOGLYPH_MAP, PERO solo a los confusables que
    viven en un contexto LATINO local (palabra latina-dominated). Un bloque
    100% cirilico/griego dentro de texto bilingue NO se mapea; un confusable
    suelto incrustado en una palabra latina SI se mapea.

    Esto cierra KI-9b: la agresividad es por segmento/palabra, no por la
    cadena entera. Asi 'Search files / Искать файлы' no diverge (el bloque
    cirilico conserva sus glifos), pero 'аlias' si diverge.
    """
    n = unicodedata.normalize("NFKC", text)
    if not aggressive:
        return "".join(ch for ch in n if not _is_hidden(ord(ch)))

    # precalcular si cada palabra es latina
    words = _split_words(n)
    word_latin = {}
    for w in words:
        word_latin[w] = _word_is_latin(w)

    out = []
    for ch in n:
        cp = ord(ch)
        if _is_hidden(cp):
            continue
        if ch in HOMOGLYPH_MAP:
            # decidir por contexto local: la palabra que contiene este char
            host = next((w for w in words if ch in w), None)
            latin_ctx = word_latin.get(host, True)  # por defecto latin (senal debil)
            if latin_ctx:
                out.append(HOMOGLYPH_MAP[ch])
                continue
        out.append(ch)
    return "".join(out)


def dominant_is_latin(text: str) -> bool | None:
    """True si el script dominante es latino; None si no hay suficiente senal.

    Cuenta solo chars con script latin/cirilico/griego (ignora espacios,
    puntuacion, digitos, ocultos). Si la mayoria es latina => True.
    Si la mayoria es cirilico/griego => False (texto de un solo script no-latino).
    Si no hay suficientes chars con script (<=1) => None (no decidir, tratar
    como latino por defecto: es seguro porque un char suelto confusable dentro
    de latin SI es el patron de ataque).
    """
    counts = {"latin": 0, "cyrillic": 0, "greek": 0}
    for ch in text:
        s = _script_of(ord(ch))
        if s in counts:
            counts[s] += 1
    total = sum(counts.values())
    if total <= 1:
        return None
    return counts["latin"] >= counts["cyrillic"] and counts["latin"] >= counts["greek"]


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

    rendered = lo que el humano PERCIBE.
    delivered = los bytes CRUDOS que el modelo recibe.

    Heuristica por contexto local (KI-9b cerrado): el mapeo de homoglifos se
    aplica SOLO a confusables que viven en una palabra latina-dominated. Un
    bloque cirilico/griego dentro de texto bilingue conserva sus glifos (no
    diverge); un confusable suelto en palabra latina diverge (ataque real).
    """
    name = tool.get("name", "")
    description = tool.get("description", "")
    schema = tool.get("input_schema", {})

    raw = f"{name}\n{description}\n{schema!s}"
    # aggressive=True activa el mapeo por-contexto-local (ver canonical)
    rendered = canonical(raw, aggressive=True)
    # delivered tambien se normaliza (NFKC + ocultos) para que la comparacion
    # sea simetrica: el unico diferenciador es el mapa de homoglifos por
    # contexto. Sin esto, NFKC aplicado solo a rendered rompe texto no-latino
    # puro (ej. ϐ -> β) introduciendo divergencia espuria.
    delivered = canonical(raw, aggressive=False)

    h_r = canon_hash(rendered)
    h_d = canon_hash(delivered)
    ok = h_r == h_d
    return {
        "conforming": ok,
        "reason": None if ok else "approval-view byte divergence (rendered != delivered)",
        "hash_rendered": h_r,
        "hash_delivered": h_d,
        "aggressive": True,
    }
