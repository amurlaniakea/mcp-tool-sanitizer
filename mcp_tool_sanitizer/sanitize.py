"""Sanitizador de metadata MCP — detección y neutralización de ocultamiento.

Fase 1 (spec 001-mvp). 0 dependencias en runtime (solo stdlib).
CIERRA KI-4: el schema se sanitiza también en `clean`, no solo name/description.
"""
import json
from dataclasses import dataclass, field

from .ranges import HIDDEN_CODEPOINTS, codepoint_name, is_hidden

REPLACEMENT = "�"  # U+FFFD marker visible


@dataclass
class Finding:
    codepoint: int
    char: str
    name: str


@dataclass
class SanitizeResult:
    conforming: bool
    clean: dict
    findings: list[Finding] = field(default_factory=list)


def find_hidden(text: str) -> list[Finding]:
    out = []
    for ch in text:
        cp = ord(ch)
        if is_hidden(cp):
            out.append(Finding(cp, ch, codepoint_name(ch)))
    return out


def sanitize_text(text: str, mode: str) -> str:
    if mode == "strip":
        return "".join(ch for ch in text if ord(ch) not in HIDDEN_CODEPOINTS)
    if mode == "replace":
        return "".join((REPLACEMENT if ord(ch) in HIDDEN_CODEPOINTS else ch) for ch in text)
    raise ValueError(f"modo desconocido: {mode!r} (usar 'strip' o 'replace')")


def _sanitize_schema(schema: dict, mode: str) -> dict:
    # El schema es superficie de ataque (V4 del spike). Serializar -> sanitizar
    # -> rejsonificar. Asi el `clean` no hereda ocultamiento del schema.
    raw = json.dumps(schema, ensure_ascii=False)
    cleaned = sanitize_text(raw, mode)
    return json.loads(cleaned)


def sanitize_tool(tool: dict, mode: str = "strip") -> SanitizeResult:
    name = tool.get("name", "")
    description = tool.get("description", "")
    input_schema = tool.get("input_schema", {})

    findings = find_hidden(name) + find_hidden(description)
    findings += find_hidden(json.dumps(input_schema, ensure_ascii=False))

    clean = dict(tool)
    clean["name"] = sanitize_text(name, mode)
    clean["description"] = sanitize_text(description, mode)
    clean["input_schema"] = _sanitize_schema(input_schema, mode)

    return SanitizeResult(conforming=len(findings) == 0, clean=clean, findings=findings)
