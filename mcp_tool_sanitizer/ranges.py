# Copyright (C) 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Codepoints de ocultamiento (concealment encoding) para metadata MCP.

Basado en arXiv:2607.05744 (Rashidi, 2026-07-07): TAG-block, zero-width,
bidi override. Unicodedata los clasifica; el rango es determinista.
"""
import unicodedata

# U+E0000 - U+E007F : Tags block. Sin glifo asignado en terminal/chat/IDE.
TAG_BLOCK = range(0xE0000, 0xE0080)

# Zero-width / invisible: U+200B, U+200C, U+200D, U+FEFF, U+2060, U+2061-2064
ZWSP_VARIANTS = frozenset({0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064})

# Bidi override: U+202A-202E (LRE/RLE/LRO/RLO/PDF) y U+2066-2069 (LRI/RLI/FSI/PDI)
BIDI_OVERRIDE = frozenset(range(0x202A, 0x202F)) | frozenset(range(0x2066, 0x206A))

HIDDEN_CODEPOINTS = frozenset(TAG_BLOCK) | ZWSP_VARIANTS | BIDI_OVERRIDE


def codepoint_name(ch: str) -> str:
    try:
        return unicodedata.name(ch, "<no-name>")
    except Exception:  # noqa: BLE001 -- degradar a nombre desconocido es el comportamiento previsto
        return "<no-name>"


def is_hidden(cp: int) -> bool:
    return cp in HIDDEN_CODEPOINTS
