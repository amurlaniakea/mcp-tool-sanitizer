"""Entry point del paquete."""
from .ranges import HIDDEN_CODEPOINTS, is_hidden
from .sanitize import Finding, SanitizeResult, find_hidden, sanitize_text, sanitize_tool

__all__ = [
    "HIDDEN_CODEPOINTS",
    "Finding",
    "SanitizeResult",
    "find_hidden",
    "is_hidden",
    "sanitize_text",
    "sanitize_tool",
]
