# Copyright (C) 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Entry point del paquete."""
from .approval import (
    VERSION_NONE_SENTINEL,
    ApprovalRecord,
    ApprovalStore,
    InMemoryApprovalStore,
    check_tool_identity,
    descriptor_digest,
)
from .bytefiel import verify_tool
from .ranges import HIDDEN_CODEPOINTS, is_hidden
from .sanitize import Finding, SanitizeResult, find_hidden, sanitize_text, sanitize_tool

__all__ = [
    "HIDDEN_CODEPOINTS",
    "VERSION_NONE_SENTINEL",
    "ApprovalRecord",
    "ApprovalStore",
    "Finding",
    "InMemoryApprovalStore",
    "SanitizeResult",
    "check_tool_identity",
    "descriptor_digest",
    "find_hidden",
    "is_hidden",
    "sanitize_text",
    "sanitize_tool",
    "verify_tool",
]
