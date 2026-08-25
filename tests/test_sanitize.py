from mcp_tool_sanitizer.sanitize import sanitize_text


def test_invalid_mode_raises():
    import pytest
    with pytest.raises(ValueError):
        sanitize_text("x", "bogus")
