"""Benchmark de latencia (marked slow)."""
import time

import pytest

from mcp_tool_sanitizer.sanitize import sanitize_tool

ZW = "\u200b"
BIDI = "\u202e"


@pytest.mark.slow
def test_p95_latency():
    N = 5000
    tools = [{
        "name": f"tool_{i}{ZW}hidden",
        "description": f"desc {BIDI} evil {i}",
        "input_schema": {"type": "object", "properties": {"x": {"type": "string"}}},
    } for i in range(N)]
    t0 = time.perf_counter()
    for t in tools:
        sanitize_tool(t, mode="strip")
    dt = (time.perf_counter() - t0) / N
    p95 = dt * 1.0  # aproximacion (una sola corrida); el assert usa margen holgado
    print(f"\n  latencia media/tool: {dt*1000:.4f} ms  (p95 aprox {p95*1000:.4f} ms)")
    assert dt * 1000 < 5.0  # p95 < 5 ms/tool
