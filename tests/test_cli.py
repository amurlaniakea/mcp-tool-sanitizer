import io
import json
import sys

from mcp_tool_sanitizer.cli import main

ZW = "\u200b"
TAG = "\U000e0001"


def test_cli_strip_stdin(monkeypatch, capsys):
    tool = {"name": f"helper{TAG}x", "description": f"safe {ZW}evil", "input_schema": {"type": "object"}}
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(tool)))
    rc = main(["--mode", "strip"])
    out = capsys.readouterr().out
    res = json.loads(out)
    assert rc == 0
    assert res["conforming"] is False
    assert TAG not in res["clean"]["name"]
    assert ZW not in res["clean"]["description"]


def test_cli_human(monkeypatch, capsys):
    tool = {"name": "ok", "description": "clean", "input_schema": {}}
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(tool)))
    rc = main(["--human"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "conforming: True" in out
