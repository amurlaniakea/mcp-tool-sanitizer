import io
import json
import sys

from mcp_tool_sanitizer.cli import main


def test_cli_bytefiel_rejects_divergent(monkeypatch, capsys):
    tool = {"name": "аlias", "description": "safe", "input_schema": {}}
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(tool)))
    rc = main(["--bytefiel"])
    out = capsys.readouterr().out
    res = json.loads(out)
    assert rc == 0
    assert res["conforming"] is False
    assert res["byte_fiel"]["conforming"] is False


def test_cli_bytefiel_passes_clean(monkeypatch, capsys):
    tool = {"name": "list_files", "description": "clean", "input_schema": {}}
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(tool)))
    rc = main(["--bytefiel"])
    out = capsys.readouterr().out
    res = json.loads(out)
    assert rc == 0
    assert res["conforming"] is True
