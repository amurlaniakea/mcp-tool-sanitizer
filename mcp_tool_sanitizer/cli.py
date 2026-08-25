"""CLI: stdin JSON -> stdout JSON."""
import argparse
import json
import sys

from .sanitize import sanitize_tool


def main(argv=None):
    p = argparse.ArgumentParser(prog="mcp-tool-sanitizer",
                                description="Detect/neutralize Unicode concealment in MCP tool metadata.")
    p.add_argument("--mode", choices=["strip", "replace"], default="strip")
    p.add_argument("--human", action="store_true", help="Imprime texto legible en vez de JSON.")
    args = p.parse_args(argv)

    raw = sys.stdin.read()
    tool = json.loads(raw)
    res = sanitize_tool(tool, mode=args.mode)

    if args.human:
        sys.stdout.write(f"conforming: {res.conforming}\n")
        sys.stdout.write(f"findings: {len(res.findings)}\n")
        for f in res.findings:
            sys.stdout.write(f"  U+{f.codepoint:04X} {f.name}\n")
        sys.stdout.write("clean: " + json.dumps(res.clean, ensure_ascii=False) + "\n")
    else:
        sys.stdout.write(json.dumps({
            "conforming": res.conforming,
            "clean": res.clean,
            "findings": [{"codepoint": f.codepoint, "name": f.name} for f in res.findings],
        }, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
