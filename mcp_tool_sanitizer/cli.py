"""CLI: stdin JSON -> stdout JSON."""
import argparse
import json
import sys

from .bytefiel import verify_tool
from .sanitize import sanitize_tool


def main(argv=None):
    p = argparse.ArgumentParser(prog="mcp-tool-sanitizer",
                                description="Detect/neutralize Unicode concealment in MCP tool metadata.")
    p.add_argument("--mode", choices=["strip", "replace"], default="strip")
    p.add_argument("--bytefiel", action="store_true",
                   help="Fase 2: tambien verifica approval-view byte-fiel (homoglyph/bidi divergence).")
    p.add_argument("--human", action="store_true", help="Imprime texto legible en vez de JSON.")
    args = p.parse_args(argv)

    raw = sys.stdin.read()
    tool = json.loads(raw)
    res = sanitize_tool(tool, mode=args.mode)
    out = {
        "conforming": res.conforming,
        "clean": res.clean,
        "findings": [{"codepoint": f.codepoint, "name": f.name} for f in res.findings],
    }
    if args.bytefiel:
        bf = verify_tool(tool)
        out["byte_fiel"] = bf
        # si Fase1 o Fase2 fallan, el tool no es conforme
        out["conforming"] = out["conforming"] and bf["conforming"]

    if args.human:
        sys.stdout.write(f"conforming: {out['conforming']}\n")
        sys.stdout.write(f"findings: {len(out['findings'])}\n")
        for f in out["findings"]:
            sys.stdout.write(f"  U+{f['codepoint']:04X} {f['name']}\n")
        if args.bytefiel:
            bf = out["byte_fiel"]
            sys.stdout.write(f"byte_fiel: conforming={bf['conforming']}")
            if bf["reason"]:
                sys.stdout.write(f" ({bf['reason']})")
            sys.stdout.write("\n")
        sys.stdout.write("clean: " + json.dumps(out["clean"], ensure_ascii=False) + "\n")
    else:
        sys.stdout.write(json.dumps(out, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
