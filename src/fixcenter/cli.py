from __future__ import annotations

import argparse
import json
import sys

from fixcenter.engine import DiagnosticEngine, write_report
from fixcenter.models import Problem
from fixcenter.server import serve


def main() -> None:
    parser = argparse.ArgumentParser(prog="fixcenter", description="WSAI FixCenter diagnostics")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve", help="Start the MCP JSON-RPC server on stdin/stdout")
    diagnose = sub.add_parser("diagnose", help="Diagnose a JSON problem from a file or stdin")
    diagnose.add_argument("source", nargs="?", help="JSON file; stdin when omitted")
    diagnose.add_argument("--out", help="Directory where the report JSON is written")
    args = parser.parse_args()
    if args.command == "serve":
        serve()
        return
    raw = open(args.source, encoding="utf-8").read() if args.source else sys.stdin.read()
    report = DiagnosticEngine().diagnose(Problem(**json.loads(raw)))
    if args.out:
        print(write_report(report, args.out))
    else:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))

