from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from fixcenter.catalog import CONTROL_CATALOG
from fixcenter.collector import SafeCollector
from fixcenter.engine import DiagnosticEngine, write_report
from fixcenter.evaluation import run_evaluation
from fixcenter.models import Problem
from fixcenter.server import serve


def _json(data) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="fixcenter", description="WSAI FixCenter diagnostics"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve", help="Start the MCP JSON-RPC server on stdin/stdout")
    diagnose = sub.add_parser(
        "diagnose", help="Diagnose a JSON problem from a file or stdin"
    )
    diagnose.add_argument("source", nargs="?", help="JSON file; stdin when omitted")
    diagnose.add_argument("--out", help="Directory where the report JSON is written")
    coverage = sub.add_parser(
        "coverage", help="Show catalog design coverage without inspecting the PC"
    )
    coverage.add_argument("--platform", choices=("windows", "linux", "darwin"))
    collect = sub.add_parser(
        "collect", help="Plan safe probes; add --execute and --consent to run"
    )
    collect.add_argument("control_ids", nargs="*")
    collect.add_argument("--platform", choices=("windows", "linux", "darwin"))
    collect.add_argument("--execute", action="store_true")
    collect.add_argument("--consent", action="store_true")
    collect.add_argument("--include-output", action="store_true")
    sub.add_parser("self-test", help="Run synthetic diagnostics without machine data")
    sub.add_parser("catalog", help="List catalogued controls without inspecting the PC")
    args = parser.parse_args()
    if args.command == "serve":
        serve()
    elif args.command == "diagnose":
        raw = (
            Path(args.source).read_text(encoding="utf-8")
            if args.source
            else sys.stdin.read()
        )
        report = DiagnosticEngine().diagnose(Problem(**json.loads(raw)))
        print(write_report(report, args.out)) if args.out else _json(report.to_dict())
    elif args.command == "coverage":
        _json(SafeCollector.design_coverage(args.platform))
    elif args.command == "collect":
        ids = args.control_ids or None
        _json(
            SafeCollector()
            .collect(
                ids,
                execute=args.execute,
                consent=args.consent,
                include_output=args.include_output,
                platform_name=args.platform,
            )
            .to_dict()
        )
    elif args.command == "self-test":
        _json(run_evaluation())
    else:
        _json(
            {
                "total": len(CONTROL_CATALOG),
                "controls": [item.to_dict() for item in CONTROL_CATALOG],
            }
        )
