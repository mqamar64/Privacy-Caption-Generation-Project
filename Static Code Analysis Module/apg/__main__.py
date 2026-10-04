"""Command line entry point.

    python -m apg build input/APK/sample.apk -o output/apg
    python -m apg build input/APK/ -o output/apg --neo4j          # every APK in a folder
    python -m apg load output/apg/<app_id> --neo4j-uri bolt://localhost:7687

Neo4j credentials default to the NEO4J_URI / NEO4J_USER / NEO4J_PASSWORD env vars.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def _quiet_androguard(verbose: bool) -> None:
    try:
        from loguru import logger
        logger.remove()
        logger.add(sys.stderr, level="INFO" if verbose else "WARNING")
    except ImportError:
        pass


def _neo4j_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--neo4j-uri", default=os.environ.get("NEO4J_URI", "bolt://localhost:7687"))
    p.add_argument("--neo4j-user", default=os.environ.get("NEO4J_USER", "neo4j"))
    p.add_argument("--neo4j-password", default=os.environ.get("NEO4J_PASSWORD"))
    p.add_argument("--neo4j-database", default=os.environ.get("NEO4J_DATABASE"))


def _load(g, args) -> None:
    from .neo4j_loader import load
    if not args.neo4j_password:
        sys.exit("Neo4j password missing: pass --neo4j-password or set NEO4J_PASSWORD")
    load(g, args.neo4j_uri, args.neo4j_user, args.neo4j_password, args.neo4j_database)


def cmd_build(args) -> None:
    from .builder import APGBuilder, BuildOptions
    from .export import write_csv

    src = Path(args.apk)
    apks = sorted(src.glob("*.apk")) if src.is_dir() else [src]
    if not apks:
        sys.exit(f"no .apk files found at {src}")
    opts = BuildOptions(stmt_scope=args.stmt_scope,
                        include_exception_edges=not args.no_exception_edges,
                        include_api_permission_mapping=not args.no_api_permissions)
    for apk in apks:
        print(f"[apg] analysing {apk}")
        b = APGBuilder(apk, opts)
        g = b.build()
        summary = {"app_id": g.app_id, "apk": str(apk), "options": vars(opts), **b.stats}
        out = Path(args.out) / g.app_id.replace("/", "_")
        if not args.no_csv:
            write_csv(g, out, summary)
            print(f"[apg] wrote CSVs to {out}")
        print(json.dumps({k: summary[k] for k in ("app_id", "nodes", "edges")}, indent=1))
        if args.neo4j:
            _load(g, args)


def cmd_load(args) -> None:
    from .export import read_csv
    g = read_csv(args.csv_dir)
    print(f"[apg] loaded {g.app_id} from {args.csv_dir}")
    _load(g, args)


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="apg", description="Build App Property Graphs from APKs")
    ap.add_argument("-v", "--verbose", action="store_true", help="show androguard logs")
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="analyse APK(s) and export the APG")
    b.add_argument("apk", help="APK file or folder of APKs")
    b.add_argument("-o", "--out", default="output/apg", help="output folder (one sub-folder per app)")
    b.add_argument("--stmt-scope", default="nonlib", choices=["app", "nonlib", "all", "none"],
                   help="which classes get statement-level CFG/data-flow "
                        "(nonlib = app + unrecognised code; default)")
    b.add_argument("--no-exception-edges", action="store_true")
    b.add_argument("--no-api-permissions", action="store_true",
                   help="skip androguard's API->permission mapping")
    b.add_argument("--no-csv", action="store_true")
    b.add_argument("--neo4j", action="store_true", help="also load into Neo4j")
    _neo4j_args(b)
    b.set_defaults(func=cmd_build)

    ld = sub.add_parser("load", help="load an exported CSV folder into Neo4j")
    ld.add_argument("csv_dir")
    _neo4j_args(ld)
    ld.set_defaults(func=cmd_load)

    args = ap.parse_args(argv)
    _quiet_androguard(args.verbose)
    args.func(args)


if __name__ == "__main__":
    main()
