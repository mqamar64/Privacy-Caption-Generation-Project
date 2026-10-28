"""Build the Privacy Property Graphs for one app by running cypher/ppg_build.cypher.

    python scripts/build_ppg.py <app_id> [--export output/ppg]

Prints what each query did, runs the validation checks, and with --export writes one
JSON file per PPG (for classification, captions and annotation).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
QUERIES = HERE.parent / "cypher" / "ppg_build.cypher"


def split_queries(text: str) -> list[tuple[str, str]]:
    """Queries end with a line ending in ';'. A query's title is the nearest 'Xn. ...' comment."""
    out, body, title = [], [], None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("//"):
            m = re.match(r"//\s*([A-Z]\d*[a-z]?\.\s.*)", stripped)
            if m:
                title = m.group(1)
            continue
        body.append(line)
        if stripped.endswith(";"):
            q = "\n".join(body).strip().rstrip(";")
            if q:
                out.append((title or "schema", q))
            body = []
    return out


def load_doc_sources() -> list[dict]:
    """Categorised sources from the Document Analysis Module (NO_CATEGORY rows are skipped)."""
    import csv
    path = HERE.parent.parent / "Document Analysis Module" / "output" / "formatted_sources.csv"
    with open(path, encoding="utf-8") as f:
        return [{"class_name": r["Class Name"], "method_name": r["Method Name"],
                 "param_types": r["Parameter Types"], "category": r["Category"]}
                for r in csv.DictReader(f) if r["Category"] != "NO_CATEGORY"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("app_id")
    ap.add_argument("--export", help="folder for one JSON file per PPG")
    ap.add_argument("--wide", action="store_true",
                    help="also use the Document Analysis Module's source list (more PPGs, needs review)")
    ap.add_argument("--rows", type=int, default=15, help="result rows to print per query")
    ap.add_argument("--neo4j-uri", default=os.environ.get("NEO4J_URI", "bolt://localhost:7687"))
    ap.add_argument("--neo4j-user", default=os.environ.get("NEO4J_USER", "neo4j"))
    ap.add_argument("--neo4j-password", default=os.environ.get("NEO4J_PASSWORD"))
    args = ap.parse_args()
    if not args.neo4j_password:
        sys.exit("Neo4j password missing: pass --neo4j-password or set NEO4J_PASSWORD")

    from neo4j import GraphDatabase

    queries = split_queries(QUERIES.read_text())
    doc_sources = load_doc_sources() if args.wide else []
    if not args.wide:
        queries = [(t, q) for t, q in queries if not t.startswith("P2b.")]
    else:
        print(f"Wide mode: {len(doc_sources)} categorised sources from the Document Analysis Module")
    driver = GraphDatabase.driver(args.neo4j_uri, auth=(args.neo4j_user, args.neo4j_password))
    problems = 0
    export_rows = []
    with driver.session() as s:
        if not s.run("MATCH (a:App {app_id: $app}) RETURN a", app=args.app_id).single():
            sys.exit(f"No App with app_id {args.app_id!r} in Neo4j. Build and load the APG first.")
        for title, q in queries:
            rows = [dict(r) for r in s.run(q, app=args.app_id, doc_sources=doc_sources)]
            if title.startswith("E."):
                export_rows = rows
                print(f"\n=== {title}\n({len(rows)} PPGs)")
                continue
            print(f"\n=== {title}")
            for r in rows[:args.rows]:
                print("  " + json.dumps(r, default=str)[:300])
            if len(rows) > args.rows:
                print(f"  ... {len(rows) - args.rows} more rows")
            if title.startswith(("V1.", "V3.", "V4.")):
                n = next(iter(rows[0].values())) if rows else 0
                problems += n
    driver.close()

    print(f"\nValidation problems: {problems}" + ("" if problems == 0 else "  <-- investigate before using the PPGs"))
    if args.export:
        out = Path(args.export) / args.app_id.replace("/", "_")
        out.mkdir(parents=True, exist_ok=True)
        for i, row in enumerate(export_rows, 1):
            for k in ("ast_table", "cfg_table", "data_flow_table", "method_call_table"):
                if isinstance(row.get(k), str):
                    row[k] = json.loads(row[k])      # stored as JSON text on the Method node
            row["flows"] = [f for f in row.get("flows") or [] if f]
            row["conditions"] = [c for c in row.get("conditions") or [] if c]
            (out / f"ppg_{i:04d}.json").write_text(json.dumps(row, indent=2, default=str))
        print(f"Wrote {len(export_rows)} PPG files to {out}")


if __name__ == "__main__":
    main()
