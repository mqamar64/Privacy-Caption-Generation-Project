"""Run cypher/apg_example_queries.cypher against a loaded APG.

    python scripts/run_example_queries.py <app_id> [--limit 10]

The Document Analysis Module's categorised sources/sinks are passed as $apis so
APG API nodes are matched on the same (class, method, parameter types) key.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODULE = HERE.parent
DOC_OUT = MODULE.parent / "Document Analysis Module" / "output"


def load_doc_analysis_apis() -> list[dict]:
    rows = []
    for name, kind in (("formatted_sources.csv", "source"), ("formatted_sinks.csv", "sink")):
        path = DOC_OUT / name
        if not path.exists():
            continue
        with open(path, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                if r["Category"] == "NO_CATEGORY":
                    continue
                rows.append({"class_name": r["Class Name"], "method_name": r["Method Name"],
                             "param_types": r["Parameter Types"], "return_type": r["Return Type"],
                             "category": r["Category"], "kind": kind})
    return rows


def split_queries(text: str) -> list[tuple[str, str]]:
    out = []
    for block in text.split(";"):
        title = next((m.group(1) for m in re.finditer(r"//\s*(Q\d+\..*)", block)), None)
        body = "\n".join(l for l in block.splitlines() if not l.strip().startswith("//")).strip()
        if body:
            out.append((title or "query", body))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("app_id")
    ap.add_argument("--limit", type=int, default=10)
    ap.add_argument("--neo4j-uri", default=os.environ.get("NEO4J_URI", "bolt://localhost:7687"))
    ap.add_argument("--neo4j-user", default=os.environ.get("NEO4J_USER", "neo4j"))
    ap.add_argument("--neo4j-password", default=os.environ.get("NEO4J_PASSWORD"))
    args = ap.parse_args()

    from neo4j import GraphDatabase

    apis = load_doc_analysis_apis()
    queries = split_queries((MODULE / "cypher" / "apg_example_queries.cypher").read_text())
    driver = GraphDatabase.driver(args.neo4j_uri, auth=(args.neo4j_user, args.neo4j_password))
    with driver.session() as s:
        for title, q in queries:
            print(f"\n=== {title}")
            rows = list(s.run(q, app=args.app_id, apis=apis))
            for r in rows[:args.limit]:
                print(dict(r))
            print(f"({len(rows)} rows)")
    driver.close()


if __name__ == "__main__":
    main()
