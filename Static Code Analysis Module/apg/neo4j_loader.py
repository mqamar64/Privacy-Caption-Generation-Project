"""Load an APG into Neo4j (5.x) over Bolt.

All nodes share the label ``:APG`` with a uniqueness constraint on ``uid``; the
specific label (``:Method``, ``:Statement`` ...) is added alongside. Loading an
app first deletes any previous graph with the same ``app_id`` so reruns are clean,
while other apps in the database are left untouched.
"""

from __future__ import annotations

from typing import Any, Iterable

from .graph import APG, NODE_LABELS

SCHEMA = [
    "CREATE CONSTRAINT apg_uid IF NOT EXISTS FOR (n:APG) REQUIRE n.uid IS UNIQUE",
    "CREATE INDEX apg_app IF NOT EXISTS FOR (n:APG) ON (n.app_id)",
    "CREATE INDEX method_sig IF NOT EXISTS FOR (n:Method) ON (n.signature)",
    "CREATE INDEX method_cls_name IF NOT EXISTS FOR (n:Method) ON (n.class_name, n.name)",
    "CREATE INDEX method_java_sig IF NOT EXISTS FOR (n:Method) ON (n.java_signature)",
    "CREATE INDEX stmt_target IF NOT EXISTS FOR (n:Statement) ON (n.target)",
    "CREATE INDEX stmt_kind IF NOT EXISTS FOR (n:Statement) ON (n.kind)",
    "CREATE INDEX field_cls_name IF NOT EXISTS FOR (n:Field) ON (n.class_name, n.name)",
    "CREATE INDEX class_name IF NOT EXISTS FOR (n:Class) ON (n.name)",
    "CREATE INDEX perm_name IF NOT EXISTS FOR (n:Permission) ON (n.name)",
]


def _chunks(rows: list, size: int) -> Iterable[list]:
    for i in range(0, len(rows), size):
        yield rows[i:i + size]


def _clean(props: dict[str, Any]) -> dict[str, Any]:
    # Neo4j rejects empty lists of unknown type and null map values are pointless.
    return {k: v for k, v in props.items() if v is not None and v != []}


def load(g: APG, uri: str, user: str, password: str, database: str | None = None,
         batch_size: int = 5000, replace: bool = True, log=print) -> None:
    from neo4j import GraphDatabase

    driver = GraphDatabase.driver(uri, auth=(user, password))
    try:
        with driver.session(database=database) as s:
            for q in SCHEMA:
                s.run(q).consume()
            if replace:
                log(f"[neo4j] removing previous graph for {g.app_id}")
                s.run(
                    "MATCH (n:APG {app_id: $app}) "
                    "CALL { WITH n DETACH DELETE n } IN TRANSACTIONS OF 10000 ROWS",
                    app=g.app_id,
                ).consume()

            for label in NODE_LABELS:
                rows = [_clean(p) for p in g.nodes.get(label, {}).values()]
                if not rows:
                    continue
                q = f"UNWIND $rows AS row MERGE (n:APG {{uid: row.uid}}) SET n:{label}, n += row"
                for batch in _chunks(rows, batch_size):
                    s.execute_write(lambda tx, b=batch: tx.run(q, rows=b).consume())
                log(f"[neo4j] {label}: {len(rows)} nodes")

            for rel, edges in g.edges.items():
                rows = [{"s": a, "e": b, "p": _clean(p)} for a, b, p in edges]
                q = (f"UNWIND $rows AS row MATCH (a:APG {{uid: row.s}}) MATCH (b:APG {{uid: row.e}}) "
                     f"CREATE (a)-[r:{rel}]->(b) SET r = row.p, r.app_id = a.app_id")
                for batch in _chunks(rows, batch_size):
                    s.execute_write(lambda tx, b=batch: tx.run(q, rows=b).consume())
                log(f"[neo4j] {rel}: {len(rows)} edges")
    finally:
        driver.close()
