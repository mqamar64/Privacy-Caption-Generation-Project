"""CSV export / import of an APG.

Files use neo4j-admin import headers so they can be bulk-imported directly, while
staying readable with pandas:

  nodes_<Label>.csv   uid:ID, app_id, prop[:type]..., :LABEL
  edges_<TYPE>.csv    :START_ID, :END_ID, :TYPE, prop[:type]...

List properties are ``;``-joined (header ``prop:string[]``). Missing values are
written as unquoted empty fields and real empty strings as ``""`` (csv.QUOTE_NOTNULL),
which neo4j-admin also reads as null vs "". This matters for ``Method.param_types``,
which is "" for no-argument methods exactly like the Document Analysis CSVs.
Requires Python 3.12+.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from .graph import APG

ARRAY_DELIM = ";"
csv.field_size_limit(1 << 30)


def _infer_type(values) -> str:
    for v in values:
        if v is None:
            continue
        if isinstance(v, bool):
            return "boolean"
        if isinstance(v, int):
            return "long"
        if isinstance(v, float):
            return "double"
        if isinstance(v, (list, tuple)):
            return "string[]"
        return "string"
    return "string"


def _fmt(v: Any, t: str) -> str | None:
    if v is None:
        return None
    if t == "string[]":
        return ARRAY_DELIM.join(str(x) for x in v)
    if t == "boolean":
        return "true" if v else "false"
    return str(v)


def _header(name: str, t: str) -> str:
    return name if t == "string" else f"{name}:{t}"


def write_csv(g: APG, out_dir: str | Path, summary: dict[str, Any] | None = None) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for label, nodes in g.nodes.items():
        rows = list(nodes.values())
        keys = [k for k in dict.fromkeys(k for r in rows for k in r) if k != "uid"]
        types = {k: _infer_type(r.get(k) for r in rows) for k in keys}
        with open(out / f"nodes_{label}.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f, quoting=csv.QUOTE_NOTNULL)
            w.writerow(["uid:ID"] + [_header(k, types[k]) for k in keys] + [":LABEL"])
            for r in rows:
                w.writerow([r["uid"]] + [_fmt(r.get(k), types[k]) for k in keys] + [f"APG;{label}"])
    for rel, edges in g.edges.items():
        keys = list(dict.fromkeys(k for _, _, p in edges for k in p))
        types = {k: _infer_type(p.get(k) for _, _, p in edges) for k in keys}
        with open(out / f"edges_{rel}.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f, quoting=csv.QUOTE_NOTNULL)
            w.writerow([":START_ID", ":END_ID", ":TYPE"] + [_header(k, types[k]) for k in keys])
            for s, d, p in edges:
                w.writerow([s, d, rel] + [_fmt(p.get(k), types[k]) for k in keys])
    if summary is not None:
        (out / "apg_summary.json").write_text(json.dumps(summary, indent=2, default=str))
    return out


def _parse(v: str | None, t: str) -> Any:
    if v is None:
        return None
    if t == "string":
        return v
    if v == "":
        return None
    if t == "string[]":
        return v.split(ARRAY_DELIM)
    if t == "boolean":
        return v == "true"
    if t in ("long", "int"):
        return int(v)
    if t in ("double", "float"):
        return float(v)
    return v


def _split_header(h: str) -> tuple[str, str]:
    name, _, t = h.partition(":")
    return name, t or "string"


def read_csv(in_dir: str | Path) -> APG:
    """Rebuild an APG from a directory written by :func:`write_csv`."""
    d = Path(in_dir)
    g: APG | None = None
    for path in sorted(d.glob("nodes_*.csv")):
        label = path.stem[len("nodes_"):]
        with open(path, newline="", encoding="utf-8") as f:
            r = csv.reader(f, quoting=csv.QUOTE_NOTNULL)
            header = next(r)
            cols = [_split_header(h) for h in header]
            for row in r:
                props = {}
                for (name, t), v in zip(cols, row):
                    if name in ("uid", "") or t in ("ID", "LABEL"):
                        continue
                    props[name] = _parse(v, t)
                if g is None:
                    g = APG(props["app_id"])
                props.pop("app_id", None)
                g.add_node(label, row[0], **props)
    if g is None:
        raise FileNotFoundError(f"no nodes_*.csv in {d}")
    for path in sorted(d.glob("edges_*.csv")):
        with open(path, newline="", encoding="utf-8") as f:
            r = csv.reader(f, quoting=csv.QUOTE_NOTNULL)
            cols = [_split_header(h) for h in next(r)]
            for row in r:
                props = {name: _parse(v, t) for (name, t), v in zip(cols[3:], row[3:])}
                g.add_edge(row[2], row[0], row[1], **{k: v for k, v in props.items() if v is not None})
    return g
