"""In-memory App Property Graph container.

Every node carries ``uid`` (globally unique, prefixed with the app_id so several
APKs can share one Neo4j database) and ``app_id``. In Neo4j every node also gets
the shared label ``:APG`` so edges can be matched through one uniqueness index.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

# --- Node labels -------------------------------------------------------------
APP = "App"
PERMISSION = "Permission"
COMPONENT = "Component"
LIBRARY = "Library"
CLASS = "Class"
METHOD = "Method"
FIELD = "Field"
PARAMETER = "Parameter"
STATEMENT = "Statement"

NODE_LABELS = (APP, PERMISSION, COMPONENT, LIBRARY, CLASS, METHOD, FIELD, PARAMETER, STATEMENT)

# --- Relationship types: type -> (from label(s), to label(s), layer, meaning) ---------
# Layers follow VulHunter's APG (AST, MCG, ICFG, SDG), plus the manifest.
EDGE_TYPES: dict[str, tuple[str, str, str, str]] = {
    # Manifest
    "USES_PERMISSION":         (APP, PERMISSION, "Manifest", "App requests the permission (<uses-permission>)"),
    "DECLARES_PERMISSION":     (APP, PERMISSION, "Manifest", "App defines a custom permission (<permission>)"),
    "HAS_COMPONENT":           (APP, COMPONENT, "Manifest", "Activity / service / receiver / provider in the manifest"),
    "IMPLEMENTED_BY":          (COMPONENT, CLASS, "Manifest", "Class implementing the component"),
    "GUARDED_BY":              (COMPONENT, PERMISSION, "Manifest", "Permission required to access the component"),
    # AST: program structure, the symbol table and its containment tree
    "HAS_CLASS":               (APP, CLASS, "AST", "Class defined in or referenced by the APK"),
    "USES_LIBRARY":            (APP, LIBRARY, "AST", "Third-party SDK detected in the APK"),
    "BELONGS_TO":              (CLASS, LIBRARY, "AST", "Class is part of a detected SDK"),
    "EXTENDS":                 (CLASS, CLASS, "AST", "Superclass"),
    "IMPLEMENTS":              (CLASS, CLASS, "AST", "Implemented interface"),
    "HAS_METHOD":              (CLASS, METHOD, "AST", "Declared method"),
    "HAS_FIELD":               (CLASS, FIELD, "AST", "Declared field"),
    "HAS_PARAM":               (METHOD, PARAMETER, "AST", "Formal parameter (index 0 = this for instance methods)"),
    "HAS_STATEMENT":           (METHOD, STATEMENT, "AST", "Bytecode statement (operands in its defs/uses)"),
    # MCG: method call graph
    "CALLS":                   (METHOD, METHOD, "MCG", "Caller -> callee; count = call sites; via = callback|icc for implicit calls"),
    "INVOKES":                 (STATEMENT, METHOD, "MCG", "Call site -> resolved callee (via = callback|icc for implicit calls)"),
    "OVERRIDES":               (METHOD, METHOD, "MCG", "Method overrides / implements an ancestor method"),
    "SENDS_INTENT":            (STATEMENT, COMPONENT, "MCG", "startActivity / startService / sendBroadcast target"),
    "API_REQUIRES_PERMISSION": (METHOD, PERMISSION, "MCG", "Framework API guarded by a permission (androguard mapping)"),
    # ICFG: interprocedural control flow
    "ENTRY":                   (METHOD, STATEMENT, "ICFG", "First statement of the method body"),
    "FLOWS_TO":                (STATEMENT, STATEMENT, "ICFG", "Next statement; branch = true|false|case:N|default|goto; exception=true into a handler"),
    "CALL_FLOW":               (STATEMENT, STATEMENT, "ICFG", "Call site -> first statement of the callee"),
    "RETURN_FLOW":             (STATEMENT, STATEMENT, "ICFG", "Callee return/throw -> call site"),
    # SDG: system dependence graph (def -> use direction, so taint paths follow edges)
    "DATA_DEP":                ("Statement|Parameter", STATEMENT, "SDG", "Reaching definition of register `reg` used here"),
    "CONTROL_DEP":             (STATEMENT, STATEMENT, "SDG", "Branch statement decides whether this runs (branch = outcome)"),
    "ARG":                     ("Statement|Parameter", PARAMETER, "SDG", "Value passed as argument `index` at call site `call_site`"),
    "RETURN":                  (STATEMENT, STATEMENT, "SDG", "Callee return statement -> caller invoke (result consumed by move-result)"),
    "WRITES_FIELD":            (STATEMENT, FIELD, "SDG", "iput / sput"),
    "READ_BY":                 (FIELD, STATEMENT, "SDG", "iget / sget"),
}


@dataclass
class APG:
    app_id: str
    nodes: dict[str, dict[str, dict[str, Any]]] = field(default_factory=lambda: defaultdict(dict))
    edges: dict[str, list[tuple[str, str, dict[str, Any]]]] = field(default_factory=lambda: defaultdict(list))

    def add_node(self, label: str, uid: str, /, **props: Any) -> str:
        bucket = self.nodes[label]
        if uid in bucket:
            bucket[uid].update({k: v for k, v in props.items() if v is not None})
        else:
            bucket[uid] = {"uid": uid, "app_id": self.app_id, **props}
        return uid

    def has_node(self, label: str, uid: str) -> bool:
        return uid in self.nodes.get(label, {})

    def add_edge(self, rel: str, src: str, dst: str, /, **props: Any) -> None:
        self.edges[rel].append((src, dst, props))

    def counts(self) -> dict[str, dict[str, int]]:
        return {
            "nodes": {k: len(v) for k, v in self.nodes.items()},
            "edges": {k: len(v) for k, v in self.edges.items()},
        }
