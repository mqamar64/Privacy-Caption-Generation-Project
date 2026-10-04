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

# --- Relationship types: (type, from label(s), to label(s), meaning) --------------
EDGE_TYPES: dict[str, tuple[str, str, str]] = {
    # Manifest
    "USES_PERMISSION":         (APP, PERMISSION, "App requests the permission (<uses-permission>)"),
    "DECLARES_PERMISSION":     (APP, PERMISSION, "App defines a custom permission (<permission>)"),
    "HAS_COMPONENT":           (APP, COMPONENT, "Activity / service / receiver / provider in the manifest"),
    "IMPLEMENTED_BY":          (COMPONENT, CLASS, "Class implementing the component"),
    "GUARDED_BY":              (COMPONENT, PERMISSION, "Permission required to access the component"),
    # Symbol table / structure (the APG's AST layer)
    "HAS_CLASS":               (APP, CLASS, "Class defined in or referenced by the APK"),
    "USES_LIBRARY":            (APP, LIBRARY, "Third-party SDK detected in the APK"),
    "BELONGS_TO":              (CLASS, LIBRARY, "Class is part of a detected SDK"),
    "EXTENDS":                 (CLASS, CLASS, "Superclass"),
    "IMPLEMENTS":              (CLASS, CLASS, "Implemented interface"),
    "HAS_METHOD":              (CLASS, METHOD, "Declared method"),
    "HAS_FIELD":               (CLASS, FIELD, "Declared field"),
    "HAS_PARAM":               (METHOD, PARAMETER, "Formal parameter (index 0 = this for instance methods)"),
    "HAS_STATEMENT":           (METHOD, STATEMENT, "Bytecode statement inside the method"),
    # Call graph
    "CALLS":                   (METHOD, METHOD, "Method-level call graph edge (count = #call sites)"),
    "OVERRIDES":               (METHOD, METHOD, "Method overrides / implements an ancestor method"),
    "API_REQUIRES_PERMISSION": (METHOD, PERMISSION, "Framework API guarded by a permission (androguard mapping)"),
    # Control flow
    "ENTRY":                   (METHOD, STATEMENT, "First statement of the method body"),
    "FLOWS_TO":                (STATEMENT, STATEMENT, "Intra-procedural control flow (exception=true for handlers)"),
    "INVOKES":                 (STATEMENT, METHOD, "Call site -> resolved callee"),
    # Data flow (def -> use direction, so taint paths follow edge direction)
    "DATA_DEP":                ("Statement|Parameter", STATEMENT, "Reaching definition of register `reg` used here"),
    "ARG":                     ("Statement|Parameter", PARAMETER, "Value passed as argument `index` at call site `call_site`"),
    "RETURN":                  (STATEMENT, STATEMENT, "Callee return statement -> caller invoke (result consumed by move-result)"),
    "WRITES_FIELD":            (STATEMENT, FIELD, "iput / sput"),
    "READ_BY":                 (FIELD, STATEMENT, "iget / sget"),
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
