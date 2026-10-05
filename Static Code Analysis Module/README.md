# Static Code Analysis Module: APK → App Property Graph (APG)

This module turns an Android APK into an **App Property Graph** stored as CSV and/or in Neo4j.
The Privacy Property Graph (PPG) is then carved out of the APG with Cypher queries built from
the Document Analysis Module's sensitive-API mapping (and later LINDDUN).

```
APK ──androguard──▶ APG (this module) ──Cypher + Document Analysis map──▶ PPG ──▶ classification / captions / labels
```

## Quick start

```bash
# from the repo root
python3 -m venv .venv --system-site-packages
.venv/bin/pip install -r "Static Code Analysis Module/requirements.txt"
cd "Static Code Analysis Module"

# Build the APG and write CSVs to output/apg/<app_id>/
../.venv/bin/python -m apg build input/APK/sample.apk -o output/apg

# Build and load straight into Neo4j 5.x
NEO4J_PASSWORD=... ../.venv/bin/python -m apg build input/APK/sample.apk --neo4j

# Load CSVs someone else exported (no re-analysis needed)
NEO4J_PASSWORD=... ../.venv/bin/python -m apg load output/apg/<app_id>

# Run the example PPG-building queries (joins the Document Analysis CSVs)
NEO4J_PASSWORD=... ../.venv/bin/python scripts/run_example_queries.py <app_id>
```

You can pass a folder instead of a single `.apk`; each app gets its own `app_id` and output folder.
Several apps can live in one Neo4j database. Reloading an app replaces only that app's subgraph.

Tests: `../.venv/bin/python -m pytest` (the sample-APK integration tests take about 1 minute).
You need Python 3.12 or newer.

## What is in the graph

Every node has `uid` (unique, prefixed with `app_id`) and `app_id`. In Neo4j every node also
carries the shared label `:APG`.

The layers follow the APG defined in VulHunter (Qian et al., IEEE Micro 2015, in
`project info/.../Task I Privacy Property Graph Extraction/`): an AST, a method call graph (MCG),
an interprocedural control-flow graph (ICFG) and a system dependence graph (SDG), plus the manifest.

| Layer | Nodes | Relationships |
|---|---|---|
| Manifest | `App`, `Permission`, `Component` | `USES_PERMISSION`, `DECLARES_PERMISSION`, `HAS_COMPONENT`, `IMPLEMENTED_BY`, `GUARDED_BY` |
| AST (symbol table + containment) | `Class`, `Method`, `Field`, `Parameter`, `Statement`, `Library` | `HAS_CLASS`, `EXTENDS`, `IMPLEMENTS`, `HAS_METHOD`, `HAS_FIELD`, `HAS_PARAM`, `HAS_STATEMENT`, `BELONGS_TO`, `USES_LIBRARY` |
| MCG | `Method`, `Statement`, `Component` | `CALLS` (`count`; `via` = `callback`/`icc` for implicit calls), `INVOKES` (call site → callee), `OVERRIDES`, `SENDS_INTENT`, `API_REQUIRES_PERMISSION` |
| ICFG | `Statement` | `ENTRY`, `FLOWS_TO` (`branch` = `true`/`false`/`case:N`/`default`/`goto`; `exception: true` into handlers), `CALL_FLOW` (call → callee's first statement), `RETURN_FLOW` (callee's return/throw → call) |
| SDG | `Statement`, `Parameter`, `Field` | `DATA_DEP` (def → use, `reg`), `CONTROL_DEP` (branch → statements it decides, `branch`), `ARG`, `RETURN`, `WRITES_FIELD`, `READ_BY` |

Each relationship type, its layer and its meaning are listed in [`apg/graph.py`](apg/graph.py) (`EDGE_TYPES`).

How it lines up with VulHunter, and where it differs:
- VulHunter reads Soot's Shimple IR; we read Dalvik bytecode through Androguard, as the project notes specify.
  Statement operands are kept as `defs`/`uses` properties rather than separate operand nodes.
- VulHunter resolves virtual calls with points-to analysis (Spark). We resolve through the class
  hierarchy (`OVERRIDES`) and, for callbacks, through the object's `new-instance` in the same method.
- VulHunter uses Epicc for Intents. We resolve explicit Intents (`X.class`, class-name strings) and
  implicit ones whose action matches one of the app's own intent filters, within the calling method.

### Properties you will query most

- **Method**: `class_name`, `name`, `param_types`, `return_type`, `java_signature`.
  These use the **same format as the Document Analysis Module** (`formatted_sources.csv`):
  dotted names, comma-joined parameters, `""` for no parameters, `[]` for arrays. So the join is:
  ```cypher
  MATCH (m:Method {class_name: api.class_name, name: api.method_name}) WHERE m.param_types = api.param_types
  ```
  Other method properties: `signature` (smali), `is_external` (true = framework/SDK API not in the APK),
  `origin`, `is_entrypoint` + `entrypoint_kind` (`component_lifecycle`, `callback`, `component_init`),
  `permissions` (for framework APIs that need one), and `source`: the decompiled Java of every method
  that has statements. That is the code-segment format PriGen/PDroid captions (compare
  `PriGenLocal/test_apk/*/PRCS_*.java`); query Q10 pulls these segments up to 3 calls above a
  permission-guarded API. Turn it off with `--no-source`.
- **Statement**: `code` (the bytecode instruction), `opcode`, `kind` (`invoke`, `field_read`,
  `const_string`, `return`, ...), `offset`, `method_signature`. Invoke statements also have
  `target_class`, `target_name`, `target_java_signature`. `const-string` statements have `literal`,
  which is where URLs and hostnames show up. `new-instance`/`const-class`/`check-cast` have `type_ref`.
  Every statement lists the registers it writes (`defs`) and reads (`uses`).
- **Class / Method / Field** `origin`: `app` (the developer's code), `library` (a recognised SDK, see
  [`apg/libraries.py`](apg/libraries.py)), `unknown` (bundled code that matches no known SDK, often
  obfuscated), or `framework` (Android/Java platform).

### Data-flow semantics (what a taint path means)

Edges point in the direction data moves, so a taint path is any directed path over
`DATA_DEP|ARG|RETURN|WRITES_FIELD|READ_BY`. An invoke `Statement` stands for the call **and its
result**: arguments flow in, and the following `move-result` reads it. Example from the sample APK
(query Q5):

```
WifiInfo.getSSID() → move-result v2 → String.replaceAll → sput FDroidApp.ssid
  → [Field FDroidApp.ssid] → sget (another method) → Uri$Builder.appendQueryParameter → build()
```

Approximations (they are deliberate, so treat paths as evidence to check, not proof):
- Unknown calls pass taint through: if any argument is tainted, the result is tainted.
- Callbacks and Intents are resolved only when the object or Intent is created in the same
  method that registers or sends it. Data passed through Intent extras is not linked yet.
  Instance calls that take arguments also taint their receiver (`sb.append(x)` taints `sb`).
- `ARG`/`RETURN` link only to the statically resolved callee. Use `OVERRIDES` if you need
  virtual-dispatch targets.
- Field flow is not object-sensitive: a write to `C.f` reaches every read of `C.f`.
- Wide (long/double) register pairs are tracked by their low register.
- No reflection, dynamic loading, or native code. The notes already say these are out of scope.

### Conditions (control dependence)

`CONTROL_DEP` answers "which check decides whether this runs?". In F-Droid, `WifiInfo.getSSID()`
is control dependent on `if-eqz v2` (the BSSID null check) with `branch: "false"`, so the SSID is
read only when a BSSID exists. Query Q8 lists the conditions guarding sensitive calls, such as
permission checks. That feeds the "conditions" field of the privacy facts in Project I.

### Statement scope (size control)

The method-level call graph always covers every class, so you can still see SDK behaviour
(for example an analytics SDK calling a location API). Statement-level CFG and data flow are only
built for the classes selected with `--stmt-scope`:

| `--stmt-scope` | Statements for | sample.apk (F-Droid) |
|---|---|---|
| `app` | `origin = app` | ~62k statements |
| `nonlib` (default) | `app` + `unknown` | ~135k statements, ~45 s build, ~2 min to load into Neo4j |
| `all` | every class in the APK | ~1.6M statements, ~70 s build, ~5 GB RAM |
| `none` | nothing (call graph only) | |

## Output files

`output/apg/<app_id>/` contains `nodes_<Label>.csv`, `edges_<TYPE>.csv`, and `apg_summary.json`
(counts, timings, options). The headers follow the `neo4j-admin database import` format, so for a
fresh database you can also bulk-import:

```bash
neo4j-admin database import full --nodes=nodes_App.csv --nodes=nodes_Method.csv ... \
  --relationships=edges_CALLS.csv ... --array-delimiter=";" --multiline-fields=true
```

(`--multiline-fields` is needed because `Method.source` holds multi-line Java.)

## Layout

```
apg/
  builder.py       APK → APG (manifest, symbols, call graph, CFG, reaching-definitions data flow)
  controldep.py    post-dominators and control dependence (CONTROL_DEP)
  callbacks.py     callbacks (listeners, threads) and Intents (ICC) as implicit calls
  dalvik.py        type descriptors, parameter registers, per-opcode def/use rules
  libraries.py     SDK prefix list + app/library/framework/unknown classification
  graph.py         APG container, node labels and relationship catalogue
  export.py        CSV writer/reader
  neo4j_loader.py  batched Bolt loader (schema, per-app replace)
  __main__.py      CLI
cypher/apg_example_queries.cypher   Q1–Q10: building blocks for the PPG
scripts/run_example_queries.py      runs them with the Document Analysis CSVs as $apis
tests/                              unit tests + sample.apk integration tests
```

`Sourcecode/` holds the earlier single-file scripts. They are kept for reference. The new module
replaces `androguard_analysis_APG_*.py` and fixes these problems in them:
- Overloaded methods were merged, because the method id had no descriptor.
- "ICFG" edges were just instruction order. Branches and catch handlers were missing.
- The DDG parsed register text, so `iput`/`aput` sources were treated as definitions and
  `move-result` was not connected to its call.
- Node ids had no app scope, so loading two APKs mixed their graphs.
- Paths were hard-coded to Windows folders.

## Next steps toward the PPG

1. Turn the Document Analysis output (`personal_info_results.csv`, `formatted_sources/sinks.csv`)
   into `:SensitiveAPI` tags on `Method` nodes. Q2 already shows the join.
2. Turn the Q4/Q5 patterns into PPG extraction queries: entrypoint → source → sink, with the
   evidence path stored on the PPG edge so captions can cite it.
3. Add LINDDUN-driven sink categories (network, logging, storage, IPC, third-party SDK). The
   Privacy Property Graph paper (Kunz et al., PoPETs 2023) lists what to detect: identifiers,
   database operations, HTTP endpoints, logging libraries and third-party libraries.
