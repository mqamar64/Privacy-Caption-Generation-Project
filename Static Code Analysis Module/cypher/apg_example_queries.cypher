// Example queries over the App Property Graph (APG).
// These are the building blocks for deriving the Privacy Property Graph (PPG).
// Parameters: $app = App.app_id (see output/apg/<app_id>/apg_summary.json)
//             $apis = rows from the Document Analysis Module, e.g.
//                     [{class_name, method_name, param_types, category, kind}]
//             (see scripts/run_example_queries.py for loading formatted_sources/sinks.csv)

// ---------------------------------------------------------------------------
// Q1. App overview: requested permissions and detected third-party SDKs
// ---------------------------------------------------------------------------
MATCH (a:App {app_id: $app})
OPTIONAL MATCH (a)-[:USES_PERMISSION]->(p:Permission)
WITH a, collect(p.name) AS permissions
OPTIONAL MATCH (a)-[:USES_LIBRARY]->(l:Library)
RETURN a.package AS package, a.version_name AS version, permissions,
       collect(l.name + ' (' + l.category + ')') AS sdks;

// ---------------------------------------------------------------------------
// Q2. Join Document Analysis sensitive APIs to APG API nodes, and count every
//     method that calls them (method-level, so library/SDK callers are included)
// ---------------------------------------------------------------------------
UNWIND $apis AS api
MATCH (m:Method {class_name: api.class_name, name: api.method_name})
WHERE m.app_id = $app AND m.param_types = api.param_types
MATCH (caller:Method)-[c:CALLS]->(m)
RETURN api.kind AS kind, api.category AS category, m.java_signature AS api_signature,
       caller.origin AS caller_origin, count(DISTINCT caller) AS callers, sum(c.count) AS call_sites
ORDER BY call_sites DESC;

// ---------------------------------------------------------------------------
// Q3. Which SDK calls which sensitive API (third-party sharing evidence)
// ---------------------------------------------------------------------------
UNWIND $apis AS api
MATCH (m:Method {class_name: api.class_name, name: api.method_name})
WHERE m.app_id = $app AND m.param_types = api.param_types
MATCH (lib:Library)<-[:BELONGS_TO]-(:Class)-[:HAS_METHOD]->(caller:Method)-[:CALLS]->(m)
RETURN lib.name AS sdk, lib.category AS sdk_category, api.category AS data_category,
       collect(DISTINCT m.name) AS apis, count(DISTINCT caller) AS calling_methods
ORDER BY sdk;

// ---------------------------------------------------------------------------
// Q4. Is a sensitive API reachable from an entrypoint? (call-graph path)
// ---------------------------------------------------------------------------
MATCH (api:Method {app_id: $app, class_name: 'android.net.wifi.WifiInfo', name: 'getSSID'})
MATCH (e:Method {app_id: $app, is_entrypoint: true})
MATCH p = shortestPath((e)-[:CALLS*1..8]->(api))
RETURN e.class_name + '.' + e.name AS entrypoint, e.entrypoint_kind AS kind,
       [n IN nodes(p) | n.class_name + '.' + n.name] AS call_chain
ORDER BY length(p) LIMIT 10;

// ---------------------------------------------------------------------------
// Q5. Taint path: data returned by a source API reaching a sink API call
//     (intra-procedural DATA_DEP + ARG/RETURN across calls + field writes/reads)
// ---------------------------------------------------------------------------
MATCH (src:Statement {app_id: $app, kind: 'invoke', target_name: 'getSSID'})
MATCH (sink:Statement {app_id: $app, kind: 'invoke'})
WHERE sink.target_class IN ['android.net.Uri$Builder', 'android.util.Log', 'java.net.URL']
MATCH p = shortestPath((src)-[:DATA_DEP|ARG|RETURN|WRITES_FIELD|READ_BY*1..15]->(sink))
RETURN src.method_signature AS source_method, sink.target_java_signature AS sink_api,
       [n IN nodes(p) | coalesce(n.code, n.signature, 'param ' + toString(n.index))] AS evidence
LIMIT 10;

// ---------------------------------------------------------------------------
// Q6. Permission check: requested permissions vs. permissions implied by used APIs
// ---------------------------------------------------------------------------
MATCH (a:App {app_id: $app})
MATCH (caller:Method {app_id: $app})-[:CALLS]->(api:Method)-[:API_REQUIRES_PERMISSION]->(p:Permission)
RETURN p.name AS permission, EXISTS((a)-[:USES_PERMISSION]->(p)) AS requested,
       collect(DISTINCT api.class_name + '.' + api.name)[..5] AS example_apis,
       count(DISTINCT caller) AS calling_methods
ORDER BY requested, permission;

// ---------------------------------------------------------------------------
// Q7. Exported components and the permission (if any) guarding them
// ---------------------------------------------------------------------------
MATCH (a:App {app_id: $app})-[:HAS_COMPONENT]->(c:Component {exported: true})
OPTIONAL MATCH (c)-[:GUARDED_BY]->(p:Permission)
RETURN c.type AS type, c.name AS component, c.intent_actions AS actions,
       collect(p.name) AS guarded_by
ORDER BY type, component;
