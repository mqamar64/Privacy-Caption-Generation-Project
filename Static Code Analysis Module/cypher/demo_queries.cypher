// =============================================================================
// Demo: from one APK to its App Property Graph and Privacy Property Graphs
//
// Run in Neo4j Browser (http://localhost:7474) after building the APG and the PPGs.
// Paste one query at a time. Queries marked [graph] are best viewed as a picture;
// [table] ones in Table view.
// Tip: click a label at the top of a picture (e.g. "Statement") and set its caption
// to `code`, "Method" to `name`, "PPG" to `data_type` so the dots are readable.
// =============================================================================


// -----------------------------------------------------------------------------
// Part 1. The App Property Graph (APG): everything in the app's code
// -----------------------------------------------------------------------------

// D1. [graph] The APG's blueprint: every kind of node and every kind of relationship
CALL db.schema.visualization();

// D2. [table] How big it is: nodes of each kind for this one app
MATCH (n:APG)
RETURN [l IN labels(n) WHERE l <> 'APG' AND NOT l IN ['SourcePoint', 'SinkPoint', 'SourceAPI', 'SinkAPI']][0] AS kind,
       count(*) AS nodes
ORDER BY nodes DESC;

// D3. [table] The app, what it asks for, and who else's code it ships with
MATCH (a:App)
OPTIONAL MATCH (a)-[:USES_PERMISSION]->(p:Permission)
WITH a, collect(p.name) AS permissions
OPTIONAL MATCH (a)-[:USES_LIBRARY]->(l:Library)
RETURN a.package AS app, a.version_name AS version, size(permissions) AS permission_count,
       permissions, collect(l.name + ' (' + l.category + ')') AS third_party_sdks;

// D4. [table] Who wrote the code: the developer, known SDKs, or unrecognised code
MATCH (c:Class {is_external: false})
RETURN c.origin AS written_by, count(*) AS classes ORDER BY classes DESC;

// D5. [graph] One method, instruction by instruction, with its control flow
//     (setSsid reads the Wi-Fi name; true/false labels show the branches)
MATCH (m:Method {name: 'setSsid'})-[:HAS_STATEMENT]->(s:Statement)
WHERE s.offset <= 140
OPTIONAL MATCH (s)-[f:FLOWS_TO]->(t:Statement)<-[:HAS_STATEMENT]-(m)
WHERE t.offset <= 140
RETURN m, s, f, t;

// D6. [graph] How the app reaches the Wi-Fi API: entry point -> calls -> Android API
MATCH (api:Method {class_name: 'android.net.wifi.WifiInfo', name: 'getSSID'})
MATCH (e:Method {is_entrypoint: true})
MATCH p = SHORTEST 1 (e)-[:CALLS]->{1,8}(api)
RETURN p LIMIT 1;

// D7. [graph] Data flow: the Wi-Fi name travelling through the code, step by step
MATCH (src:Statement {kind: 'invoke', target_name: 'getSSID'})
MATCH (sink:Statement {kind: 'invoke', target_name: 'appendQueryParameter'})
MATCH p = SHORTEST 1 (src)-[:DATA_DEP|ARG|RETURN|WRITES_FIELD|READ_BY]->{1,15}(sink)
RETURN p;

// D8. [graph] Conditions: which `if` decides whether getSSID() runs
MATCH (src:Statement {kind: 'invoke', target_name: 'getSSID'})
MATCH (c:Statement)-[cd:CONTROL_DEP]->(src)
OPTIONAL MATCH (check:Statement {kind: 'invoke'})-[d:DATA_DEP*1..2]->(c)
RETURN src, c, cd, check, d;


// -----------------------------------------------------------------------------
// Part 2. The Privacy Property Graphs (PPGs): the method APGs that make a sensitive call
// -----------------------------------------------------------------------------

// D9. [table] Every PPG: which method, which data, why it is a PPG, where the data goes
MATCH (g:PPG)
RETURN g.method AS method, g.categories AS data_categories, g.data_types AS data,
       g.reasons AS why_it_is_a_ppg, g.sink_kinds AS data_goes_to, g.confidence AS confidence
ORDER BY method;

// D10. [table] Nutrition-label view: each kind of data, how many PPGs handle it, where it goes
MATCH (g:PPG)-[b:BECAUSE]->()
WHERE b.category IS NOT NULL
OPTIONAL MATCH (g)-[:HAS_FLOW]->(f:PrivacyFlow {data_type: b.data_type})
WITH b.category AS category, b.data_type AS data, count(DISTINCT g) AS ppgs, collect(DISTINCT f.kind) AS uses
RETURN category, data, ppgs, CASE WHEN size(uses) = 0 THEN ['read only'] ELSE uses END AS what_happens_to_it
ORDER BY category, data;

// D11. [graph] One PPG (setSsid): its method APG, reasons, sinks, trigger, conditions
MATCH (g:PPG {method: 'org.fdroid.fdroid.nearby.WifiStateChangeService.setSsid'})
MATCH (g)-[r:FOR_METHOD|BECAUSE|REACHES_SINK|TRIGGERED_BY|GUARDED_BY_CONDITION|REQUIRES_PERMISSION|CALLS_INTO]->(n)
RETURN g, r, n;

// D12. [graph] Everything inside that PPG's method APG: statements, control flow, data flow
MATCH (g:PPG {method: 'org.fdroid.fdroid.nearby.WifiStateChangeService.setSsid'})-[:INCLUDES]->(n)
WITH collect(n) AS nodes
UNWIND nodes AS a
MATCH (a)-[r:FLOWS_TO|DATA_DEP]->(b)
WHERE b IN nodes
RETURN a, r, b;

// D13. [table] Where each PPG's data travels: the methods it passes through, and where it ends
MATCH (g:PPG)-[:HAS_FLOW]->(f:PrivacyFlow)
RETURN g.method AS ppg, f.data_type AS data, f.through_methods AS passes_through,
       f.kind AS ends_in, f.sink_method AS sink_method, f.confidence AS confidence
ORDER BY ppg, data;

// D14. [table] Evidence for one flow, step by step (BSSID -> written to a file)
MATCH (f:PrivacyFlow {data_type: 'Wi-Fi access point ID', kind: 'storage_file'})
UNWIND range(0, size(f.path) - 1) AS step
RETURN step, f.evidence[step] AS instruction,
       head([(m:Method)-[:HAS_STATEMENT|HAS_PARAM]->(n:APG {uid: f.path[step]}) | m.class_name + '.' + m.name]) AS in_method;

// D15. [table] The method's own APG tables and Java (what classification and captions use)
MATCH (g:PPG {method: 'org.fdroid.fdroid.nearby.WifiStateChangeService.setSsid'})-[:FOR_METHOD]->(m)
RETURN m.parameters AS parameters, m.method_call_table AS method_call_table,
       m.data_flow_table AS data_flow_table, m.source AS java;

// D16. [table] Conditions guarding the sensitive calls in each PPG
MATCH (g:PPG)-[c:GUARDED_BY_CONDITION]->()
RETURN g.method AS method, c.guards AS guards_call_to, c.code AS condition, c.branch AS runs_when,
       c.uses_calls AS condition_uses, c.permission_check AS permission_check
ORDER BY method;

// D17. [table] Third-party SDKs: PPGs inside SDK code, or sending data to an SDK
MATCH (g:PPG)-[r:IN_SDK|SHARES_WITH]->(lib:Library)
RETURN g.method AS method, type(r) AS relation, lib.name AS sdk, lib.category AS category;

// D18. [table] Candidates left out because no entry point reaches them
MATCH (g:ExcludedPPG)-[:FOR_METHOD]->(m)
OPTIONAL MATCH (g)-[b:BECAUSE]->()
RETURN m.class_name + '.' + m.name AS method, collect(DISTINCT b.data_type) AS data, g.excluded_reason AS reason;

// D19. [table] Checks: all three should be 0
MATCH (g:PPG)
WITH count(CASE WHEN NOT exists { (g)-[:BECAUSE]->() } THEN 1 END) AS ppgs_without_reason
OPTIONAL MATCH (g2:PPG)-[:INCLUDES]->(n) WHERE n.app_id <> g2.app_id
WITH ppgs_without_reason, count(n) AS foreign_nodes
OPTIONAL MATCH (f:PrivacyFlow)
WITH ppgs_without_reason, foreign_nodes, f
UNWIND CASE WHEN f IS NULL THEN [null] ELSE range(0, size(f.path) - 2) END AS i
WITH ppgs_without_reason, foreign_nodes, f.path[i] AS a_uid, f.path[i + 1] AS b_uid
RETURN ppgs_without_reason, foreign_nodes,
       count(CASE WHEN a_uid IS NOT NULL AND NOT exists {
         MATCH (a:APG {uid: a_uid})-[:DATA_DEP|ARG|RETURN|WRITES_FIELD|READ_BY]->(b:APG {uid: b_uid}) } THEN 1 END) AS broken_evidence_steps;
