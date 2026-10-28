// =============================================================================
// Demo: from one method in the app's code, to its APG, to its PPG
//
// The example is WifiStateChangeService.setSsid in F-Droid, which reads the Wi-Fi
// network name and router ID. To use another method, replace the class/method names.
// The app ID is written into each query, so no :param is needed.
// Paste one query at a time into Neo4j Browser and press Ctrl+Enter.
//
// Before you start: the APG is loaded (python -m apg build ... --neo4j) and the
// strict PPGs are built (python scripts/build_ppg.py <app_id>, without --wide).
// =============================================================================


// -----------------------------------------------------------------------------
// STEP 1. Find the method in the code
// -----------------------------------------------------------------------------

// 1a. [table] Search the decompiled Java (made by Androguard) for a keyword.
//     Every method that mentions getSSID, with its code.
MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184', is_external: false})
WHERE m.source CONTAINS 'getSSID'
RETURN m.class_name + '.' + m.name AS method, m.source AS decompiled_java;

// 1b. [table] Every method of one class, with its size
MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184', class_name: 'org.fdroid.fdroid.nearby.WifiStateChangeService'})
RETURN m.name AS method, m.signature AS signature, m.instruction_count AS statements
ORDER BY method;


// -----------------------------------------------------------------------------
// STEP 2. The method's APG
// -----------------------------------------------------------------------------

// 2a. [graph] The method, its parameters and statements, with control flow
//     (FLOWS_TO) and data flow (DATA_DEP) between them
MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184', class_name: 'org.fdroid.fdroid.nearby.WifiStateChangeService', name: 'setSsid'})
MATCH (m)-[:HAS_STATEMENT|HAS_PARAM]->(n)
WITH m, collect(n) AS nodes
UNWIND nodes AS a
MATCH (a)-[r:FLOWS_TO|DATA_DEP]->(b)
WHERE b IN nodes
RETURN m, a, r, b;

// 2b. [table] The same APG as its tables: parameters, AST, control flow,
//     data flow and method calls
MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184', class_name: 'org.fdroid.fdroid.nearby.WifiStateChangeService', name: 'setSsid'})
RETURN m.parameters AS parameters, m.ast_table AS ast_table, m.cfg_table AS cfg_table,
       m.data_flow_table AS data_flow_table, m.method_call_table AS method_call_table;

// 2c. [graph] The methods this method calls (the Android APIs among them)
MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184', class_name: 'org.fdroid.fdroid.nearby.WifiStateChangeService', name: 'setSsid'})-[c:CALLS]->(callee:Method)
RETURN m, c, callee;


// -----------------------------------------------------------------------------
// STEP 3. Is this method's APG a PPG, and why? (cypher/ppg_for_method.cypher)
// -----------------------------------------------------------------------------

// 3a. [table] One query for one PPG
MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184'})
WHERE m.class_name + '.' + m.name = 'org.fdroid.fdroid.nearby.WifiStateChangeService.setSsid' AND m.is_external = false

// Reason 1: calls an API that returns personal data
OPTIONAL MATCH (m)-[c:CALLS]->(api:SourceAPI)
WITH m, [x IN collect(DISTINCT {reason: 'calls_sensitive_api', category: api.source_category,
                                data_type: api.data_type, detail: api.java_signature})
         WHERE x.category IS NOT NULL] AS r1

// Reason 1b: personal data read in a way proven from its arguments (android_id, contacts URI ...)
OPTIONAL MATCH (m)-[:HAS_STATEMENT]->(s:SourcePoint)
WHERE NOT exists { (s)-[:INVOKES]->(:SourceAPI) }
WITH m, r1, [x IN collect(DISTINCT {reason: 'calls_sensitive_api', category: s.source_category,
                                    data_type: s.data_type, detail: s.target_java_signature})
             WHERE x.category IS NOT NULL] AS r1b

// Reason 2: calls an API guarded by a dangerous (runtime) permission
OPTIONAL MATCH (m)-[:CALLS]->(papi:Method)-[:API_REQUIRES_PERMISSION]->(perm:Permission)
WHERE perm.name IN ['android.permission.ACCESS_FINE_LOCATION', 'android.permission.ACCESS_COARSE_LOCATION',
  'android.permission.ACCESS_BACKGROUND_LOCATION', 'android.permission.READ_CONTACTS', 'android.permission.WRITE_CONTACTS',
  'android.permission.GET_ACCOUNTS', 'android.permission.READ_CALENDAR', 'android.permission.WRITE_CALENDAR',
  'android.permission.READ_CALL_LOG', 'android.permission.WRITE_CALL_LOG', 'android.permission.READ_PHONE_STATE',
  'android.permission.READ_PHONE_NUMBERS', 'android.permission.CALL_PHONE', 'android.permission.SEND_SMS',
  'android.permission.RECEIVE_SMS', 'android.permission.READ_SMS', 'android.permission.RECEIVE_MMS',
  'android.permission.CAMERA', 'android.permission.RECORD_AUDIO', 'android.permission.BODY_SENSORS',
  'android.permission.ACTIVITY_RECOGNITION', 'android.permission.READ_EXTERNAL_STORAGE',
  'android.permission.WRITE_EXTERNAL_STORAGE', 'android.permission.READ_MEDIA_IMAGES',
  'android.permission.READ_MEDIA_VIDEO', 'android.permission.READ_MEDIA_AUDIO', 'android.permission.BLUETOOTH_SCAN',
  'android.permission.BLUETOOTH_CONNECT', 'android.permission.NEARBY_WIFI_DEVICES']
WITH m, r1, r1b, [x IN collect(DISTINCT {reason: 'requires_dangerous_permission', category: null,
                                         data_type: perm.name, detail: papi.java_signature})
                  WHERE x.data_type IS NOT NULL] AS r2

// Reason 3: personal data flows into the method (callback parameter, or from another method)
OPTIONAL MATCH (m)-[:HAS_PARAM]->(p:Parameter:SourcePoint)
WITH m, r1, r1b, r2, [x IN collect(DISTINCT {reason: 'receives_personal_data', category: p.source_category,
                                             data_type: p.data_type, detail: 'callback parameter'})
                      WHERE x.category IS NOT NULL] AS r3a
WITH m, r1 + r1b + r2 + r3a AS reasons

// Where this PPG's data goes: flows that start at its sensitive calls
OPTIONAL MATCH (m)-[:HAS_STATEMENT|HAS_PARAM]->(src)<-[:FROM]-(f:PrivacyFlow)
WITH m, reasons, [x IN collect(DISTINCT {data_type: f.data_type, sink_kind: f.kind, sink: f.api,
                                         sink_method: f.sink_method, through_methods: f.through_methods,
                                         confidence: f.confidence, evidence: f.evidence})
                  WHERE x.sink_kind IS NOT NULL] AS flows

// Not a reason, just context: personal data read elsewhere that passes through this method
OPTIONAL MATCH (f2:PrivacyFlow {app_id: 'org.fdroid.fdroid@1021051-b6465184'})
WHERE (m.class_name + '.' + m.name) IN f2.through_methods AND f2.source_method <> m.class_name + '.' + m.name
WITH m, reasons, flows, collect(DISTINCT f2.data_type + ' from ' + f2.source_method) AS passes_data_from
RETURN m.class_name + '.' + m.name AS method,
       m.signature AS signature,
       size(reasons) > 0 AS is_ppg,
       reasons,
       [c IN reduce(acc = [], r IN reasons | acc + [r.category]) WHERE c IS NOT NULL] AS categories,
       flows,
       passes_data_from,
       m.parameters AS parameters,
       m.instruction_count AS statements,
       m.source AS java,
       m.ast_table AS ast_table,
       m.cfg_table AS cfg_table,
       m.data_flow_table AS data_flow_table,
       m.method_call_table AS method_call_table;

// 3b. [graph] The PPG built for it: its method APG, reasons, sinks, trigger, conditions
MATCH (g:PPG {app_id: 'org.fdroid.fdroid@1021051-b6465184', method: 'org.fdroid.fdroid.nearby.WifiStateChangeService.setSsid'})
MATCH (g)-[r:FOR_METHOD|BECAUSE|REACHES_SINK|TRIGGERED_BY|GUARDED_BY_CONDITION|REQUIRES_PERMISSION]->(n)
RETURN g, r, n;


// -----------------------------------------------------------------------------
// STEP 4. The query that finds the PPGs among ALL method APGs
//   The same filter as P6a + P7 in cypher/ppg_build.cypher, but read-only: it
//   checks every method APG in the app, keeps those that call an API returning
//   personal data, and checks that the app can actually run them.
//   setSsid should be in the list with is_ppg = true.
// -----------------------------------------------------------------------------

// 4a. [table] Every method APG that calls a sensitive API, and whether it is a PPG
MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184', is_external: false})-[:CALLS]->(api:SourceAPI)
WHERE api.source_list = 'curated'
WITH m, collect(DISTINCT api.data_type) AS personal_data,
     collect(DISTINCT api.java_signature) AS sensitive_calls
OPTIONAL CALL (m) {
  MATCH (m)-[:OVERRIDES*0..2]->(target:Method)
  WHERE target = m OR target.origin IN ['app', 'unknown']
  MATCH p = SHORTEST 1 (e:Method WHERE e.is_entrypoint = true OR e.name = '<clinit>')-[:CALLS]->{0,12}(target)
  RETURN e.class_name + '.' + e.name AS triggered_by, length(p) AS hops
  ORDER BY hops LIMIT 1
}
RETURN m.class_name + '.' + m.name AS method, personal_data, sensitive_calls,
       triggered_by IS NOT NULL AS is_ppg, triggered_by
ORDER BY is_ppg DESC, method;

// 4b. [table] The PPGs the build created: should match the is_ppg = true rows above
MATCH (g:PPG {app_id: 'org.fdroid.fdroid@1021051-b6465184'})
RETURN g.method AS method, g.data_types AS personal_data, g.reasons AS why, g.entrypoint AS triggered_by
ORDER BY method;
