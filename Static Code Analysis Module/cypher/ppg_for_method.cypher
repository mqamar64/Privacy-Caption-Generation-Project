// =============================================================================
// One query for one PPG: is this method's APG a PPG, and why?
//
// Give it one method; it returns that method's whole APG (parameters, AST, control
// flow, data-flow table, method-call table, decompiled Java), the reasons it is or is
// not a PPG, the personal-data categories involved, and where the data goes.
//
// A method's APG is a PPG when the method itself makes the sensitive call. Needs the
// source/sink markers from cypher/ppg_build.cypher (P2-P5), which scripts/build_ppg.py
// creates; the flows need P8-P10.
//
// Neo4j Browser:
//   :param app => 'org.fdroid.fdroid@1021051-b6465184'
//   :param method => 'org.fdroid.fdroid.nearby.WifiStateChangeService.setSsid'
// then run the query below. ($method is Class.methodName; overloads all appear.)
// =============================================================================

MATCH (m:Method {app_id: $app})
WHERE m.class_name + '.' + m.name = $method AND m.is_external = false

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
OPTIONAL MATCH (f2:PrivacyFlow {app_id: $app})
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
