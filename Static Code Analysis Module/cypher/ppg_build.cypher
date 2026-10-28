// =============================================================================
// Privacy Property Graphs (PPGs) from an App Property Graph (APG)
//
// Unit: one METHOD = one APG (its AST, control flow, data-flow table and method-call
// table; see the Method node's ast_table / cfg_table / data_flow_table /
// method_call_table properties). The whole app graph holds every method's APG.
//
// A method's APG is a PPG when that method itself makes the sensitive call, wherever it
// sits in the call hierarchy. These queries filter the APGs down to the PPGs and record
// WHY each one is a PPG:
//   * calls_sensitive_api            - it calls an API that returns personal data
//   * requires_dangerous_permission  - it calls an API guarded by a dangerous permission
//   * receives_personal_data         - Android hands it personal data as a callback
//                                      parameter (e.g. the Location in onLocationChanged)
// The methods the data later passes through are recorded on the PPG's flows
// (through_methods); they are not separate PPGs.
// A PPG includes EVERYTHING in that method's APG (all statements and parameters, with
// its tables and decompiled Java), plus its reasons, the data categories involved
// (one PPG can have several, e.g. financial + location), where the data goes (sinks,
// with evidence paths), the conditions guarding it, its permissions, and the entry
// point that runs it. Classification then labels each PPG.
//
// Precision rules (to avoid false positives):
//   * Sources are a fixed list of APIs that RETURN personal data (not "is Wi-Fi on?").
//   * Only dangerous (runtime) permissions count as a reason.
//   * A PPG must be reachable from an entry point; unreachable ones become ExcludedPPG.
//   * Data must reach a specific argument of a sink, and may not pass through calls that
//     turn it into a yes/no or a number about it (isEmpty, equals, length ...).
//   * Every element is an existing APG node and every evidence step an existing APG edge.
//
// Run the queries in order with $app = the App's app_id:
//   Neo4j Browser:  :param app => 'org.fdroid.fdroid@1021051-b6465184'
//   or:             python scripts/build_ppg.py <app_id> --export output/ppg
// For one method on its own, see cypher/ppg_for_method.cypher.
// =============================================================================


// -----------------------------------------------------------------------------
// P0. Schema
// -----------------------------------------------------------------------------
CREATE CONSTRAINT ppg_id IF NOT EXISTS FOR (g:PPG) REQUIRE g.ppg_id IS UNIQUE;

CREATE INDEX ppg_app IF NOT EXISTS FOR (g:PPG) ON (g.app_id);

CREATE INDEX excluded_ppg_app IF NOT EXISTS FOR (g:ExcludedPPG) ON (g.app_id);

CREATE INDEX flow_app IF NOT EXISTS FOR (f:PrivacyFlow) ON (f.app_id);


// -----------------------------------------------------------------------------
// P1. Reset: remove this app's PPGs, flows and markers from a previous run
// -----------------------------------------------------------------------------
MATCH (g:PPG|ExcludedPPG {app_id: $app}) DETACH DELETE g;

MATCH (f:PrivacyFlow {app_id: $app}) DETACH DELETE f;

MATCH (n:APG {app_id: $app}) WHERE n:SourcePoint OR n:SinkPoint OR n:SourceAPI OR n:SinkAPI
REMOVE n:SourcePoint, n:SinkPoint, n:SourceAPI, n:SinkAPI,
       n.source_category, n.data_type, n.source_list, n.sink_kind, n.sink_args, n.sink_detail;


// -----------------------------------------------------------------------------
// P2. Source APIs: Android/SDK methods that RETURN personal data.
//     Categories follow the Document Analysis Module's names.
//     Edit this list to add sources; keep it to APIs whose return value IS the data.
// -----------------------------------------------------------------------------
UNWIND [
  // Location
  {c:'android.location.LocationManager', m:'getLastKnownLocation', cat:'LOCATION_INFORMATION', d:'device location'},
  {c:'android.location.Location', m:'getLatitude', cat:'LOCATION_INFORMATION', d:'latitude'},
  {c:'android.location.Location', m:'getLongitude', cat:'LOCATION_INFORMATION', d:'longitude'},
  {c:'android.location.Location', m:'getAltitude', cat:'LOCATION_INFORMATION', d:'altitude'},
  {c:'com.google.android.gms.location.FusedLocationProviderClient', m:'getLastLocation', cat:'LOCATION_INFORMATION', d:'device location'},
  {c:'com.google.android.gms.location.FusedLocationProviderClient', m:'getCurrentLocation', cat:'LOCATION_INFORMATION', d:'device location'},
  {c:'android.net.wifi.WifiManager', m:'getScanResults', cat:'LOCATION_INFORMATION', d:'nearby Wi-Fi networks'},
  // Device and advertising identifiers
  {c:'android.telephony.TelephonyManager', m:'getDeviceId', cat:'UNIQUE_IDENTIFIER', d:'IMEI/MEID'},
  {c:'android.telephony.TelephonyManager', m:'getImei', cat:'UNIQUE_IDENTIFIER', d:'IMEI'},
  {c:'android.telephony.TelephonyManager', m:'getMeid', cat:'UNIQUE_IDENTIFIER', d:'MEID'},
  {c:'android.telephony.TelephonyManager', m:'getSubscriberId', cat:'UNIQUE_IDENTIFIER', d:'IMSI'},
  {c:'android.telephony.TelephonyManager', m:'getSimSerialNumber', cat:'UNIQUE_IDENTIFIER', d:'SIM serial number'},
  {c:'android.telephony.TelephonyManager', m:'getLine1Number', cat:'UNIQUE_IDENTIFIER', d:'phone number'},
  {c:'android.os.Build', m:'getSerial', cat:'UNIQUE_IDENTIFIER', d:'device serial number'},
  {c:'android.net.wifi.WifiInfo', m:'getMacAddress', cat:'UNIQUE_IDENTIFIER', d:'Wi-Fi MAC address'},
  {c:'java.net.NetworkInterface', m:'getHardwareAddress', cat:'UNIQUE_IDENTIFIER', d:'MAC address'},
  {c:'android.bluetooth.BluetoothAdapter', m:'getAddress', cat:'UNIQUE_IDENTIFIER', d:'Bluetooth MAC address'},
  {c:'com.google.android.gms.ads.identifier.AdvertisingIdClient$Info', m:'getId', cat:'UNIQUE_IDENTIFIER', d:'advertising ID'},
  // Network
  {c:'android.net.wifi.WifiInfo', m:'getSSID', cat:'NETWORK_INFORMATION', d:'Wi-Fi network name'},
  {c:'android.net.wifi.WifiInfo', m:'getBSSID', cat:'NETWORK_INFORMATION', d:'Wi-Fi access point ID'},
  {c:'android.net.wifi.WifiInfo', m:'getIpAddress', cat:'NETWORK_INFORMATION', d:'IP address'},
  {c:'android.net.wifi.WifiManager', m:'getDhcpInfo', cat:'NETWORK_INFORMATION', d:'IP/DHCP information'},
  // Bluetooth
  {c:'android.bluetooth.BluetoothAdapter', m:'getName', cat:'BLUETOOTH_INFORMATION', d:'device Bluetooth name'},
  {c:'android.bluetooth.BluetoothAdapter', m:'getBondedDevices', cat:'BLUETOOTH_INFORMATION', d:'paired Bluetooth devices'},
  {c:'android.bluetooth.BluetoothDevice', m:'getAddress', cat:'BLUETOOTH_INFORMATION', d:'nearby device address'},
  {c:'android.bluetooth.BluetoothDevice', m:'getName', cat:'BLUETOOTH_INFORMATION', d:'nearby device name'},
  // Accounts
  {c:'android.accounts.AccountManager', m:'getAccounts', cat:'ACCOUNT_INFORMATION', d:'accounts on device'},
  {c:'android.accounts.AccountManager', m:'getAccountsByType', cat:'ACCOUNT_INFORMATION', d:'accounts on device'},
  {c:'com.google.android.gms.auth.api.signin.GoogleSignInAccount', m:'getEmail', cat:'EMAIL', d:'email address'},
  {c:'com.google.android.gms.auth.api.signin.GoogleSignInAccount', m:'getDisplayName', cat:'ACCOUNT_INFORMATION', d:'account name'},
  // Messages
  {c:'android.telephony.SmsMessage', m:'getMessageBody', cat:'SMS_MMS', d:'SMS text'},
  {c:'android.telephony.SmsMessage', m:'getDisplayMessageBody', cat:'SMS_MMS', d:'SMS text'},
  {c:'android.telephony.SmsMessage', m:'getOriginatingAddress', cat:'SMS_MMS', d:'SMS sender number'},
  // Clipboard and installed apps
  {c:'android.content.ClipboardManager', m:'getPrimaryClip', cat:'CLIPBOARD', d:'clipboard contents'},
  {c:'android.content.ClipboardManager', m:'getText', cat:'CLIPBOARD', d:'clipboard contents'},
  {c:'android.content.pm.PackageManager', m:'getInstalledPackages', cat:'INSTALLED_APPS', d:'installed apps'},
  {c:'android.content.pm.PackageManager', m:'getInstalledApplications', cat:'INSTALLED_APPS', d:'installed apps'}
] AS s
MATCH (m:Method {app_id: $app, class_name: s.c, name: s.m})
SET m:SourceAPI, m.source_category = s.cat, m.data_type = s.d, m.source_list = 'curated'
RETURN s.cat AS category, s.c + '.' + s.m AS api, count(m) AS overloads_in_apg
ORDER BY category, api;


// -----------------------------------------------------------------------------
// P2b. WIDE MODE ONLY (python scripts/build_ppg.py <app_id> --wide): add the Document
//      Analysis Module's categorised sources (formatted_sources.csv, passed in as
//      $doc_sources). They are broader than the curated list above and include APIs
//      that are not personal data, so PPGs found only through them get confidence
//      'review'. Skip this query when running the file by hand.
// -----------------------------------------------------------------------------
UNWIND $doc_sources AS s
MATCH (m:Method {app_id: $app, class_name: s.class_name, name: s.method_name})
WHERE m.param_types = s.param_types AND NOT m:SourceAPI
SET m:SourceAPI, m.source_category = s.category, m.data_type = s.category + ' (Document Analysis)',
    m.source_list = 'document_analysis'
RETURN s.category AS category, count(DISTINCT m) AS apis_in_apg
ORDER BY category;


// -----------------------------------------------------------------------------
// P3. Source points (where the app's own code reads the data). Four kinds:
// -----------------------------------------------------------------------------
// P3a. Calls to a source API from code that has statements (app / unrecognised code)
MATCH (s:Statement {app_id: $app, kind: 'invoke'})-[:INVOKES]->(api:SourceAPI)
SET s:SourcePoint, s.source_category = api.source_category, s.data_type = api.data_type
RETURN s.source_category AS category, api.class_name + '.' + api.name AS api, count(s) AS call_sites
ORDER BY category, api;

// P3b. Settings.Secure.getString(resolver, "android_id"): only when the key IS "android_id"
MATCH (s:Statement {app_id: $app, kind: 'invoke', target_class: 'android.provider.Settings$Secure', target_name: 'getString'})
MATCH (k:Statement {kind: 'const_string', literal: 'android_id'})-[:DATA_DEP]->(s)
SET s:SourcePoint, s.source_category = 'UNIQUE_IDENTIFIER', s.data_type = 'Android ID'
RETURN count(DISTINCT s) AS android_id_reads;

// P3c. ContentResolver.query on a personal-data content provider. The provider is proven
//      by its URI constant (e.g. ContactsContract...CONTENT_URI) flowing into the query.
UNWIND [
  {p:'android.provider.ContactsContract', cat:'CONTACT_INFORMATION', d:'contacts'},
  {p:'android.provider.CallLog', cat:'CONTACT_INFORMATION', d:'call log'},
  {p:'android.provider.CalendarContract', cat:'CALENDAR_INFORMATION', d:'calendar events'},
  {p:'android.provider.Telephony', cat:'SMS_MMS', d:'SMS/MMS messages'},
  {p:'android.provider.MediaStore', cat:'IMAGE', d:'photos and media'},
  {p:'android.provider.Browser', cat:'BROWSER_INFORMATION', d:'browser history'}
] AS prov
MATCH (q:Statement {app_id: $app, kind: 'invoke', target_class: 'android.content.ContentResolver', target_name: 'query'})
MATCH (f:Field)-[:READ_BY]->(uri:Statement)-[:DATA_DEP*1..3]->(q)
WHERE f.class_name STARTS WITH prov.p
SET q:SourcePoint, q.source_category = prov.cat, q.data_type = prov.d
RETURN prov.d AS provider, count(DISTINCT q) AS queries;

// P3d. Callbacks that RECEIVE location: the Location parameter of onLocationChanged / onLocationResult
MATCH (m:Method {app_id: $app})-[:OVERRIDES]->(api:Method)
WHERE (api.class_name = 'android.location.LocationListener' AND api.name = 'onLocationChanged')
   OR (api.class_name = 'com.google.android.gms.location.LocationCallback' AND api.name = 'onLocationResult')
MATCH (m)-[:HAS_PARAM]->(p:Parameter {index: 1})
SET p:SourcePoint, p.source_category = 'LOCATION_INFORMATION', p.data_type = 'device location'
RETURN count(p) AS location_callbacks;


// -----------------------------------------------------------------------------
// P4. Sink APIs: where data is stored, logged, shown, sent or shared.
//     args = positions in the call's `uses` list that count (0 = the object a method
//     is called on, then the arguments in order; for static calls 0 = first argument).
// -----------------------------------------------------------------------------
UNWIND [
  // Logging
  {c:'android.util.Log', m:['d','e','i','v','w','wtf'], k:'log', a:[1,2], det:'Android log'},
  {c:'android.util.Log', m:['println'], k:'log', a:[2], det:'Android log'},
  {c:'java.io.PrintStream', m:['println','print'], k:'log', a:[1], det:'standard output'},
  // URLs and network requests
  {c:'java.net.URL', m:['<init>'], k:'url', a:[1,2,3], det:'URL'},
  {c:'android.net.Uri', m:['parse'], k:'url', a:[0], det:'URI'},
  {c:'android.net.Uri$Builder', m:['appendQueryParameter'], k:'url', a:[1,2], det:'URI query'},
  {c:'android.net.Uri$Builder', m:['appendPath','path','query','encodedQuery','encodedPath','authority'], k:'url', a:[1], det:'URI'},
  {c:'java.net.HttpURLConnection', m:['setRequestProperty','addRequestProperty'], k:'network', a:[1,2], det:'HTTP header'},
  {c:'java.net.URLConnection', m:['setRequestProperty','addRequestProperty'], k:'network', a:[1,2], det:'HTTP header'},
  {c:'android.webkit.WebView', m:['loadUrl','postUrl','evaluateJavascript'], k:'network', a:[1,2], det:'WebView'},
  {c:'android.telephony.SmsManager', m:['sendTextMessage','sendMultipartTextMessage'], k:'sms', a:[1,3], det:'SMS'},
  // Streams: file, network socket or Bluetooth; P5 works out which
  {c:'java.io.OutputStream', m:['write'], k:'stream', a:[1], det:'output stream'},
  {c:'java.io.Writer', m:['write','append'], k:'stream', a:[1], det:'writer'},
  {c:'java.io.PrintWriter', m:['write','print','println','append'], k:'stream', a:[1], det:'writer'},
  {c:'java.io.DataOutputStream', m:['write','writeUTF','writeBytes','writeInt','writeLong'], k:'stream', a:[1], det:'output stream'},
  // Storage on the device
  {c:'android.content.SharedPreferences$Editor', m:['putString','putInt','putLong','putFloat','putBoolean','putStringSet'], k:'storage_preferences', a:[2], det:'SharedPreferences'},
  {c:'android.database.sqlite.SQLiteDatabase', m:['insert','insertOrThrow','insertWithOnConflict','replace','update','execSQL'], k:'storage_database', a:[1,2,3], det:'SQLite'},
  {c:'android.content.ContentValues', m:['put'], k:'storage_database', a:[2], det:'database values'},
  {c:'android.content.ContentResolver', m:['insert','update','bulkInsert'], k:'storage_database', a:[2], det:'content provider'},
  // Other apps and system
  {c:'android.content.Intent', m:['putExtra','putExtras','setData','setDataAndType'], k:'ipc', a:[1,2], det:'Intent'},
  {c:'android.content.ClipboardManager', m:['setPrimaryClip','setText'], k:'clipboard', a:[1], det:'clipboard'},
  {c:'android.content.ClipData', m:['newPlainText','newRawUri','newUri'], k:'clipboard', a:[1,2], det:'clipboard'},
  // Shown on screen
  {c:'android.widget.TextView', m:['setText','append','setHint'], k:'ui_display', a:[1], det:'text on screen'},
  {c:'android.widget.Toast', m:['makeText'], k:'ui_display', a:[1], det:'toast message'},
  {c:'android.app.AlertDialog$Builder', m:['setMessage','setTitle'], k:'ui_display', a:[1], det:'dialog'}
] AS spec
UNWIND spec.m AS name
MATCH (m:Method {app_id: $app, class_name: spec.c, name: name})
SET m:SinkAPI, m.sink_kind = spec.k, m.sink_args = spec.a, m.sink_detail = spec.det
RETURN spec.k AS kind, spec.c AS class, collect(DISTINCT name) AS methods, count(m) AS in_apg
ORDER BY kind, class;

// P4b. Sink points: calls to sink APIs
MATCH (t:Statement {app_id: $app, kind: 'invoke'})-[:INVOKES]->(api:SinkAPI)
SET t:SinkPoint, t.sink_kind = api.sink_kind, t.sink_args = api.sink_args, t.sink_detail = api.sink_detail
RETURN t.sink_kind AS kind, count(t) AS call_sites ORDER BY kind;

// P4c. Sink points: calls into third-party SDKs that send data elsewhere (analytics,
//      ads, crash reporting, networking ...). Okio (file/buffer I/O) and runtime libraries (Kotlin, AndroidX,
//      serialization, UI) are not counted as sharing.
MATCH (t:Statement {app_id: $app, kind: 'invoke'})-[:INVOKES]->(api:Method {origin: 'library'})
MATCH (api)<-[:HAS_METHOD]-(:Class)-[:BELONGS_TO]->(lib:Library)
WHERE lib.category IN ['analytics', 'attribution', 'advertising', 'crash_reporting', 'monitoring',
                       'social', 'authentication', 'push_messaging', 'backend', 'payments',
                       'location', 'networking', 'logging']
  AND lib.name <> 'Okio'
  AND NOT t:SinkPoint
SET t:SinkPoint,
    t.sink_kind = CASE lib.category WHEN 'networking' THEN 'network'
                                    WHEN 'logging' THEN 'log'
                                    ELSE 'third_party_sdk' END,
    t.sink_args = CASE WHEN t.opcode STARTS WITH 'invoke-static' THEN range(0, 9) ELSE range(1, 9) END,
    t.sink_detail = lib.name
RETURN lib.name AS sdk, lib.category AS category, count(t) AS call_sites ORDER BY sdk;


// -----------------------------------------------------------------------------
// P5. Streams: decide whether a write goes to a file, the network or Bluetooth, from
//     where the stream object came from. Unresolved streams stay kind 'stream'.
// -----------------------------------------------------------------------------
MATCH (t:SinkPoint {app_id: $app, sink_kind: 'stream'})
MATCH (o:Statement)-[:DATA_DEP*1..6]->(t)
WHERE (o.kind = 'invoke' AND o.target_name = 'getOutputStream')
   OR (o.kind = 'invoke' AND o.target_name = '<init>' AND o.target_class IN
        ['java.io.FileOutputStream', 'java.io.FileWriter', 'java.io.RandomAccessFile'])
WITH t, collect(DISTINCT CASE
       WHEN o.target_class IN ['java.net.Socket', 'java.net.HttpURLConnection', 'java.net.URLConnection',
                               'javax.net.ssl.HttpsURLConnection'] THEN 'network'
       WHEN o.target_class STARTS WITH 'android.bluetooth' THEN 'bluetooth'
       WHEN o.target_class IN ['java.io.FileOutputStream', 'java.io.FileWriter', 'java.io.RandomAccessFile']
            THEN 'storage_file'
       ELSE NULL END) AS kinds
WHERE size(kinds) = 1
SET t.sink_kind = kinds[0]
RETURN t.sink_kind AS resolved_kind, count(t) AS streams;



// -----------------------------------------------------------------------------
// P6. Candidate PPGs: method APGs with a direct reason to be a PPG
// -----------------------------------------------------------------------------
// P6a. Reason calls_sensitive_api: the method calls an API that returns personal data
MATCH (m:Method {app_id: $app, is_external: false})-[c:CALLS]->(api:SourceAPI)
MERGE (g:PPG {ppg_id: $app + '|PPG|' + m.signature})
SET g.app_id = $app
MERGE (g)-[:FOR_METHOD]->(m)
MERGE (g)-[b:BECAUSE {reason: 'calls_sensitive_api'}]->(api)
SET b.category = api.source_category, b.data_type = api.data_type,
    b.detail = api.java_signature, b.call_sites = c.count, b.source_list = api.source_list,
    b.confidence = CASE api.source_list WHEN 'document_analysis' THEN 'review' ELSE 'high' END
RETURN api.source_category AS category, api.data_type AS data, count(DISTINCT m) AS methods
ORDER BY category, data;

// P6b. Reason calls_sensitive_api, special cases proven from arguments (android_id, provider URIs)
MATCH (m:Method {app_id: $app})-[:HAS_STATEMENT]->(s:SourcePoint)
WHERE NOT exists { (s)-[:INVOKES]->(:SourceAPI) }
MERGE (g:PPG {ppg_id: $app + '|PPG|' + m.signature})
SET g.app_id = $app
MERGE (g)-[:FOR_METHOD]->(m)
MERGE (g)-[b:BECAUSE {reason: 'calls_sensitive_api'}]->(s)
SET b.category = s.source_category, b.data_type = s.data_type,
    b.detail = s.target_java_signature, b.confidence = 'high'
RETURN s.data_type AS data, count(DISTINCT m) AS methods;

// P6c. Reason receives_personal_data: callback parameters that carry personal data (Location)
MATCH (m:Method {app_id: $app})-[:HAS_PARAM]->(p:Parameter:SourcePoint)
MERGE (g:PPG {ppg_id: $app + '|PPG|' + m.signature})
SET g.app_id = $app
MERGE (g)-[:FOR_METHOD]->(m)
MERGE (g)-[b:BECAUSE {reason: 'receives_personal_data'}]->(p)
SET b.category = p.source_category, b.data_type = p.data_type,
    b.detail = 'parameter ' + toString(p.index) + ' of ' + m.name, b.confidence = 'high'
RETURN count(DISTINCT m) AS methods;

// P6d. Reason requires_dangerous_permission: the method calls an API guarded by a
//      dangerous (runtime) permission
UNWIND [
  {p:'android.permission.ACCESS_FINE_LOCATION', cat:'LOCATION_INFORMATION'},
  {p:'android.permission.ACCESS_COARSE_LOCATION', cat:'LOCATION_INFORMATION'},
  {p:'android.permission.ACCESS_BACKGROUND_LOCATION', cat:'LOCATION_INFORMATION'},
  {p:'android.permission.READ_CONTACTS', cat:'CONTACT_INFORMATION'},
  {p:'android.permission.WRITE_CONTACTS', cat:'CONTACT_INFORMATION'},
  {p:'android.permission.GET_ACCOUNTS', cat:'ACCOUNT_INFORMATION'},
  {p:'android.permission.READ_CALENDAR', cat:'CALENDAR_INFORMATION'},
  {p:'android.permission.WRITE_CALENDAR', cat:'CALENDAR_INFORMATION'},
  {p:'android.permission.READ_CALL_LOG', cat:'CONTACT_INFORMATION'},
  {p:'android.permission.WRITE_CALL_LOG', cat:'CONTACT_INFORMATION'},
  {p:'android.permission.READ_PHONE_STATE', cat:'UNIQUE_IDENTIFIER'},
  {p:'android.permission.READ_PHONE_NUMBERS', cat:'UNIQUE_IDENTIFIER'},
  {p:'android.permission.CALL_PHONE', cat:'CONTACT_INFORMATION'},
  {p:'android.permission.SEND_SMS', cat:'SMS_MMS'},
  {p:'android.permission.RECEIVE_SMS', cat:'SMS_MMS'},
  {p:'android.permission.READ_SMS', cat:'SMS_MMS'},
  {p:'android.permission.RECEIVE_MMS', cat:'SMS_MMS'},
  {p:'android.permission.CAMERA', cat:'IMAGE'},
  {p:'android.permission.RECORD_AUDIO', cat:'AUDIO'},
  {p:'android.permission.BODY_SENSORS', cat:'HEALTH_INFORMATION'},
  {p:'android.permission.ACTIVITY_RECOGNITION', cat:'HEALTH_INFORMATION'},
  {p:'android.permission.READ_EXTERNAL_STORAGE', cat:'FILE_INFORMATION'},
  {p:'android.permission.WRITE_EXTERNAL_STORAGE', cat:'FILE_INFORMATION'},
  {p:'android.permission.READ_MEDIA_IMAGES', cat:'IMAGE'},
  {p:'android.permission.READ_MEDIA_VIDEO', cat:'IMAGE'},
  {p:'android.permission.READ_MEDIA_AUDIO', cat:'AUDIO'},
  {p:'android.permission.BLUETOOTH_SCAN', cat:'BLUETOOTH_INFORMATION'},
  {p:'android.permission.BLUETOOTH_CONNECT', cat:'BLUETOOTH_INFORMATION'},
  {p:'android.permission.NEARBY_WIFI_DEVICES', cat:'NETWORK_INFORMATION'}
] AS d
MATCH (perm:Permission {app_id: $app, name: d.p})<-[:API_REQUIRES_PERMISSION]-(api:Method)
MATCH (m:Method {app_id: $app, is_external: false})-[:CALLS]->(api)
WITH m, perm, d, collect(DISTINCT api.java_signature) AS apis
MERGE (g:PPG {ppg_id: $app + '|PPG|' + m.signature})
SET g.app_id = $app
MERGE (g)-[:FOR_METHOD]->(m)
MERGE (g)-[b:BECAUSE {reason: 'requires_dangerous_permission'}]->(perm)
SET b.category = d.cat, b.data_type = perm.name, b.detail = apis, b.confidence = 'high'
RETURN perm.name AS permission, count(DISTINCT m) AS methods;


// -----------------------------------------------------------------------------
// P7. Keep only PPGs an entry point can reach (others become ExcludedPPG, see V2).
//     A method is also reached when code calls the app interface/parent method it
//     overrides (virtual dispatch).
// -----------------------------------------------------------------------------
MATCH (g:PPG {app_id: $app})-[:FOR_METHOD]->(m)
OPTIONAL CALL (m) {
  MATCH (m)-[:OVERRIDES*0..2]->(target:Method)
  WHERE target = m OR target.origin IN ['app', 'unknown']
  MATCH p = SHORTEST 1 (e:Method WHERE e.is_entrypoint = true OR e.name = '<clinit>')-[:CALLS]->{0,12}(target)
  RETURN e, [n IN nodes(p) | n.class_name + '.' + n.name] AS chain, length(p) AS hops
  ORDER BY hops LIMIT 1
}
WITH g, e, chain, hops
FOREACH (_ IN CASE WHEN e IS NULL THEN [1] ELSE [] END |
  REMOVE g:PPG SET g:ExcludedPPG, g.excluded_reason = 'not reachable from any entry point')
FOREACH (_ IN CASE WHEN e IS NULL THEN [] ELSE [1] END |
  SET g.entrypoint = e.class_name + '.' + e.name,
      g.entrypoint_kind = coalesce(e.entrypoint_kind, 'class_init'),
      g.call_chain = chain
  MERGE (g)-[t:TRIGGERED_BY]->(e) SET t.hops = hops)
RETURN e IS NOT NULL AS reachable, count(*) AS ppgs;


// -----------------------------------------------------------------------------
// P8. Privacy flows: from personal data read in a PPG to every sink it reaches.
//     A path follows only APG data edges and must end on a counted argument of the sink.
// -----------------------------------------------------------------------------
MATCH (g:PPG {app_id: $app})-[:FOR_METHOD]->(m)-[:HAS_STATEMENT|HAS_PARAM]->(src:SourcePoint)
MATCH p = SHORTEST 1 (
      (src)
      ((a)-[:DATA_DEP|ARG|RETURN|WRITES_FIELD|READ_BY]->(b)
         WHERE b:Field OR b:Parameter
            OR b.kind <> 'invoke'
            OR b:SinkPoint
            OR (NOT b.target_java_signature CONTAINS ': boolean '
                AND NOT b.target_name IN ['hashCode', 'length', 'size', 'compareTo', 'compareToIgnoreCase',
                                          'indexOf', 'lastIndexOf', 'getClass', 'ordinal', 'count']))
      {0,19}
      (x)-[final:DATA_DEP]->(t:SinkPoint)
      WHERE final.reg IN [i IN t.sink_args WHERE i < size(t.uses) | t.uses[i]] AND t <> src
    )
WITH m, src, t, p,
     size([r IN relationships(p) WHERE type(r) = 'WRITES_FIELD']) AS field_hops,
     size([r IN relationships(p) WHERE r.via IS NOT NULL]) AS callback_hops
MERGE (f:PrivacyFlow {flow_id: src.uid + ' -> ' + t.uid})
SET f.app_id = $app,
    f.category = src.source_category, f.data_type = src.data_type,
    f.kind = t.sink_kind, f.detail = t.sink_detail, f.api = t.target_java_signature,
    f.source_method = m.class_name + '.' + m.name,
    f.hops = length(p), f.field_hops = field_hops,
    f.confidence = CASE WHEN field_hops = 0 AND callback_hops = 0 THEN 'high' ELSE 'medium' END,
    f.path = [n IN nodes(p) | n.uid],
    f.evidence = [n IN nodes(p) | coalesce(n.code, 'field ' + n.signature, 'parameter ' + toString(n.index))]
MERGE (f)-[:FROM]->(src)
MERGE (f)-[:TO]->(t)
RETURN f.data_type AS data, f.kind AS sink_kind, count(f) AS flows
ORDER BY data, sink_kind;


// -----------------------------------------------------------------------------
// P9. Context for each flow: every method the personal data passes through on its way
//     to the sink. These methods are NOT separate PPGs; the PPG is the method that
//     made the sensitive call.
// -----------------------------------------------------------------------------
MATCH (f:PrivacyFlow {app_id: $app})
UNWIND range(0, size(f.path) - 1) AS i
MATCH (n:APG {uid: f.path[i]})<-[:HAS_STATEMENT|HAS_PARAM]-(m:Method)
WITH f, i, m.class_name + '.' + m.name AS method ORDER BY i
WITH f, collect(method) AS steps
SET f.through_methods = reduce(acc = [], x IN steps | CASE WHEN x IN acc THEN acc ELSE acc + [x] END)
RETURN f.data_type AS data, f.kind AS sink_kind, f.through_methods AS passes_through;


// -----------------------------------------------------------------------------
// P10. Link each PPG to its flows and the sinks its data reaches
// -----------------------------------------------------------------------------
MATCH (g:PPG {app_id: $app})-[:FOR_METHOD]->(:Method)-[:HAS_STATEMENT|HAS_PARAM]->(src)<-[:FROM]-(f:PrivacyFlow)-[:TO]->(t)
MATCH (t)<-[:HAS_STATEMENT]-(tm:Method)
SET f.sink_method = tm.class_name + '.' + tm.name
MERGE (g)-[:HAS_FLOW]->(f)
MERGE (g)-[r:REACHES_SINK {flow: f.flow_id}]->(t)
SET r.kind = f.kind, r.detail = f.detail, r.api = f.api, r.data_type = f.data_type,
    r.sink_method = f.sink_method, r.through_methods = f.through_methods,
    r.confidence = f.confidence, r.evidence = f.evidence, r.path = f.path, r.hops = f.hops
RETURN f.kind AS sink_kind, count(r) AS sinks;


// -----------------------------------------------------------------------------
// P11. Everything inside each method's APG belongs to its PPG, plus calls between PPGs
// -----------------------------------------------------------------------------
// P11a. All statements and parameters of the method
MATCH (g:PPG {app_id: $app})-[:FOR_METHOD]->(m)-[:HAS_STATEMENT|HAS_PARAM]->(n)
MERGE (g)-[:INCLUDES]->(n)
RETURN count(DISTINCT g) AS ppgs, count(n) AS nodes_included;

// P11b. Method call tree between PPGs (one PPG's method calls another's)
MATCH (g1:PPG {app_id: $app})-[:FOR_METHOD]->(m1)-[c:CALLS]->(m2)<-[:FOR_METHOD]-(g2:PPG)
WHERE g1 <> g2
MERGE (g1)-[r:CALLS_INTO]->(g2)
SET r.via = c.via, r.count = c.count
RETURN count(r) AS calls_between_ppgs;


// -----------------------------------------------------------------------------
// P12. Context: conditions, permissions, SDKs
// -----------------------------------------------------------------------------
// P12a. Conditions deciding whether the sensitive calls in the method run
MATCH (g:PPG {app_id: $app})-[:FOR_METHOD]->(m)-[:HAS_STATEMENT]->(s:Statement)
WHERE s:SourcePoint OR exists { (s)-[:INVOKES]->(:Method)-[:API_REQUIRES_PERMISSION]->(:Permission) }
MATCH (c:Statement)-[cd:CONTROL_DEP]->(s)
OPTIONAL MATCH (call:Statement {kind: 'invoke'})-[:DATA_DEP*1..2]->(c)
WITH g, s, c, cd, collect(DISTINCT call.target_name) AS uses_calls
MERGE (g)-[r:GUARDED_BY_CONDITION]->(c)
SET r.branch = cd.branch, r.code = c.code, r.guards = s.target_name, r.uses_calls = uses_calls,
    r.permission_check = any(x IN uses_calls WHERE x IN
        ['checkSelfPermission', 'checkPermission', 'checkCallingOrSelfPermission', 'shouldShowRequestPermissionRationale'])
RETURN count(r) AS conditions;

// P12b. Permissions needed by APIs the method calls (all, not only dangerous)
MATCH (g:PPG {app_id: $app})-[:FOR_METHOD]->(m)-[:CALLS]->(api:Method)-[:API_REQUIRES_PERMISSION]->(p:Permission)
MERGE (g)-[:REQUIRES_PERMISSION]->(p)
RETURN p.name AS permission, count(DISTINCT g) AS ppgs;

// P12c. Third-party SDKs: the SDK the method belongs to, and SDKs the data reaches
MATCH (g:PPG {app_id: $app})-[:FOR_METHOD]->(:Method)<-[:HAS_METHOD]-(:Class)-[:BELONGS_TO]->(lib:Library)
MERGE (g)-[:IN_SDK]->(lib)
RETURN lib.name AS sdk_code, count(g) AS ppgs;

MATCH (g:PPG {app_id: $app})-[:HAS_FLOW]->(f:PrivacyFlow)-[:TO]->(t:Statement)-[:INVOKES]->(:Method)<-[:HAS_METHOD]-(:Class)-[:BELONGS_TO]->(lib:Library)
MERGE (g)-[:SHARES_WITH]->(lib)
RETURN lib.name AS sdk_receiving_data, count(DISTINCT g) AS ppgs;


// -----------------------------------------------------------------------------
// P13a. Attach every PPG to its app
// -----------------------------------------------------------------------------
MATCH (a:App {app_id: $app}), (g:PPG {app_id: $app})
MERGE (a)-[:HAS_PPG]->(g)
RETURN count(g) AS ppgs;


// -----------------------------------------------------------------------------
// P13. Summary on each PPG (used by classification): why, which data, where it goes
// -----------------------------------------------------------------------------
MATCH (g:PPG {app_id: $app})-[:FOR_METHOD]->(m:Method)
OPTIONAL MATCH (g)-[b:BECAUSE]->()
WITH g, m, collect(DISTINCT b.reason) AS reasons,
     [c IN collect(DISTINCT b.category) WHERE c IS NOT NULL] AS categories,
     [d IN collect(DISTINCT b.data_type) WHERE d IS NOT NULL] AS data_types,
     collect(DISTINCT b.confidence) AS confs
OPTIONAL MATCH (g)-[:HAS_FLOW]->(f:PrivacyFlow)
WITH g, m, reasons, categories, data_types, confs, collect(DISTINCT f.kind) AS sink_kinds
OPTIONAL MATCH (g)-[:REQUIRES_PERMISSION]->(p:Permission)
WITH g, m, reasons, categories, data_types, confs, sink_kinds, collect(DISTINCT p.name) AS permissions
SET g.method = m.class_name + '.' + m.name,
    g.method_signature = m.signature,
    g.class_name = m.class_name,
    g.method_origin = m.origin,
    g.has_body = coalesce(m.has_statements, false),
    g.statement_count = coalesce(m.instruction_count, 0),
    g.reasons = reasons,
    g.categories = categories,
    g.data_types = data_types,
    g.permissions = permissions,
    g.sink_kinds = sink_kinds,
    g.confidence = CASE WHEN 'high' IN confs THEN 'high' ELSE 'review' END
RETURN g.method AS method, g.categories AS categories, g.reasons AS reasons,
       g.sink_kinds AS sinks, g.confidence AS confidence
ORDER BY method;


// -----------------------------------------------------------------------------
// V. Validation: V1, V3 and V4 should be 0
// -----------------------------------------------------------------------------
// V1. Every node a PPG includes belongs to the same app's APG
MATCH (g:PPG {app_id: $app})-[:INCLUDES|FOR_METHOD|REACHES_SINK]->(n)
WHERE NOT n:APG OR n.app_id <> $app
RETURN count(*) AS foreign_nodes;

// V2. Candidate PPGs left out because no entry point reaches them (review these by hand)
MATCH (g:ExcludedPPG {app_id: $app})-[:FOR_METHOD]->(m)
OPTIONAL MATCH (g)-[b:BECAUSE]->()
RETURN m.class_name + '.' + m.name AS method, collect(DISTINCT b.data_type) AS data, g.excluded_reason AS reason;

// V3. Every consecutive pair on every flow's evidence path is joined by a real APG data edge
MATCH (f:PrivacyFlow {app_id: $app})
UNWIND range(0, size(f.path) - 2) AS i
WITH f.path[i] AS a_uid, f.path[i + 1] AS b_uid
WHERE NOT exists {
  MATCH (a:APG {uid: a_uid})-[:DATA_DEP|ARG|RETURN|WRITES_FIELD|READ_BY]->(b:APG {uid: b_uid})
}
RETURN count(*) AS broken_steps;

// V4. Every PPG has at least one reason
MATCH (g:PPG {app_id: $app})
WHERE NOT exists { (g)-[:BECAUSE]->() }
RETURN count(g) AS ppgs_without_reason;


// -----------------------------------------------------------------------------
// E. Export: one record per PPG (for classification, captions and annotation)
// -----------------------------------------------------------------------------
MATCH (a:App {app_id: $app})-[:HAS_PPG]->(g:PPG)-[:FOR_METHOD]->(m:Method)
OPTIONAL MATCH (g)-[b:BECAUSE]->()
WITH a, g, m, collect({reason: b.reason, category: b.category, data_type: b.data_type,
                       detail: b.detail, confidence: b.confidence}) AS reasons
OPTIONAL MATCH (g)-[:HAS_FLOW]->(f:PrivacyFlow)
WITH a, g, m, reasons, collect(CASE WHEN f IS NULL THEN NULL ELSE
       {data_type: f.data_type, sink_kind: f.kind, sink: f.api, sink_method: f.sink_method,
        through_methods: f.through_methods, confidence: f.confidence, evidence: f.evidence} END) AS flows
OPTIONAL MATCH (g)-[c:GUARDED_BY_CONDITION]->()
WITH a, g, m, reasons, flows, collect(CASE WHEN c IS NULL THEN NULL ELSE
       {code: c.code, branch: c.branch, guards: c.guards, uses: c.uses_calls,
        permission_check: c.permission_check} END) AS conditions
OPTIONAL MATCH (g)-[:CALLS_INTO]->(g2:PPG)
OPTIONAL MATCH (g)-[:IN_SDK|SHARES_WITH]->(lib:Library)
RETURN g.ppg_id AS ppg_id, a.package AS package,
       g.method AS method, g.method_signature AS signature, m.parameters AS parameters,
       g.categories AS categories, g.data_types AS data_types, g.reasons AS reason_kinds,
       reasons, g.permissions AS permissions, g.sink_kinds AS sink_kinds, g.confidence AS confidence,
       g.entrypoint AS entrypoint, g.entrypoint_kind AS entrypoint_kind, g.call_chain AS call_chain,
       flows, conditions, collect(DISTINCT g2.method) AS calls_ppgs, collect(DISTINCT lib.name) AS sdks,
       m.source AS java, m.ast_table AS ast_table, m.cfg_table AS cfg_table,
       m.data_flow_table AS data_flow_table, m.method_call_table AS method_call_table
ORDER BY method;
