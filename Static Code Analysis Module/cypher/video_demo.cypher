// =============================================================================
// Video demo: filtering method APGs into PPGs, live in Neo4j Browser
// A PPG is the method that itself makes a sensitive call.
// The app ID (org.fdroid.fdroid@1021051-b6465184) is written into the queries, so no
// :param is needed. Copy each PASTE block (from its '// ===' line to the next one),
// paste it into the Browser's query box and press Ctrl+Enter, in order.
// The queries are the same as cypher/ppg_build.cypher, grouped into steps.
// =============================================================================


// =============================================================================
// PASTE 1 - Clean start: remove PPGs from an earlier run
// =============================================================================
CREATE CONSTRAINT ppg_id IF NOT EXISTS FOR (g:PPG) REQUIRE g.ppg_id IS UNIQUE;

CREATE INDEX ppg_app IF NOT EXISTS FOR (g:PPG) ON (g.app_id);

CREATE INDEX excluded_ppg_app IF NOT EXISTS FOR (g:ExcludedPPG) ON (g.app_id);

CREATE INDEX flow_app IF NOT EXISTS FOR (f:PrivacyFlow) ON (f.app_id);

MATCH (g:PPG|ExcludedPPG {app_id: 'org.fdroid.fdroid@1021051-b6465184'}) DETACH DELETE g;

MATCH (f:PrivacyFlow {app_id: 'org.fdroid.fdroid@1021051-b6465184'}) DETACH DELETE f;

MATCH (n:APG {app_id: 'org.fdroid.fdroid@1021051-b6465184'}) WHERE n:SourcePoint OR n:SinkPoint OR n:SourceAPI OR n:SinkAPI
REMOVE n:SourcePoint, n:SinkPoint, n:SourceAPI, n:SinkAPI,
       n.source_category, n.data_type, n.sink_kind, n.sink_args, n.sink_detail;

MATCH (g:PPG) RETURN count(g) AS ppgs_right_now;


// =============================================================================
// PASTE 2 - Find where the app reads personal data (sources)
// =============================================================================
UNWIND [
  {c:'android.location.LocationManager', m:'getLastKnownLocation', cat:'LOCATION_INFORMATION', d:'device location'},
  {c:'android.location.Location', m:'getLatitude', cat:'LOCATION_INFORMATION', d:'latitude'},
  {c:'android.location.Location', m:'getLongitude', cat:'LOCATION_INFORMATION', d:'longitude'},
  {c:'android.location.Location', m:'getAltitude', cat:'LOCATION_INFORMATION', d:'altitude'},
  {c:'com.google.android.gms.location.FusedLocationProviderClient', m:'getLastLocation', cat:'LOCATION_INFORMATION', d:'device location'},
  {c:'com.google.android.gms.location.FusedLocationProviderClient', m:'getCurrentLocation', cat:'LOCATION_INFORMATION', d:'device location'},
  {c:'android.net.wifi.WifiManager', m:'getScanResults', cat:'LOCATION_INFORMATION', d:'nearby Wi-Fi networks'},
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
  {c:'android.net.wifi.WifiInfo', m:'getSSID', cat:'NETWORK_INFORMATION', d:'Wi-Fi network name'},
  {c:'android.net.wifi.WifiInfo', m:'getBSSID', cat:'NETWORK_INFORMATION', d:'Wi-Fi access point ID'},
  {c:'android.net.wifi.WifiInfo', m:'getIpAddress', cat:'NETWORK_INFORMATION', d:'IP address'},
  {c:'android.net.wifi.WifiManager', m:'getDhcpInfo', cat:'NETWORK_INFORMATION', d:'IP/DHCP information'},
  {c:'android.bluetooth.BluetoothAdapter', m:'getName', cat:'BLUETOOTH_INFORMATION', d:'device Bluetooth name'},
  {c:'android.bluetooth.BluetoothAdapter', m:'getBondedDevices', cat:'BLUETOOTH_INFORMATION', d:'paired Bluetooth devices'},
  {c:'android.bluetooth.BluetoothDevice', m:'getAddress', cat:'BLUETOOTH_INFORMATION', d:'nearby device address'},
  {c:'android.bluetooth.BluetoothDevice', m:'getName', cat:'BLUETOOTH_INFORMATION', d:'nearby device name'},
  {c:'android.accounts.AccountManager', m:'getAccounts', cat:'ACCOUNT_INFORMATION', d:'accounts on device'},
  {c:'android.accounts.AccountManager', m:'getAccountsByType', cat:'ACCOUNT_INFORMATION', d:'accounts on device'},
  {c:'com.google.android.gms.auth.api.signin.GoogleSignInAccount', m:'getEmail', cat:'EMAIL', d:'email address'},
  {c:'com.google.android.gms.auth.api.signin.GoogleSignInAccount', m:'getDisplayName', cat:'ACCOUNT_INFORMATION', d:'account name'},
  {c:'android.telephony.SmsMessage', m:'getMessageBody', cat:'SMS_MMS', d:'SMS text'},
  {c:'android.telephony.SmsMessage', m:'getDisplayMessageBody', cat:'SMS_MMS', d:'SMS text'},
  {c:'android.telephony.SmsMessage', m:'getOriginatingAddress', cat:'SMS_MMS', d:'SMS sender number'},
  {c:'android.content.ClipboardManager', m:'getPrimaryClip', cat:'CLIPBOARD', d:'clipboard contents'},
  {c:'android.content.ClipboardManager', m:'getText', cat:'CLIPBOARD', d:'clipboard contents'},
  {c:'android.content.pm.PackageManager', m:'getInstalledPackages', cat:'INSTALLED_APPS', d:'installed apps'},
  {c:'android.content.pm.PackageManager', m:'getInstalledApplications', cat:'INSTALLED_APPS', d:'installed apps'}
] AS s
MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184', class_name: s.c, name: s.m})
SET m:SourceAPI, m.source_category = s.cat, m.data_type = s.d
RETURN s.cat AS category, s.c + '.' + s.m AS api, count(m) AS overloads_in_apg
ORDER BY category, api;

MATCH (s:Statement {app_id: 'org.fdroid.fdroid@1021051-b6465184', kind: 'invoke'})-[:INVOKES]->(api:SourceAPI)
SET s:SourcePoint, s.source_category = api.source_category, s.data_type = api.data_type
RETURN s.source_category AS category, api.class_name + '.' + api.name AS api, count(s) AS call_sites
ORDER BY category, api;

MATCH (s:Statement {app_id: 'org.fdroid.fdroid@1021051-b6465184', kind: 'invoke', target_class: 'android.provider.Settings$Secure', target_name: 'getString'})
MATCH (k:Statement {kind: 'const_string', literal: 'android_id'})-[:DATA_DEP]->(s)
SET s:SourcePoint, s.source_category = 'UNIQUE_IDENTIFIER', s.data_type = 'Android ID'
RETURN count(DISTINCT s) AS android_id_reads;

UNWIND [
  {p:'android.provider.ContactsContract', cat:'CONTACT_INFORMATION', d:'contacts'},
  {p:'android.provider.CallLog', cat:'CONTACT_INFORMATION', d:'call log'},
  {p:'android.provider.CalendarContract', cat:'CALENDAR_INFORMATION', d:'calendar events'},
  {p:'android.provider.Telephony', cat:'SMS_MMS', d:'SMS/MMS messages'},
  {p:'android.provider.MediaStore', cat:'IMAGE', d:'photos and media'},
  {p:'android.provider.Browser', cat:'BROWSER_INFORMATION', d:'browser history'}
] AS prov
MATCH (q:Statement {app_id: 'org.fdroid.fdroid@1021051-b6465184', kind: 'invoke', target_class: 'android.content.ContentResolver', target_name: 'query'})
MATCH (f:Field)-[:READ_BY]->(uri:Statement)-[:DATA_DEP*1..3]->(q)
WHERE f.class_name STARTS WITH prov.p
SET q:SourcePoint, q.source_category = prov.cat, q.data_type = prov.d
RETURN prov.d AS provider, count(DISTINCT q) AS queries;

MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184'})-[:OVERRIDES]->(api:Method)
WHERE (api.class_name = 'android.location.LocationListener' AND api.name = 'onLocationChanged')
   OR (api.class_name = 'com.google.android.gms.location.LocationCallback' AND api.name = 'onLocationResult')
MATCH (m)-[:HAS_PARAM]->(p:Parameter {index: 1})
SET p:SourcePoint, p.source_category = 'LOCATION_INFORMATION', p.data_type = 'device location'
RETURN count(p) AS location_callbacks;


// =============================================================================
// PASTE 3 - Show the methods that read personal data
// =============================================================================
MATCH (m:Method)-[r:HAS_STATEMENT|HAS_PARAM]->(s:SourcePoint)
RETURN m, r, s;


// =============================================================================
// PASTE 4 - Find where data can end up (sinks: logs, files, network, screen, SDKs)
// =============================================================================
UNWIND [
  {c:'android.util.Log', m:['d','e','i','v','w','wtf'], k:'log', a:[1,2], det:'Android log'},
  {c:'android.util.Log', m:['println'], k:'log', a:[2], det:'Android log'},
  {c:'java.io.PrintStream', m:['println','print'], k:'log', a:[1], det:'standard output'},
  {c:'java.net.URL', m:['<init>'], k:'url', a:[1,2,3], det:'URL'},
  {c:'android.net.Uri', m:['parse'], k:'url', a:[0], det:'URI'},
  {c:'android.net.Uri$Builder', m:['appendQueryParameter'], k:'url', a:[1,2], det:'URI query'},
  {c:'android.net.Uri$Builder', m:['appendPath','path','query','encodedQuery','encodedPath','authority'], k:'url', a:[1], det:'URI'},
  {c:'java.net.HttpURLConnection', m:['setRequestProperty','addRequestProperty'], k:'network', a:[1,2], det:'HTTP header'},
  {c:'java.net.URLConnection', m:['setRequestProperty','addRequestProperty'], k:'network', a:[1,2], det:'HTTP header'},
  {c:'android.webkit.WebView', m:['loadUrl','postUrl','evaluateJavascript'], k:'network', a:[1,2], det:'WebView'},
  {c:'android.telephony.SmsManager', m:['sendTextMessage','sendMultipartTextMessage'], k:'sms', a:[1,3], det:'SMS'},
  {c:'java.io.OutputStream', m:['write'], k:'stream', a:[1], det:'output stream'},
  {c:'java.io.Writer', m:['write','append'], k:'stream', a:[1], det:'writer'},
  {c:'java.io.PrintWriter', m:['write','print','println','append'], k:'stream', a:[1], det:'writer'},
  {c:'java.io.DataOutputStream', m:['write','writeUTF','writeBytes','writeInt','writeLong'], k:'stream', a:[1], det:'output stream'},
  {c:'android.content.SharedPreferences$Editor', m:['putString','putInt','putLong','putFloat','putBoolean','putStringSet'], k:'storage_preferences', a:[2], det:'SharedPreferences'},
  {c:'android.database.sqlite.SQLiteDatabase', m:['insert','insertOrThrow','insertWithOnConflict','replace','update','execSQL'], k:'storage_database', a:[1,2,3], det:'SQLite'},
  {c:'android.content.ContentValues', m:['put'], k:'storage_database', a:[2], det:'database values'},
  {c:'android.content.ContentResolver', m:['insert','update','bulkInsert'], k:'storage_database', a:[2], det:'content provider'},
  {c:'android.content.Intent', m:['putExtra','putExtras','setData','setDataAndType'], k:'ipc', a:[1,2], det:'Intent'},
  {c:'android.content.ClipboardManager', m:['setPrimaryClip','setText'], k:'clipboard', a:[1], det:'clipboard'},
  {c:'android.content.ClipData', m:['newPlainText','newRawUri','newUri'], k:'clipboard', a:[1,2], det:'clipboard'},
  {c:'android.widget.TextView', m:['setText','append','setHint'], k:'ui_display', a:[1], det:'text on screen'},
  {c:'android.widget.Toast', m:['makeText'], k:'ui_display', a:[1], det:'toast message'},
  {c:'android.app.AlertDialog$Builder', m:['setMessage','setTitle'], k:'ui_display', a:[1], det:'dialog'}
] AS spec
UNWIND spec.m AS name
MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184', class_name: spec.c, name: name})
SET m:SinkAPI, m.sink_kind = spec.k, m.sink_args = spec.a, m.sink_detail = spec.det
RETURN spec.k AS kind, spec.c AS class, collect(DISTINCT name) AS methods, count(m) AS in_apg
ORDER BY kind, class;

MATCH (t:Statement {app_id: 'org.fdroid.fdroid@1021051-b6465184', kind: 'invoke'})-[:INVOKES]->(api:SinkAPI)
SET t:SinkPoint, t.sink_kind = api.sink_kind, t.sink_args = api.sink_args, t.sink_detail = api.sink_detail
RETURN t.sink_kind AS kind, count(t) AS call_sites ORDER BY kind;

MATCH (t:Statement {app_id: 'org.fdroid.fdroid@1021051-b6465184', kind: 'invoke'})-[:INVOKES]->(api:Method {origin: 'library'})
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

MATCH (t:SinkPoint {app_id: 'org.fdroid.fdroid@1021051-b6465184', sink_kind: 'stream'})
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


// =============================================================================
// PASTE 5 - Show how many sinks of each kind were found
// =============================================================================
MATCH (t:SinkPoint)
RETURN t.sink_kind AS kind_of_sink, count(*) AS places_in_code
ORDER BY places_in_code DESC;


// =============================================================================
// PASTE 6 - Filter the method APGs: keep each method that makes a sensitive call and can run
// =============================================================================
MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184', is_external: false})-[c:CALLS]->(api:SourceAPI)
MERGE (g:PPG {ppg_id: 'org.fdroid.fdroid@1021051-b6465184' + '|PPG|' + m.signature})
SET g.app_id = 'org.fdroid.fdroid@1021051-b6465184'
MERGE (g)-[:FOR_METHOD]->(m)
MERGE (g)-[b:BECAUSE {reason: 'calls_sensitive_api'}]->(api)
SET b.category = api.source_category, b.data_type = api.data_type,
    b.detail = api.java_signature, b.call_sites = c.count, b.confidence = 'high'
RETURN api.source_category AS category, api.data_type AS data, count(DISTINCT m) AS methods
ORDER BY category, data;

MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184'})-[:HAS_STATEMENT]->(s:SourcePoint)
WHERE NOT exists { (s)-[:INVOKES]->(:SourceAPI) }
MERGE (g:PPG {ppg_id: 'org.fdroid.fdroid@1021051-b6465184' + '|PPG|' + m.signature})
SET g.app_id = 'org.fdroid.fdroid@1021051-b6465184'
MERGE (g)-[:FOR_METHOD]->(m)
MERGE (g)-[b:BECAUSE {reason: 'calls_sensitive_api'}]->(s)
SET b.category = s.source_category, b.data_type = s.data_type,
    b.detail = s.target_java_signature, b.confidence = 'high'
RETURN s.data_type AS data, count(DISTINCT m) AS methods;

MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184'})-[:HAS_PARAM]->(p:Parameter:SourcePoint)
MERGE (g:PPG {ppg_id: 'org.fdroid.fdroid@1021051-b6465184' + '|PPG|' + m.signature})
SET g.app_id = 'org.fdroid.fdroid@1021051-b6465184'
MERGE (g)-[:FOR_METHOD]->(m)
MERGE (g)-[b:BECAUSE {reason: 'receives_personal_data'}]->(p)
SET b.category = p.source_category, b.data_type = p.data_type,
    b.detail = 'parameter ' + toString(p.index) + ' of ' + m.name, b.confidence = 'high'
RETURN count(DISTINCT m) AS methods;

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
MATCH (perm:Permission {app_id: 'org.fdroid.fdroid@1021051-b6465184', name: d.p})<-[:API_REQUIRES_PERMISSION]-(api:Method)
MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184', is_external: false})-[:CALLS]->(api)
WITH m, perm, d, collect(DISTINCT api.java_signature) AS apis
MERGE (g:PPG {ppg_id: 'org.fdroid.fdroid@1021051-b6465184' + '|PPG|' + m.signature})
SET g.app_id = 'org.fdroid.fdroid@1021051-b6465184'
MERGE (g)-[:FOR_METHOD]->(m)
MERGE (g)-[b:BECAUSE {reason: 'requires_dangerous_permission'}]->(perm)
SET b.category = d.cat, b.data_type = perm.name, b.detail = apis, b.confidence = 'high'
RETURN perm.name AS permission, count(DISTINCT m) AS methods;

MATCH (g:PPG {app_id: 'org.fdroid.fdroid@1021051-b6465184'})-[:FOR_METHOD]->(m)
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


// =============================================================================
// PASTE 7 - Show the PPGs, each attached to its method APG
// =============================================================================
MATCH (g:PPG)-[r:FOR_METHOD]->(m:Method)
RETURN g, r, m;


// =============================================================================
// PASTE 8 - Follow each PPG's personal data to where it goes
// =============================================================================
MATCH (g:PPG {app_id: 'org.fdroid.fdroid@1021051-b6465184'})-[:FOR_METHOD]->(m)-[:HAS_STATEMENT|HAS_PARAM]->(src:SourcePoint)
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
SET f.app_id = 'org.fdroid.fdroid@1021051-b6465184',
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

MATCH (f:PrivacyFlow {app_id: 'org.fdroid.fdroid@1021051-b6465184'})
UNWIND range(0, size(f.path) - 1) AS i
MATCH (n:APG {uid: f.path[i]})<-[:HAS_STATEMENT|HAS_PARAM]-(m:Method)
WITH f, i, m.class_name + '.' + m.name AS method ORDER BY i
WITH f, collect(method) AS steps
SET f.through_methods = reduce(acc = [], x IN steps | CASE WHEN x IN acc THEN acc ELSE acc + [x] END)
RETURN f.data_type AS data, f.kind AS sink_kind, f.through_methods AS passes_through;

MATCH (g:PPG {app_id: 'org.fdroid.fdroid@1021051-b6465184'})-[:FOR_METHOD]->(:Method)-[:HAS_STATEMENT|HAS_PARAM]->(src)<-[:FROM]-(f:PrivacyFlow)-[:TO]->(t)
MATCH (t)<-[:HAS_STATEMENT]-(tm:Method)
SET f.sink_method = tm.class_name + '.' + tm.name
MERGE (g)-[:HAS_FLOW]->(f)
MERGE (g)-[r:REACHES_SINK {flow: f.flow_id}]->(t)
SET r.kind = f.kind, r.detail = f.detail, r.api = f.api, r.data_type = f.data_type,
    r.sink_method = f.sink_method, r.through_methods = f.through_methods,
    r.confidence = f.confidence, r.evidence = f.evidence, r.path = f.path, r.hops = f.hops
RETURN f.kind AS sink_kind, count(r) AS sinks;

MATCH (g:PPG {app_id: 'org.fdroid.fdroid@1021051-b6465184'})-[:FOR_METHOD]->(m)-[:HAS_STATEMENT|HAS_PARAM]->(n)
MERGE (g)-[:INCLUDES]->(n)
RETURN count(DISTINCT g) AS ppgs, count(n) AS nodes_included;

MATCH (g1:PPG {app_id: 'org.fdroid.fdroid@1021051-b6465184'})-[:FOR_METHOD]->(m1)-[c:CALLS]->(m2)<-[:FOR_METHOD]-(g2:PPG)
WHERE g1 <> g2
MERGE (g1)-[r:CALLS_INTO]->(g2)
SET r.via = c.via, r.count = c.count
RETURN count(r) AS calls_between_ppgs;


// =============================================================================
// PASTE 9 - Show each PPG connected to the places its data ends up
// =============================================================================
MATCH (g:PPG)-[r:REACHES_SINK]->(t)
RETURN g, r, t;


// =============================================================================
// PASTE 10 - Add conditions, permissions, SDKs and a summary on each PPG
// =============================================================================
MATCH (g:PPG {app_id: 'org.fdroid.fdroid@1021051-b6465184'})-[:FOR_METHOD]->(m)-[:HAS_STATEMENT]->(s:Statement)
WHERE s:SourcePoint OR exists { (s)-[:INVOKES]->(:Method)-[:API_REQUIRES_PERMISSION]->(:Permission) }
MATCH (c:Statement)-[cd:CONTROL_DEP]->(s)
OPTIONAL MATCH (call:Statement {kind: 'invoke'})-[:DATA_DEP*1..2]->(c)
WITH g, s, c, cd, collect(DISTINCT call.target_name) AS uses_calls
MERGE (g)-[r:GUARDED_BY_CONDITION]->(c)
SET r.branch = cd.branch, r.code = c.code, r.guards = s.target_name, r.uses_calls = uses_calls,
    r.permission_check = any(x IN uses_calls WHERE x IN
        ['checkSelfPermission', 'checkPermission', 'checkCallingOrSelfPermission', 'shouldShowRequestPermissionRationale'])
RETURN count(r) AS conditions;

MATCH (g:PPG {app_id: 'org.fdroid.fdroid@1021051-b6465184'})-[:FOR_METHOD]->(m)-[:CALLS]->(api:Method)-[:API_REQUIRES_PERMISSION]->(p:Permission)
MERGE (g)-[:REQUIRES_PERMISSION]->(p)
RETURN p.name AS permission, count(DISTINCT g) AS ppgs;

MATCH (g:PPG {app_id: 'org.fdroid.fdroid@1021051-b6465184'})-[:FOR_METHOD]->(:Method)<-[:HAS_METHOD]-(:Class)-[:BELONGS_TO]->(lib:Library)
MERGE (g)-[:IN_SDK]->(lib)
RETURN lib.name AS sdk_code, count(g) AS ppgs;

MATCH (g:PPG {app_id: 'org.fdroid.fdroid@1021051-b6465184'})-[:HAS_FLOW]->(f:PrivacyFlow)-[:TO]->(t:Statement)-[:INVOKES]->(:Method)<-[:HAS_METHOD]-(:Class)-[:BELONGS_TO]->(lib:Library)
MERGE (g)-[:SHARES_WITH]->(lib)
RETURN lib.name AS sdk_receiving_data, count(DISTINCT g) AS ppgs;

MATCH (a:App {app_id: 'org.fdroid.fdroid@1021051-b6465184'}), (g:PPG {app_id: 'org.fdroid.fdroid@1021051-b6465184'})
MERGE (a)-[:HAS_PPG]->(g)
RETURN count(g) AS ppgs;

MATCH (g:PPG {app_id: 'org.fdroid.fdroid@1021051-b6465184'})-[:FOR_METHOD]->(m:Method)
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
    g.confidence = 'high'
RETURN g.method AS method, g.categories AS categories, g.reasons AS reasons,
       g.sink_kinds AS sinks, g.confidence AS confidence
ORDER BY method;


// =============================================================================
// PASTE 11 - Table of every PPG and why it is one
// =============================================================================
MATCH (g:PPG)
RETURN g.method AS method, g.data_types AS data, g.categories AS data_categories,
       g.reasons AS why_it_is_a_ppg, g.sink_kinds AS data_goes_to
ORDER BY method;


// =============================================================================
// PASTE 12 - Checks: all three should be 0
// =============================================================================
MATCH (g:PPG {app_id: 'org.fdroid.fdroid@1021051-b6465184'})
WITH count(CASE WHEN NOT exists { (g)-[:BECAUSE]->() } THEN 1 END) AS ppgs_without_reason
OPTIONAL MATCH (g2:PPG {app_id: 'org.fdroid.fdroid@1021051-b6465184'})-[:INCLUDES]->(n) WHERE n.app_id <> 'org.fdroid.fdroid@1021051-b6465184'
WITH ppgs_without_reason, count(n) AS foreign_nodes
OPTIONAL MATCH (f:PrivacyFlow {app_id: 'org.fdroid.fdroid@1021051-b6465184'})
WITH ppgs_without_reason, foreign_nodes, f
UNWIND CASE WHEN f IS NULL THEN [null] ELSE range(0, size(f.path) - 2) END AS i
WITH ppgs_without_reason, foreign_nodes, f.path[i] AS a_uid, f.path[i + 1] AS b_uid
RETURN ppgs_without_reason, foreign_nodes,
       count(CASE WHEN a_uid IS NOT NULL AND NOT exists {
         MATCH (a:APG {uid: a_uid})-[:DATA_DEP|ARG|RETURN|WRITES_FIELD|READ_BY]->(b:APG {uid: b_uid}) } THEN 1 END) AS broken_evidence_steps;


// =============================================================================
// PASTE 13 - Close-up: one PPG (setSsid) with its reasons, sinks, trigger and conditions
// =============================================================================
MATCH (g:PPG {method: 'org.fdroid.fdroid.nearby.WifiStateChangeService.setSsid'})
MATCH (g)-[r:FOR_METHOD|BECAUSE|REACHES_SINK|TRIGGERED_BY|GUARDED_BY_CONDITION|REQUIRES_PERMISSION|CALLS_INTO]->(n)
RETURN g, r, n;


// =============================================================================
// PASTE 14 - Close-up: everything inside that PPG's method APG (statements, control flow, data flow)
// =============================================================================
MATCH (g:PPG {method: 'org.fdroid.fdroid.nearby.WifiStateChangeService.setSsid'})-[:INCLUDES]->(n)
WITH collect(n) AS nodes
UNWIND nodes AS a
MATCH (a)-[r:FLOWS_TO|DATA_DEP]->(b)
WHERE b IN nodes
RETURN a, r, b;


// =============================================================================
// PASTE 15 - One query for one PPG: is setSsid's APG a PPG, and why? (with its tables and Java)
// =============================================================================
MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184'})
WHERE m.class_name + '.' + m.name = 'org.fdroid.fdroid.nearby.WifiStateChangeService.setSsid' AND m.is_external = false

OPTIONAL MATCH (m)-[c:CALLS]->(api:SourceAPI)
WITH m, [x IN collect(DISTINCT {reason: 'calls_sensitive_api', category: api.source_category,
                                data_type: api.data_type, detail: api.java_signature})
         WHERE x.category IS NOT NULL] AS r1

OPTIONAL MATCH (m)-[:HAS_STATEMENT]->(s:SourcePoint)
WHERE NOT exists { (s)-[:INVOKES]->(:SourceAPI) }
WITH m, r1, [x IN collect(DISTINCT {reason: 'calls_sensitive_api', category: s.source_category,
                                    data_type: s.data_type, detail: s.target_java_signature})
             WHERE x.category IS NOT NULL] AS r1b

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

OPTIONAL MATCH (m)-[:HAS_PARAM]->(p:Parameter:SourcePoint)
WITH m, r1, r1b, r2, [x IN collect(DISTINCT {reason: 'receives_personal_data', category: p.source_category,
                                             data_type: p.data_type, detail: 'callback parameter'})
                      WHERE x.category IS NOT NULL] AS r3a
WITH m, r1 + r1b + r2 + r3a AS reasons

OPTIONAL MATCH (m)-[:HAS_STATEMENT|HAS_PARAM]->(src)<-[:FROM]-(f:PrivacyFlow)
WITH m, reasons, [x IN collect(DISTINCT {data_type: f.data_type, sink_kind: f.kind, sink: f.api,
                                         sink_method: f.sink_method, through_methods: f.through_methods,
                                         confidence: f.confidence, evidence: f.evidence})
                  WHERE x.sink_kind IS NOT NULL] AS flows

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
