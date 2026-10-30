// =============================================================================
// Find the PPGs by querying every method's APG.
//
// A method's APG is a PPG when the method itself calls an Android API that returns
// personal data (the source list below, same as P2 in ppg_build.cypher) and the app
// can actually run it (an entry point reaches it). Needs only the APG in Neo4j.
// The app ID is written in, so paste each query straight into Neo4j Browser.
//
//   Query 1 only looks (nothing is written).
//   Query 2 does the same search and saves each PPG as a PPG node.
//   Query 3 shows the saved PPGs.
// =============================================================================


// -----------------------------------------------------------------------------
// Query 1. [table] Search every method APG for PPGs (read-only)
// -----------------------------------------------------------------------------
WITH 'org.fdroid.fdroid@1021051-b6465184' AS app
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
] AS src
MATCH (m:Method {app_id: app, is_external: false})-[:HAS_STATEMENT]->(s:Statement)-[:INVOKES]->(api:Method {class_name: src.c, name: src.m})
WITH app, m, collect(DISTINCT src.cat) AS categories, collect(DISTINCT src.d) AS personal_data,
     collect(DISTINCT {stmt: s, cat: src.cat, d: src.d, api: src.c + '.' + src.m}) AS calls
CALL (m) {
  MATCH (m)-[:OVERRIDES*0..2]->(target:Method)
  WHERE target = m OR target.origin IN ['app', 'unknown']
  MATCH p = SHORTEST 1 (e:Method WHERE e.is_entrypoint = true OR e.name = '<clinit>')-[:CALLS]->{0,12}(target)
  RETURN e.class_name + '.' + e.name AS triggered_by, [n IN nodes(p) | n.class_name + '.' + n.name] AS call_chain, length(p) AS hops
  ORDER BY hops LIMIT 1
}
RETURN m.class_name + '.' + m.name AS ppg_method, personal_data, categories,
       [c IN calls | c.api + ' at offset ' + toString(c.stmt.offset)] AS sensitive_calls,
       triggered_by, call_chain
ORDER BY ppg_method;


// -----------------------------------------------------------------------------
// Query 2. Same search, and save each PPG: a PPG node joined to its method's APG
// (FOR_METHOD) and to each sensitive call that makes it one (BECAUSE)
// -----------------------------------------------------------------------------
WITH 'org.fdroid.fdroid@1021051-b6465184' AS app
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
] AS src
MATCH (m:Method {app_id: app, is_external: false})-[:HAS_STATEMENT]->(s:Statement)-[:INVOKES]->(api:Method {class_name: src.c, name: src.m})
WITH app, m, collect(DISTINCT src.cat) AS categories, collect(DISTINCT src.d) AS personal_data,
     collect(DISTINCT {stmt: s, cat: src.cat, d: src.d, api: src.c + '.' + src.m}) AS calls
CALL (m) {
  MATCH (m)-[:OVERRIDES*0..2]->(target:Method)
  WHERE target = m OR target.origin IN ['app', 'unknown']
  MATCH p = SHORTEST 1 (e:Method WHERE e.is_entrypoint = true OR e.name = '<clinit>')-[:CALLS]->{0,12}(target)
  RETURN e.class_name + '.' + e.name AS triggered_by, [n IN nodes(p) | n.class_name + '.' + n.name] AS call_chain, length(p) AS hops
  ORDER BY hops LIMIT 1
}
MERGE (g:PPG {ppg_id: app + '|PPG|' + m.signature})
SET g.app_id = app, g.method = m.class_name + '.' + m.name, g.categories = categories,
    g.data_types = personal_data, g.entrypoint = triggered_by, g.call_chain = call_chain
MERGE (g)-[:FOR_METHOD]->(m)
WITH g, calls
UNWIND calls AS c
WITH g, c, c.stmt AS s
MERGE (g)-[b:BECAUSE {reason: 'calls_sensitive_api', detail: c.api}]->(s)
SET b.category = c.cat, b.data_type = c.d
RETURN g.method AS ppg, g.data_types AS personal_data, count(b) AS sensitive_calls
ORDER BY ppg;


// -----------------------------------------------------------------------------
// Query 3. [graph] The PPGs: each PPG, its method, and the calls that make it one
// -----------------------------------------------------------------------------
MATCH (g:PPG {app_id: 'org.fdroid.fdroid@1021051-b6465184'})-[r:FOR_METHOD|BECAUSE]->(n)
RETURN g, r, n;
