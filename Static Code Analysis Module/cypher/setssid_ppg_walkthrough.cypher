// =============================================================================
// Walkthrough: filtering all of F-Droid's method APGs down to one PPG (setSsid)
//
// Each step narrows the previous one. Paste one step at a time into Neo4j Browser
// (Ctrl+Enter). Steps 1-4 are tables; step 5 is a graph.
// =============================================================================


// -----------------------------------------------------------------------------
// STEP 1. Start: every method APG in the app (one APG per method)
// -----------------------------------------------------------------------------
MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184', has_statements: true})
RETURN count(m) AS method_apgs;


// -----------------------------------------------------------------------------
// STEP 2. Mark the Android APIs that return personal data (the source list)
//   Labels each one :SourceAPI with its category and data type.
// -----------------------------------------------------------------------------
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
SET m:SourceAPI, m.source_category = s.cat, m.data_type = s.d, m.source_list = 'curated'
RETURN s.cat AS category, s.c + '.' + s.m AS api, count(m) AS overloads_in_apg
ORDER BY category, api;


// -----------------------------------------------------------------------------
// STEP 3. Filter 1: keep the method APGs with a statement that calls one of them
// -----------------------------------------------------------------------------
MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184', is_external: false})-[:HAS_STATEMENT]->(s:Statement)-[:INVOKES]->(api:SourceAPI)
WHERE api.source_list = 'curated'
RETURN m.class_name + '.' + m.name AS method, collect(DISTINCT api.data_type) AS personal_data
ORDER BY method;


// -----------------------------------------------------------------------------
// STEP 4. Filter 2: keep only those the app can actually run (an entry point such
//   as a screen or service reaches them through the call graph). These are the PPGs.
// -----------------------------------------------------------------------------
MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184', is_external: false})-[:HAS_STATEMENT]->(s:Statement)-[:INVOKES]->(api:SourceAPI)
WHERE api.source_list = 'curated'
WITH m, collect(DISTINCT api.data_type) AS personal_data
CALL (m) {
  MATCH (m)-[:OVERRIDES*0..2]->(target:Method)
  WHERE target = m OR target.origin IN ['app', 'unknown']
  MATCH p = SHORTEST 1 (e:Method WHERE e.is_entrypoint = true OR e.name = '<clinit>')-[:CALLS]->{0,12}(target)
  RETURN e.class_name + '.' + e.name AS triggered_by, length(p) AS hops
  ORDER BY hops LIMIT 1
}
RETURN m.class_name + '.' + m.name AS ppg, personal_data, triggered_by
ORDER BY ppg;


// -----------------------------------------------------------------------------
// STEP 5. [graph] Zoom in on one PPG: setSsid. Its sensitive calls, the APIs they
//   call, where the data goes inside the method, and the ifs that decide it.
// -----------------------------------------------------------------------------
MATCH (m:Method {app_id: 'org.fdroid.fdroid@1021051-b6465184', class_name: 'org.fdroid.fdroid.nearby.WifiStateChangeService', name: 'setSsid'})
MATCH (m)-[:HAS_STATEMENT]->(src:Statement)-[call:INVOKES]->(api:SourceAPI)
WHERE api.source_list = 'curated'
OPTIONAL MATCH flow = (src)-[:DATA_DEP*1..6]->(use:Statement)<-[:HAS_STATEMENT]-(m)
OPTIONAL MATCH (cond:Statement)-[cd:CONTROL_DEP]->(src)
RETURN m, src, call, api, flow, cond, cd;
