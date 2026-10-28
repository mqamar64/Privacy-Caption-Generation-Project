"""Integration test on input/APK/sample.apk (F-Droid). Takes ~1 minute.

Run with:  pytest -m slow
"""

from collections import defaultdict
from pathlib import Path

import pytest

from apg.builder import APGBuilder, BuildOptions
from apg.export import read_csv, write_csv

SAMPLE = Path(__file__).resolve().parents[1] / "input" / "APK" / "sample.apk"

pytestmark = [pytest.mark.slow,
              pytest.mark.skipif(not SAMPLE.exists(), reason="sample.apk not present")]


@pytest.fixture(scope="module")
def apg():
    return APGBuilder(SAMPLE, BuildOptions(stmt_scope="app")).build()


def _out(g):
    out = defaultdict(list)
    for rel in ("DATA_DEP", "ARG", "RETURN", "WRITES_FIELD", "READ_BY"):
        for a, b, _ in g.edges[rel]:
            out[a].append(b)
    return out


def test_manifest_and_symbols(apg):
    app = next(iter(apg.nodes["App"].values()))
    assert app["package"] == "org.fdroid.fdroid"
    perms = {p["name"] for p in apg.nodes["Permission"].values() if p.get("requested")}
    assert "android.permission.ACCESS_WIFI_STATE" in perms
    main = [c for c in apg.nodes["Component"].values() if c.get("is_main")]
    assert main and main[0]["name"] == "org.fdroid.fdroid.views.main.MainActivity"
    assert any(l["name"] == "OkHttp" for l in apg.nodes["Library"].values())


def test_every_edge_endpoint_exists(apg):
    uids = {u for nodes in apg.nodes.values() for u in nodes}
    for rel, edges in apg.edges.items():
        for a, b, _ in edges:
            assert a in uids and b in uids, (rel, a, b)


def test_ssid_flows_into_sharing_uri(apg):
    """WifiInfo.getSSID() -> FDroidApp.ssid -> Uri.Builder.appendQueryParameter()."""
    S = apg.nodes["Statement"]
    out = _out(apg)
    src = [u for u, s in S.items() if s.get("target_name") == "getSSID"]
    assert src
    seen, todo = set(src), list(src)
    while todo:
        for nxt in out[todo.pop()]:
            if nxt not in seen:
                seen.add(nxt)
                todo.append(nxt)
    reached = {S[u].get("target_name") for u in seen if u in S}
    assert "appendQueryParameter" in reached


def test_entrypoint_reaches_getssid(apg):
    M = apg.nodes["Method"]
    calls = defaultdict(set)
    for a, b, _ in apg.edges["CALLS"]:
        calls[a].add(b)
    target = next(u for u, m in M.items()
                  if m["class_name"] == "android.net.wifi.WifiInfo" and m["name"] == "getSSID")
    entries = [u for u, m in M.items() if m.get("is_entrypoint")]
    seen, todo = set(entries), list(entries)
    while todo:
        for nxt in calls[todo.pop()]:
            if nxt not in seen:
                seen.add(nxt)
                todo.append(nxt)
    assert target in seen


def test_branch_labels_and_control_dependence(apg):
    """getSSID() only runs when the preceding BSSID null-check is false."""
    S = apg.nodes["Statement"]
    labels = {p.get("branch") for _, _, p in apg.edges["FLOWS_TO"]}
    assert {"true", "false", "goto"} <= labels
    src = next(u for u, s in S.items() if s.get("target_name") == "getSSID")
    ctrl = [(S[a], p["branch"]) for a, b, p in apg.edges["CONTROL_DEP"] if b == src]
    assert ctrl and ctrl[0][0]["opcode"] == "if-eqz" and ctrl[0][1] == "false"


def test_callbacks_and_intents(apg):
    S, M, C = apg.nodes["Statement"], apg.nodes["Method"], apg.nodes["Component"]
    cb = {(S[a]["target_name"], M[b]["class_name"], M[b]["name"])
          for a, b, p in apg.edges["INVOKES"] if p.get("via") == "callback"}
    assert ("start", "org.fdroid.fdroid.nearby.WifiStateChangeService$WifiInfoThread", "run") in cb
    assert all(M[b]["origin"] in ("app", "unknown")
               for _, b, p in apg.edges["INVOKES"] if p.get("via") == "callback")
    explicit = {C[b]["name"] for _, b, p in apg.edges["SENDS_INTENT"] if p["explicit"]}
    assert "org.fdroid.fdroid.views.AppDetailsActivity" in explicit
    on_create = [M[b] for _, b, p in apg.edges["INVOKES"]
                 if p.get("via") == "icc" and M[b]["class_name"].endswith("AppDetailsActivity")]
    assert any(m["name"] == "onCreate" for m in on_create)


def test_interprocedural_control_flow(apg):
    S = apg.nodes["Statement"]
    calls = [(a, b) for a, b, _ in apg.edges["CALL_FLOW"]]
    assert calls
    a, b = calls[0]
    assert S[a]["kind"] == "invoke" and S[b]["idx"] == 0


def test_csv_round_trip(apg, tmp_path):
    write_csv(apg, tmp_path)
    g2 = read_csv(tmp_path)
    assert g2.app_id == apg.app_id
    assert g2.counts() == apg.counts()
    def present(props):
        # empty lists are stored as missing, as in Neo4j
        return {k: v for k, v in props.items() if v is not None and v != []}

    for label in ("Method", "Statement", "Component"):
        for uid, props in list(apg.nodes[label].items())[:500]:
            assert present(g2.nodes[label][uid]) == present(props)
    no_arg = next(m for m in g2.nodes["Method"].values() if m["param_count"] == 0)
    assert no_arg["param_types"] == ""


def test_each_method_carries_its_own_apg_tables(apg):
    """One method = one APG: parameters, AST, control flow, data flow and calls as properties."""
    import json
    m = next(v for v in apg.nodes["Method"].values()
             if v["class_name"].endswith("WifiStateChangeService") and v["name"] == "setSsid")
    assert m["parameters"] == ["0:this:org.fdroid.fdroid.nearby.WifiStateChangeService",
                               "1:p1:android.net.wifi.WifiInfo"]
    ast = json.loads(m["ast_table"])
    assert len(ast) == m["instruction_count"]
    calls = json.loads(m["method_call_table"])
    assert any("getSSID" in c["callee"] for c in calls)
    dft = json.loads(m["data_flow_table"])
    assert {"from": "param1", "to": 12, "var": "v8"} in dft   # the WifiInfo parameter is used
    assert json.loads(m["cfg_table"])


def test_constant_arguments_are_properties(apg):
    """setSsid strips quotes with ssid.replaceAll("^\"(.*)\"$", "$1")."""
    S = apg.nodes["Statement"]
    calls = [s for s in S.values() if s.get("target_name") == "replaceAll"
             and s["method_signature"].endswith("WifiStateChangeService;->setSsid(Landroid/net/wifi/WifiInfo;)V")]
    assert calls and calls[0]["const_args"] == ['1=^"(.*)"$', "2=$1"]
