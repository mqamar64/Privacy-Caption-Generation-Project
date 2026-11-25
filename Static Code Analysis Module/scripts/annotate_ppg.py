import sys
import os
import re
import csv
import json
import html

levelOrder=["identifier","sensitive_attribute","quasi_identifier","other","unknown"]
levelNames={"identifier":"PII identifier","quasi_identifier":"Quasi-identifier",
            "sensitive_attribute":"Sensitive attribute","other":"Other","unknown":"Unclassified"}
permCalls=["checkSelfPermission","checkPermission","checkCallingPermission","checkCallingOrSelfPermission",
           "enforcePermission","enforceCallingPermission","requestPermissions"]

def loadMap(path):
    with open(path,encoding="utf-8") as f:
        return json.load(f)

def classify(dataType,category,sensMap):
    if dataType in sensMap["data_types"]:
        return sensMap["data_types"][dataType]
    if category in sensMap["categories"]:
        return sensMap["categories"][category]
    return {"level":"unknown","play":"?","apple":"?"}

def loadManifest(apgDir):
    requested=[]
    app={}
    permFile=os.path.join(apgDir,"nodes_Permission.csv")
    appFile=os.path.join(apgDir,"nodes_App.csv")
    if os.path.exists(permFile):
        with open(permFile,encoding="utf-8",newline="") as f:
            for row in csv.DictReader(f):
                if row["requested:boolean"].lower()=="true":
                    requested.append(row["name"])
    if os.path.exists(appFile):
        with open(appFile,encoding="utf-8",newline="") as f:
            for row in csv.DictReader(f):
                app=row
    return requested,app

def apiName(signature):
    match=re.search(r"<[\w.$]+:\s*[\w.$\[\]]+\s+([\w$<>]+)\(",str(signature))
    if match:
        return match.group(1)
    return None

def describe(method):
    parts=method.split(".")
    name=parts[-1]
    if name=="run":
        name=parts[-2].split("$")[-1]
    words=re.sub(r"([a-z0-9])([A-Z])",r"\1 \2",name).split()
    text=" ".join(words).lower()
    return text[0].upper()+text[1:]

def findAssigned(line):
    match=re.match(r"^\s*(?:[\w.$<>\[\]]+\s+)?([A-Za-z_][\w$]*)\s*=(?!=)\s*(.*)$",line)
    if match and match.group(1)!="return":
        return match.group(1),match.group(2)
    return None,None

def findVariables(lines,apis):
    returnVars=[]
    for line in lines:
        for api in apis:
            if re.search(r"\b"+api+r"\s*\(",line):
                var,rest=findAssigned(line)
                if var and var not in returnVars:
                    returnVars.append(var)
    flowVars=[]
    for i in range(2):
        tainted=returnVars+flowVars
        for line in lines:
            var,rest=findAssigned(line)
            if var is None or var in tainted:
                continue
            for t in tainted:
                if re.search(r"\b"+re.escape(t)+r"\b",rest) and var not in flowVars:
                    flowVars.append(var)
    return returnVars,flowVars

def colorLine(line,apis,returnVars,flowVars,isFirst):
    tokens=re.findall(r'"(?:\\.|[^"\\])*"|[A-Za-z_$][\w$]*|\s+|.',line)
    out=""
    blueDone=not isFirst
    for i in range(len(tokens)):
        t=tokens[i]
        nxt=""
        for x in tokens[i+1:]:
            if not x.isspace():
                nxt=x
                break
        prev=""
        for x in reversed(tokens[:i]):
            if not x.isspace():
                prev=x
                break
        safe=html.escape(t)
        if t.startswith('"') and "android.permission." in t:
            out+='<span class="perm">'+safe+'</span>'
        elif not blueDone and nxt=="(" and re.match(r"[A-Za-z_$]",t):
            out+='<span class="blue">'+safe+'</span>'
            blueDone=True
        elif t in apis and nxt=="(" and prev==".":
            out+='<span class="red">'+safe+'</span>'
        elif t in permCalls and nxt=="(":
            out+='<span class="perm">'+safe+'</span>'
        elif t in returnVars:
            out+='<span class="orange">'+safe+'</span>'
        elif t in flowVars:
            out+='<span class="green">'+safe+'</span>'
        else:
            out+=safe
    return out

def colorCode(java,apis):
    lines=java.split("\n")
    returnVars,flowVars=findVariables(lines,apis)
    first=0
    for i in range(len(lines)):
        if "(" in lines[i]:
            first=i
            break
    colored=[]
    for i in range(len(lines)):
        colored.append(colorLine(lines[i], apis, returnVars, flowVars, i==first))
    return "\n".join(colored),returnVars,flowVars

def readPpgs(ppgDir):
    methodPpgs=[]
    flowPpgs=[]
    for name in sorted(os.listdir(ppgDir)):
        if not (name.startswith("ppg_") and name.endswith(".json")):
            continue
        with open(os.path.join(ppgDir,name),encoding="utf-8") as f:
            ppg=json.load(f)
        ppg["file"]=name
        if "reasons" in ppg:
            methodPpgs.append(ppg)
        else:
            flowPpgs.append(ppg)
    return methodPpgs,flowPpgs

def findSinks(ppg,flowPpgs):
    sinks=[]
    seen=[]
    for flow in ppg.get("flows") or []:
        sink={"data_type":flow.get("data_type"),"kind":flow.get("kind") or flow.get("sink_kind"),"sink":flow.get("sink")}
        if sink not in seen:
            seen.append(sink)
            sinks.append(sink)
    for other in flowPpgs:
        if other.get("method")!=ppg.get("method"):
            continue
        for s in other.get("sinks") or []:
            sink={"data_type":other.get("data_type"),"kind":s.get("kind"),"sink":s.get("api")}
            if sink not in seen:
                seen.append(sink)
                sinks.append(sink)
    return sinks

def labelPpg(ppg,flowPpgs,requested,sensMap):
    apis=[]
    data=[]
    seen=[]
    for reason in ppg["reasons"]:
        details=reason["detail"]
        if not isinstance(details,list):
            details=[details]
        for d in details:
            name=apiName(d)
            if name and name not in apis:
                apis.append(name)
        key=(reason.get("data_type"),reason.get("category"))
        if key in seen:
            continue
        seen.append(key)
        c=classify(reason.get("data_type"), reason.get("category"), sensMap)
        data.append({"data_type":reason.get("data_type"),"category":reason.get("category"),"api":reason.get("detail"),
                     "level":c["level"],"play":c["play"],"apple":c["apple"]})
    perms=[]
    for p in ppg.get("permissions") or []:
        perms.append({"name":p,"declared_in_manifest":p in requested})
    highest="unknown"
    for d in data:
        if levelOrder.index(d["level"])<levelOrder.index(highest):
            highest=d["level"]
    code,returnVars,flowVars=colorCode(ppg.get("java") or "", apis)
    return {"file":ppg["file"],"ppg_id":ppg.get("ppg_id"),"method":ppg.get("method"),
            "description":describe(ppg.get("method","")),"highest_level":highest,"data":data,
            "permissions":perms,"conditions":ppg.get("conditions") or [],"sinks":findSinks(ppg, flowPpgs),
            "entrypoint_kind":ppg.get("entrypoint_kind"),"call_chain":ppg.get("call_chain") or [],
            "return_vars":returnVars,"flow_vars":flowVars,"code":code}

def writeCsv(path,labels):
    with open(path,"w",encoding="utf-8",newline="") as f:
        w=csv.writer(f)
        w.writerow(["ppg_file","method","description","data_type","susi_category","level",
                    "google_play_category","apple_category","permissions","sink_kinds"])
        for l in labels:
            perms=[]
            for p in l["permissions"]:
                perms.append(p["name"])
            kinds=[]
            for s in l["sinks"]:
                if str(s["kind"]) not in kinds:
                    kinds.append(str(s["kind"]))
            for d in l["data"]:
                w.writerow([l["file"],l["method"],l["description"],d["data_type"],d["category"],d["level"],
                            d["play"],d["apple"],"; ".join(perms),"; ".join(kinds)])

def writeJson(path,appId,labels):
    clean=[]
    for l in labels:
        item={}
        for k in l:
            if k!="code":
                item[k]=l[k]
        clean.append(item)
    with open(path,"w",encoding="utf-8") as f:
        json.dump({"app_id":appId,"ppgs":clean},f,indent=2)

def appBox(appId,app,requested,labels):
    counts={}
    for l in labels:
        for d in l["data"]:
            counts[d["level"]]=counts.get(d["level"],0)+1
    out='<div class="app"><h2>'+html.escape(app.get("app_name",appId))+'</h2>'
    out+='<div class="muted"><code>'+html.escape(app.get("package",appId))+'</code>'
    if app:
        out+=' · version '+html.escape(app.get("version_name",""))+' · target SDK '+html.escape(app.get("target_sdk",""))
    out+='</div><div style="margin-top:6px">'+str(len(labels))+' PPGs'
    for level in levelOrder:
        if level in counts:
            out+=' · <span class="badge '+level+'">'+levelNames[level]+'</span>'+str(counts[level])
    if requested:
        out+='<br><span class="muted">Manifest requests '+str(len(requested))+' permissions</span>'
    return out+'</div></div>'

def card(l):
    e=html.escape
    out='<section class="card"><div class="mname">'+e(l["method"] or "")+'</div>'
    out+='<div class="desc">'+e(l["description"])+'</div>'
    out+='<table><tr><th>Data</th><th>Level</th><th>Google Play</th><th>Apple</th><th>Sensitive API</th></tr>'
    for d in l["data"]:
        out+='<tr><td>'+e(str(d["data_type"]))+'</td><td><span class="badge '+d["level"]+'">'+levelNames[d["level"]]+'</span></td>'
        out+='<td>'+e(d["play"])+'</td><td>'+e(d["apple"])+'</td><td><code>'+e(str(d["api"]))+'</code></td></tr>'
    out+='</table><div><b>Permissions:</b> '
    if not l["permissions"]:
        out+='<span class="muted">none needed</span>'
    for p in l["permissions"]:
        out+='<code>'+e(p["name"].replace("android.permission.",""))+'</code> '
        if p["declared_in_manifest"]:
            out+='<span class="ok">✓ in manifest</span> '
        else:
            out+='<span class="bad">✗ not in manifest</span> '
    out+='</div><div style="margin-top:6px"><b>Where the data goes:</b> '
    if not l["sinks"]:
        out+='<span class="muted">no sink found (used locally)</span></div>'
    else:
        out+='<ul>'
        for s in l["sinks"]:
            out+='<li>'+e(str(s["data_type"]))+' → <b>'+e(str(s["kind"]))+'</b> <code>'+e(str(s["sink"] or ""))+'</code></li>'
        out+='</ul></div>'
    if l["conditions"]:
        out+='<details><summary>Conditions ('+str(len(l["conditions"]))+')</summary><ul>'
        for c in l["conditions"]:
            out+='<li><code>'+e(c.get("code",""))+'</code> decides <code>'+e(str(c.get("guards")))+'</code> (branch '+e(str(c.get("branch")))+')</li>'
        out+='</ul></details>'
    if l["call_chain"]:
        chain=[]
        for c in l["call_chain"]:
            chain.append(e(c.split(".")[-1]))
        out+='<details><summary>How the app gets here ('+e(str(l["entrypoint_kind"]))+')</summary><p><code>'+" → ".join(chain)+'</code></p></details>'
    out+='<pre>'+l["code"]+'</pre><div class="muted" style="font-size:12px">'+e(l["file"])+'</div></section>'
    return out

def writeHtml(path,appId,app,requested,labels,cssPath):
    with open(cssPath,encoding="utf-8") as f:
        css=f.read()
    legend='<div class="legend">'
    legend+='<span><i class="sw" style="border:3px solid var(--black)"></i>Black: the app (APK)</span>'
    legend+='<span><i class="sw" style="background:var(--red)"></i>Red: sensitive API call</span>'
    legend+='<span><i class="sw" style="background:var(--orange)"></i>Orange: its return value</span>'
    legend+='<span><i class="sw" style="border:2px dashed var(--orange)"></i>Orange dashed: permission check</span>'
    legend+='<span><i class="sw" style="background:var(--blue)"></i>Blue: method name + description</span>'
    legend+='<span><i class="sw" style="background:var(--green)"></i>Green: variables the data flows into</span></div>'
    ordered=sorted(labels,key=lambda l:(levelOrder.index(l["highest_level"]),l["method"] or ""))
    cards=""
    for l in ordered:
        cards+=card(l)
    page='<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
    page+='<title>Annotated PPGs</title><style>'+css+'</style></head><body><main>'
    page+='<h1>Annotated Privacy Property Graphs</h1><div class="muted">Code segments marked up per the 11/18 meeting notes. '
    page+='Levels and label categories come from config/sensitivity_map.json.</div>'
    page+=appBox(appId, app, requested, labels)+legend+cards+'</main></body></html>'
    with open(path,"w",encoding="utf-8") as f:
        f.write(page)

def main():
    ppgDir=sys.argv[1].rstrip("/")
    appId=os.path.basename(ppgDir)
    moduleDir=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    apgDir=os.path.join(os.path.dirname(os.path.dirname(ppgDir)),"apg",appId)
    outDir=os.path.join(moduleDir,"output","annotated",appId)
    os.makedirs(outDir,exist_ok=True)

    sensMap=loadMap(os.path.join(moduleDir,"config","sensitivity_map.json"))
    requested,app=loadManifest(apgDir)
    methodPpgs,flowPpgs=readPpgs(ppgDir)

    labels=[]
    for ppg in methodPpgs:
        labels.append(labelPpg(ppg, flowPpgs, requested, sensMap))

    writeJson(os.path.join(outDir,"ppg_labels.json"), appId, labels)
    writeCsv(os.path.join(outDir,"ppg_labels.csv"), labels)
    writeHtml(os.path.join(outDir,"index.html"), appId, app, requested, labels, os.path.join(moduleDir,"config","annotate.css"))
    print("Annotated",len(labels),"PPGs, saved to",outDir)

if __name__ == "__main__":
    main()
