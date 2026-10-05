"""Implicit calls Android makes on the app's behalf (VulHunter's MCG challenge 2).

Two kinds of edges are added from a call site to methods the framework will run later:

* **Callbacks** - the app hands an object to framework/SDK code that will call it back:
  ``view.setOnClickListener(l)`` -> ``l.onClick``, ``lm.requestLocationUpdates(.., l)`` ->
  ``l.onLocationChanged``, ``executor.execute(r)`` -> ``r.run``, ``thread.start()`` -> ``run``.
  The object's concrete class comes from the reaching definitions (``new-instance``),
  and the callbacks are its methods that override a method of the parameter's type.
* **Inter-component communication (ICC)** - ``startActivity(intent)`` and friends, where the
  Intent names its target with ``X.class``, a class-name string, or an action string that
  matches a manifest intent filter. The call site gets ``SENDS_INTENT`` to the Component
  and ``INVOKES`` to the target's lifecycle methods.

Both are resolved within the calling method only; objects or Intents built in another
method are not followed.
"""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

from .graph import METHOD

if TYPE_CHECKING:
    from .builder import APGBuilder

# Parameter types that carry plain data, not callbacks.
_NOT_CALLBACK_TYPES = {
    "Ljava/lang/Object;", "Ljava/lang/String;", "Ljava/lang/CharSequence;",
    "Ljava/lang/Number;", "Ljava/lang/Integer;", "Ljava/lang/Long;",
}

# Calls whose *receiver* is the callback object: (class, method) -> methods run later.
RECEIVER_STARTERS = {
    ("Ljava/lang/Thread;", "start"): {"run"},
    ("Landroid/os/AsyncTask;", "execute"): {"onPreExecute", "doInBackground", "onProgressUpdate", "onPostExecute"},
    ("Landroid/os/AsyncTask;", "executeOnExecutor"): {"onPreExecute", "doInBackground", "onProgressUpdate", "onPostExecute"},
}

ICC_SENDERS = {
    "startActivity": "activity", "startActivityForResult": "activity",
    "startActivityIfNeeded": "activity",
    "startService": "service", "startForegroundService": "service", "bindService": "service",
    "sendBroadcast": "receiver", "sendOrderedBroadcast": "receiver",
    "sendStickyBroadcast": "receiver", "sendBroadcastAsUser": "receiver",
}

LIFECYCLE = {
    "activity": {"onCreate", "onStart", "onResume", "onNewIntent", "onActivityResult"},
    "service": {"onCreate", "onStartCommand", "onBind", "onHandleIntent", "onHandleWork"},
    "receiver": {"onReceive"},
}

_INTENT_CLASSES = {"Landroid/content/Intent;", "Landroid/content/ComponentName;"}
_MAX_DEPTH = 8


def link(b: "APGBuilder") -> None:
    g = b.g
    calls: dict[tuple[str, str, str], int] = defaultdict(int)
    n_cb = n_icc = 0
    comps = _components(b)

    for reg in b.registrations:
        caller, call_suid, tcls, tname, op, args, pdescs = reg
        static = op.startswith("invoke-static")
        use_defs = b.use_defs.get(call_suid, {})

        # --- callbacks
        for idx, r in args:
            if idx == 0 and not static:
                names = RECEIVER_STARTERS.get((tcls, tname))
                if not names:
                    continue
                ptype = tcls
            else:
                names = None
                ptype = pdescs[idx - (0 if static else 1)]
            if not ptype.startswith("L") or ptype in _NOT_CALLBACK_TYPES:
                continue
            defs = use_defs.get(r, ())
            for cls in {t for d in defs for t in _concrete_types(b, d, 0)}:
                info = b.class_info.get(cls)
                # Only the app's own (or unrecognised) classes: SDK internals are not app behaviour.
                if cls == ptype or info is None or info["external"] or info["origin"] not in ("app", "unknown"):
                    continue
                for cb in _callback_methods(b, cls, ptype, names):
                    g.add_edge("INVOKES", call_suid, cb, via="callback")
                    calls[(caller, cb, "callback")] += 1
                    n_cb += 1
                    this_param = next((p for i, _, p in b.params.get(cb, []) if i == 0), None)
                    if this_param:
                        for d in defs:
                            g.add_edge("ARG", d, this_param, index=0, call_site=call_suid, via="callback")

        # --- inter-component communication
        kind = ICC_SENDERS.get(tname)
        if kind is None:
            continue
        for idx, r in args:
            if idx == 0 and not static:
                continue
            if pdescs[idx - (0 if static else 1)] != "Landroid/content/Intent;":
                continue
            classes, strings = _intent_targets(b, use_defs.get(r, ()))
            targets: dict[str, bool] = {}  # component name -> explicit?
            for name in classes | {s for s in strings if s in comps}:
                if name in comps:
                    targets[name] = True
            for s in strings:
                for name, (_, ctype, _, actions) in comps.items():
                    if s in actions and ctype == kind:
                        targets.setdefault(name, False)
            for name, explicit in targets.items():
                comp_uid, ctype, impl_cls, _ = comps[name]
                g.add_edge("SENDS_INTENT", call_suid, comp_uid, explicit=explicit, api=tname)
                n_icc += 1
                for cb in _named_methods(b, impl_cls, LIFECYCLE.get(ctype, set())):
                    g.add_edge("INVOKES", call_suid, cb, via="icc")
                    calls[(caller, cb, "icc")] += 1

    for (src, dst, via), n in calls.items():
        g.add_edge("CALLS", src, dst, count=n, via=via)
    b.stats["callback_edges"] = n_cb
    b.stats["icc_edges"] = n_icc


def _components(b: "APGBuilder") -> dict[str, tuple[str, str, str, set[str]]]:
    """component name -> (uid, type, dalvik class implementing it, intent actions)."""
    out = {}
    nodes = b.g.nodes.get("Component", {})
    for comp_uid, target in b.pending_impl:
        node = nodes[comp_uid]
        out[node["name"]] = (comp_uid, node["type"], "L" + target.replace(".", "/") + ";",
                             set(node.get("intent_actions") or []))
    return out


def _concrete_types(b: "APGBuilder", d: str, depth: int) -> set[str]:
    """Classes a definition's value can be an instance of, when the method shows it."""
    meta = b.stmt_meta.get(d)
    if meta is None or depth > _MAX_DEPTH:
        return set()
    op, regs, type_ref, _, _ = meta
    if op == "new-instance":
        return {type_ref} if type_ref else set()
    if op.startswith("invoke") or op == "check-cast":
        src = regs[0] if regs else None          # receiver redefined by the call / cast
    elif op.startswith("move-object"):
        src = regs[1] if len(regs) > 1 else None
    else:
        return set()
    out: set[str] = set()
    for e in b.use_defs.get(d, {}).get(src, ()):
        out |= _concrete_types(b, e, depth + 1)
    return out


def _overrides_type(b: "APGBuilder", muid: str, ptype_java: str, depth: int = 0) -> bool:
    for t in b.overrides.get(muid, ()):
        node = b.g.nodes[METHOD][t]
        if node["class_name"] == ptype_java or (depth < 5 and _overrides_type(b, t, ptype_java, depth + 1)):
            return True
    return False


def _class_chain(b: "APGBuilder", cls: str):
    """The class and its superclasses, stopping where app (or unrecognised) code ends."""
    seen = set()
    while (cls and cls not in seen and cls in b.class_info and not b.class_info[cls]["external"]
           and b.class_info[cls]["origin"] in ("app", "unknown")):
        seen.add(cls)
        yield cls
        cls = b.class_info[cls]["super"]


def _callback_methods(b: "APGBuilder", cls: str, ptype: str, names: set[str] | None) -> list[str]:
    from .dalvik import descriptor_to_java
    ptype_java = descriptor_to_java(ptype)
    found: dict[str, str] = {}
    for c in _class_chain(b, cls):
        for key in b.class_methods.get(c, ()):
            if key in found:
                continue  # overridden lower in the chain
            sig = f"{c}->{key}"
            if sig not in b.methods:
                continue
            muid = b.method_ids[sig]
            if names is not None:
                if key.split("(", 1)[0] in names:
                    found[key] = muid
            elif _overrides_type(b, muid, ptype_java):
                found[key] = muid
    return list(found.values())


def _named_methods(b: "APGBuilder", cls: str, names: set[str]) -> list[str]:
    found: dict[str, str] = {}
    for c in _class_chain(b, cls):
        for key in b.class_methods.get(c, ()):
            sig = f"{c}->{key}"
            if key.split("(", 1)[0] in names and key not in found and sig in b.methods:
                found[key] = b.method_ids[sig]
    return list(found.values())


def _intent_targets(b: "APGBuilder", defs) -> tuple[set[str], set[str]]:
    """Walk back from an Intent value: X.class constants and string constants used to build it."""
    from .dalvik import descriptor_to_java
    classes: set[str] = set()
    strings: set[str] = set()
    todo = [(d, 0) for d in defs]
    seen = set()
    while todo:
        d, depth = todo.pop()
        if d in seen or depth > _MAX_DEPTH:
            continue
        seen.add(d)
        meta = b.stmt_meta.get(d)
        if meta is None:
            continue
        op, regs, type_ref, target_cls, literal = meta
        if op == "const-class" and type_ref:
            classes.add(descriptor_to_java(type_ref))
        elif op.startswith("const-string") and literal:
            strings.add(literal)
        elif op.startswith("invoke") and target_cls in _INTENT_CLASSES:
            for es in b.use_defs.get(d, {}).values():
                todo.extend((e, depth + 1) for e in es)
        elif op.startswith("move-object") or op == "check-cast":
            for es in b.use_defs.get(d, {}).values():
                todo.extend((e, depth + 1) for e in es)
    return classes, strings
