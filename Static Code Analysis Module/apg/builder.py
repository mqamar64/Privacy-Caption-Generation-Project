"""Build an App Property Graph (APG) from an APK with Androguard.

Layers follow VulHunter's APG (AST, MCG, ICFG, SDG) plus the manifest; see
graph.EDGE_TYPES for every relationship and the layer it belongs to:
  * Manifest  - App, Permission, Component nodes
  * AST       - Class, Method, Field, Parameter, Statement nodes and their containment
  * MCG       - CALLS / INVOKES / OVERRIDES, including callbacks and Intents (callbacks.py)
  * ICFG      - ENTRY / FLOWS_TO (with branch labels) / CALL_FLOW / RETURN_FLOW
  * SDG       - DATA_DEP (reaching definitions), CONTROL_DEP (controldep.py),
                ARG / RETURN (inter-procedural), WRITES_FIELD / READ_BY (fields)

Statement-level layers are only built for classes inside ``stmt_scope`` because
library code can be 20x larger than the app itself; the call graph always covers
every class so SDK behaviour (e.g. an analytics SDK reading location) stays visible.
"""

from __future__ import annotations

import hashlib
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from . import callbacks, dalvik
from .controldep import control_dependence
from .graph import (APG, APP, CLASS, COMPONENT, FIELD, LIBRARY, METHOD, PARAMETER,
                    PERMISSION, STATEMENT)
from .libraries import OriginClassifier

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

STMT_SCOPES = {
    "app": {"app"},
    "nonlib": {"app", "unknown"},
    "all": {"app", "unknown", "library"},
    "none": set(),
}

# Framework callbacks that do not follow the onXxx naming convention.
CALLBACK_NAMES = {
    "run", "call", "handleMessage", "doInBackground", "onPostExecute", "onPreExecute",
    "query", "insert", "update", "delete", "getType", "bulkInsert", "openFile",
    "shouldOverrideUrlLoading", "invoke", "accept", "apply", "test", "compare",
    "uncaughtException", "getView", "getItem", "getCount", "getItemCount",
}
_CALLBACK_RE = re.compile(r"^on[A-Z]")

# java.* types whose overriders are invoked asynchronously by the runtime. Other java.*
# overrides (equals, hashCode, InputStream.read ...) are not treated as entrypoints.
FRAMEWORK_CALLBACK_CLASSES = {
    "java.lang.Runnable", "java.lang.Thread", "java.util.concurrent.Callable",
    "java.util.TimerTask", "java.lang.Thread$UncaughtExceptionHandler",
}

COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")

# Highest API level shipped with androguard's API -> permission mapping.
PERMISSION_MAPPING_API = 25


@dataclass
class BuildOptions:
    stmt_scope: str = "nonlib"
    include_exception_edges: bool = True
    include_api_permission_mapping: bool = True
    with_source: bool = True    # decompiled Java per method (for PRCS / captions)


def class_dots(dalvik_name: str) -> str:
    return dalvik.descriptor_to_java(dalvik_name)


def method_sig(cls: str, name: str, descriptor: str) -> str:
    """Canonical smali signature with no spaces: ``Lpkg/C;->m(I)V``."""
    return f"{cls}->{name}{descriptor.replace(' ', '')}"


def java_method_info(cls: str, name: str, descriptor: str) -> dict[str, Any]:
    """Properties in the Document Analysis Module's format (dotted, comma-joined)."""
    params, ret = dalvik.split_method_descriptor(descriptor)
    jparams = [dalvik.descriptor_to_java(p) for p in params]
    jcls = class_dots(cls)
    jret = dalvik.descriptor_to_java(ret)
    return {
        "class_name": jcls,
        "return_type": jret,
        "param_types": ",".join(jparams),
        "param_count": len(params),
        "java_signature": f"<{jcls}: {jret} {name}({','.join(jparams)})>",
    }


class APGBuilder:
    def __init__(self, apk_path: str | Path, options: BuildOptions | None = None,
                 analysis: tuple | None = None):
        """``analysis`` may be a pre-computed ``(a, d, dx)`` from ``AnalyzeAPK``."""
        self.apk_path = Path(apk_path)
        self.opts = options or BuildOptions()
        if self.opts.stmt_scope not in STMT_SCOPES:
            raise ValueError(f"stmt_scope must be one of {sorted(STMT_SCOPES)}")
        self._analysis = analysis
        self.stats: dict[str, Any] = {}
        self.component_classes: dict[str, str] = {}   # dotted class -> component type
        self.pending_impl: list[tuple[str, str]] = []   # (component uid, class name)
        self._call_args: dict[str, tuple[str, list]] = {}  # call stmt -> (callee, args)
        # Per-statement facts kept for callbacks.py (only for the opcodes it walks).
        self.stmt_meta: dict[str, tuple] = {}     # stmt -> (op, regs, type_ref, target_class, literal)
        self.use_defs: dict[str, dict] = {}       # stmt -> {register: reaching definitions}
        self.registrations: list[tuple] = []      # calls into code without statements
        self.overrides: dict[str, list[str]] = defaultdict(list)

    # ------------------------------------------------------------------ public
    def build(self) -> APG:
        t0 = time.time()
        if self._analysis is None:
            from androguard.misc import AnalyzeAPK
            self._analysis = AnalyzeAPK(str(self.apk_path))
        self.a, self.d, self.dx = self._analysis
        self.stats["androguard_seconds"] = round(time.time() - t0, 1)

        sha = hashlib.sha256(self.apk_path.read_bytes()).hexdigest()
        self.app_id = f"{self.a.get_package()}@{self.a.get_androidversion_code() or 0}-{sha[:8]}"
        self.g = APG(self.app_id)
        self._u = lambda kind, key: f"{self.app_id}|{kind}|{key}"

        t1 = time.time()
        self._add_app(sha)
        self._add_manifest()
        self.origins = OriginClassifier(self._app_prefixes())
        self._add_classes()
        self._add_methods_and_fields()
        self._add_bodies()
        self._link_returns()
        self._add_overrides_and_entrypoints()
        callbacks.link(self)
        if self.opts.include_api_permission_mapping:
            self._add_api_permissions()
        self.stats["apg_seconds"] = round(time.time() - t1, 1)
        self.stats.update(self.g.counts())
        return self.g

    # ---------------------------------------------------------------- manifest
    def _add_app(self, sha: str) -> None:
        a = self.a
        try:
            app_name = a.get_app_name()
        except Exception:  # resource parsing can fail on unusual APKs
            app_name = None
        self.g.add_node(
            APP, self.app_id,
            package=a.get_package(),
            app_name=app_name,
            version_name=a.get_androidversion_name(),
            version_code=str(a.get_androidversion_code() or ""),
            min_sdk=str(a.get_min_sdk_version() or ""),
            target_sdk=str(a.get_target_sdk_version() or ""),
            main_activity=a.get_main_activity(),
            sha256=sha,
            file_name=self.apk_path.name,
            stmt_scope=self.opts.stmt_scope,
        )

    def _perm_node(self, name: str, **props: Any) -> str:
        return self.g.add_node(PERMISSION, self._u("Perm", name), name=name, **props)

    def _add_manifest(self) -> None:
        a = self.a
        details = {}
        try:
            details = a.get_details_permissions()
        except Exception:
            pass
        for perm in sorted(set(a.get_permissions())):
            prot, label, desc = (details.get(perm) or [None, None, None])[:3]
            uid = self._perm_node(perm, protection_level=prot, label=label, description=desc,
                                  requested=True, is_aosp=perm.startswith("android.permission."))
            self.g.add_edge("USES_PERMISSION", self.app_id, uid)

        manifest = a.get_android_manifest_xml()
        pkg = a.get_package()
        for el in manifest.iter("permission"):
            name = el.get(ANDROID_NS + "name")
            if name:
                uid = self._perm_node(name, protection_level=el.get(ANDROID_NS + "protectionLevel"),
                                      declared=True)
                self.g.add_edge("DECLARES_PERMISSION", self.app_id, uid)

        main_acts = set(a.get_main_activities() or [])
        app_el = manifest.find("application")
        if app_el is None:
            return
        for el in app_el:
            tag = el.tag if isinstance(el.tag, str) else ""
            if tag not in COMPONENT_TAGS:
                continue
            name = self._resolve_name(el.get(ANDROID_NS + "name"), pkg)
            if not name:
                continue
            ctype = "activity" if tag == "activity-alias" else tag
            actions, categories, schemes = [], [], []
            for f in el.iter("intent-filter"):
                actions += [x.get(ANDROID_NS + "name") for x in f.iter("action")]
                categories += [x.get(ANDROID_NS + "name") for x in f.iter("category")]
                schemes += [x.get(ANDROID_NS + "scheme") for x in f.iter("data")]
            exported_attr = el.get(ANDROID_NS + "exported")
            exported = (exported_attr.lower() == "true") if exported_attr is not None else bool(actions)
            uid = self.g.add_node(
                COMPONENT, self._u("Comp", name),
                name=name, type=ctype, is_alias=tag == "activity-alias",
                exported=exported, exported_explicit=exported_attr is not None,
                permission=el.get(ANDROID_NS + "permission"),
                authorities=el.get(ANDROID_NS + "authorities"),
                intent_actions=sorted({x for x in actions if x}),
                intent_categories=sorted({x for x in categories if x}),
                data_schemes=sorted({x for x in schemes if x}),
                is_main=name in main_acts,
            )
            self.g.add_edge("HAS_COMPONENT", self.app_id, uid)
            target = name
            if tag == "activity-alias":
                target = self._resolve_name(el.get(ANDROID_NS + "targetActivity"), pkg) or name
            self.component_classes.setdefault(target, ctype)
            self.pending_impl.append((uid, target))
            for attr in ("permission", "readPermission", "writePermission"):
                p = el.get(ANDROID_NS + attr)
                if p:
                    self.g.add_edge("GUARDED_BY", uid, self._perm_node(p), access=attr)

    @staticmethod
    def _resolve_name(name: str | None, pkg: str) -> str | None:
        if not name:
            return None
        if name.startswith("."):
            return pkg + name
        if "." not in name:
            return f"{pkg}.{name}"
        return name

    def _app_prefixes(self) -> list[str]:
        """Package name plus the packages of manifest components that are not SDK classes."""
        from .libraries import match_library
        prefixes = {self.a.get_package()}
        for cls in self.component_classes:
            if match_library(cls) is None and "." in cls:
                prefixes.add(cls.rsplit(".", 1)[0])
        return sorted(prefixes)

    # ----------------------------------------------------------------- classes
    def _add_classes(self) -> None:
        self.class_info: dict[str, dict[str, Any]] = {}  # dalvik name -> info
        for ca in self.dx.get_classes():
            self._ensure_class(ca.name, ca)
        for uid_comp, target in self.pending_impl:
            dname = "L" + target.replace(".", "/") + ";"
            if dname in self.class_info:
                self.g.add_edge("IMPLEMENTED_BY", uid_comp, self._u("C", dname))

    def _ensure_class(self, dname: str, ca=None) -> str:
        uid = self._u("C", dname)
        if dname in self.class_info:
            return uid
        if ca is None:
            ca = self.dx.get_class_analysis(dname)
        external = ca is None or ca.is_external()
        jname = class_dots(dname)
        origin, lib, lib_cat = self.origins.classify(jname, external)
        superclass, interfaces, flags = None, [], ""
        if not external:
            vm = ca.get_vm_class()
            superclass = vm.get_superclassname()
            interfaces = list(vm.get_interfaces() or [])
            flags = vm.get_access_flags_string()
        self.class_info[dname] = {"super": superclass, "interfaces": interfaces,
                                  "external": external, "origin": origin}
        self.g.add_node(
            CLASS, uid, name=jname, dalvik_name=dname, is_external=external,
            superclass=class_dots(superclass) if superclass else None,
            interfaces=[class_dots(i) for i in interfaces],
            access_flags=flags, is_interface="interface" in flags,
            is_abstract="abstract" in flags, origin=origin,
            library=lib, library_category=lib_cat,
            component_type=self.component_classes.get(jname),
        )
        self.g.add_edge("HAS_CLASS", self.app_id, uid)
        if lib:
            luid = self._u("L", lib)
            if not self.g.has_node(LIBRARY, luid):
                self.g.add_node(LIBRARY, luid, name=lib, category=lib_cat)
                self.g.add_edge("USES_LIBRARY", self.app_id, luid)
            self.g.add_edge("BELONGS_TO", uid, luid)
        if not external:
            if superclass:
                self.g.add_edge("EXTENDS", uid, self._ensure_class(superclass))
            for itf in interfaces:
                self.g.add_edge("IMPLEMENTS", uid, self._ensure_class(itf))
        return uid

    # --------------------------------------------------------- methods/fields
    def _add_methods_and_fields(self) -> None:
        self.methods: dict[str, Any] = {}       # sig -> MethodAnalysis (internal)
        self.method_ids: dict[str, str] = {}    # sig -> uid (all, incl. external)
        self.class_methods: dict[str, set[str]] = defaultdict(set)  # dalvik cls -> {name+desc}
        for ma in self.dx.get_methods():
            m = ma.get_method()
            cls, name, desc = m.get_class_name(), m.get_name(), m.get_descriptor()
            sig = method_sig(cls, name, desc)
            self._method_node(sig, ma)
        # Declared fields of internal classes
        self.field_ids: dict[str, str] = {}
        for ca in self.dx.get_classes():
            if ca.is_external():
                continue
            for f in ca.get_vm_class().get_fields():
                self._field_node(f.get_class_name(), f.get_name(), f.get_descriptor(),
                                 external=False, flags=f.get_access_flags_string())

    def _method_node(self, sig: str, ma=None, external_stub: bool = False) -> str:
        if sig in self.method_ids:
            return self.method_ids[sig]
        cls, name, desc = dalvik.parse_method_ref(sig)
        cuid = self._ensure_class(cls)
        external = external_stub or ma is None or ma.is_external()
        flags = "" if external else ma.get_method().get_access_flags_string()
        info = java_method_info(cls, name, desc)
        uid = self._u("M", sig)
        self.g.add_node(
            METHOD, uid, name=name, signature=sig, descriptor=desc.replace(" ", ""),
            **info, access_flags=flags, is_external=external,
            is_android_api=bool(ma.is_android_api()) if ma is not None else None,
            is_static="static" in flags, is_abstract="abstract" in flags,
            is_native="native" in flags, is_constructor=name in ("<init>", "<clinit>"),
            origin=self.class_info[cls]["origin"], is_entrypoint=False,
        )
        self.g.add_edge("HAS_METHOD", cuid, uid)
        self.method_ids[sig] = uid
        self.class_methods[cls].add(name + desc.replace(" ", ""))
        if not external:
            self.methods[sig] = ma
        return uid

    def _field_node(self, cls: str, name: str, ftype: str, external: bool, flags: str = "") -> str:
        key = f"{cls}->{name}:{ftype}"
        if key in self.field_ids:
            return self.field_ids[key]
        cuid = self._ensure_class(cls)
        uid = self.g.add_node(
            FIELD, self._u("F", key), name=name, class_name=class_dots(cls),
            type=dalvik.descriptor_to_java(ftype), signature=key,
            is_external=external, is_static="static" in flags, access_flags=flags,
            origin=self.class_info[cls]["origin"],
        )
        self.g.add_edge("HAS_FIELD", cuid, uid)
        self.field_ids[key] = uid
        return uid

    def _resolve_method(self, ref: str) -> str:
        """Resolve an invoke target to a method uid, walking internal superclasses."""
        sig = method_sig(*dalvik.parse_method_ref(ref))
        if sig in self.method_ids and sig in self.methods:
            return self.method_ids[sig]
        cls, name, desc = dalvik.parse_method_ref(sig)
        key = name + desc
        seen = set()
        todo = [cls]
        while todo:
            c = todo.pop(0)
            if c in seen:
                continue
            seen.add(c)
            info = self.class_info.get(c)
            if info is None or info["external"]:
                continue
            if key in self.class_methods.get(c, ()) and c != cls:
                return self.method_ids[f"{c}->{key}"]
            if info["super"]:
                todo.append(info["super"])
            todo.extend(info["interfaces"])
        return self._method_node(sig, None, external_stub=True)

    def _resolve_field(self, ref: str) -> str:
        cls, name, ftype = dalvik.parse_field_ref(ref)
        key = f"{cls}->{name}:{ftype}"
        if key in self.field_ids:
            return self.field_ids[key]
        # Field declared in an internal superclass?
        c = self.class_info.get(cls, {}).get("super")
        while c and c in self.class_info and not self.class_info[c]["external"]:
            k = f"{c}->{name}:{ftype}"
            if k in self.field_ids:
                return self.field_ids[k]
            c = self.class_info[c]["super"]
        return self._field_node(cls, name, ftype, external=self.class_info.get(cls, {}).get("external", True))

    # ------------------------------------------------------------ method bodies
    def _add_bodies(self) -> None:
        scope = STMT_SCOPES[self.opts.stmt_scope]
        self.calls: dict[tuple[str, str], int] = defaultdict(int)
        self.returns: dict[str, list[str]] = defaultdict(list)    # method uid -> return stmts
        self.exits: dict[str, list[str]] = defaultdict(list)      # method uid -> return/throw stmts
        self.entries: dict[str, str] = {}                         # method uid -> first stmt
        self.pending_returns: list[tuple[str, str]] = []          # (callee uid, call stmt uid)
        self.pending_calls: list[tuple[str, str]] = []            # (callee uid, call stmt uid)
        self.params: dict[str, list[tuple[int, int, str]]] = {}   # method uid -> [(idx, reg, uid)]
        detailed = []
        for sig, ma in list(self.methods.items()):
            m = ma.get_method()
            if m.get_code() is None:
                continue
            muid = self.method_ids[sig]
            cls = m.get_class_name()
            if self.class_info[cls]["origin"] in scope:
                detailed.append((sig, ma))
                # Parameters first so ARG edges can target methods processed later.
                self._add_params(sig, muid, m)
            else:
                self._scan_calls(muid, m)
        for sig, ma in detailed:
            self._add_statements(sig, self.method_ids[sig], ma)
        if self.opts.with_source:
            self._add_sources(detailed)
        for (src, dst), n in self.calls.items():
            self.g.add_edge("CALLS", src, dst, count=n)
        self.stats["methods_with_statements"] = len(detailed)

    def _scan_calls(self, muid: str, m) -> None:
        for ins in m.get_instructions():
            if ins.get_name().startswith("invoke"):
                ref = _ref_operand(ins)
                if ref:
                    self.calls[(muid, self._resolve_method(ref))] += 1

    def _add_params(self, sig: str, muid: str, m) -> None:
        code = m.get_code()
        cls, name, desc = dalvik.parse_method_ref(sig)
        pdescs, _ = dalvik.split_method_descriptor(desc)
        is_static = "static" in m.get_access_flags_string()
        regs = dalvik.param_registers(code.get_registers_size(), code.get_ins_size(), pdescs, is_static)
        out = []
        types = ([cls] if not is_static else []) + pdescs
        for (idx, reg), t in zip(regs, types):
            uid = self.g.add_node(
                PARAMETER, f"{muid}#{idx}", method_signature=sig, index=idx, register=reg,
                type=dalvik.descriptor_to_java(t), is_this=(not is_static and idx == 0),
            )
            self.g.add_edge("HAS_PARAM", muid, uid, index=idx)
            out.append((idx, reg, uid))
        self.params[muid] = out

    def _add_statements(self, sig: str, muid: str, ma) -> None:
        g = self.g
        m = ma.get_method()
        bbs = [bb for bb in ma.get_basic_blocks().get()]
        if not bbs:
            return

        # 1. Statements per basic block
        block_stmts: list[list[tuple[str, list, list]]] = []
        block_last: list[tuple | None] = []    # (op, offset, operands) of each block's last instruction
        ins_at: dict[int, Any] = {}            # offset -> instruction, payloads included
        o = 0
        for ins in m.get_instructions():
            ins_at[o] = ins
            o += ins.get_length()
        idx = 0
        for b, bb in enumerate(bbs):
            stmts = []
            last = None
            off = bb.get_start()
            for ins in bb.get_instructions():
                op = ins.get_name()
                length = ins.get_length()
                if op.endswith("-payload"):
                    off += length
                    continue
                suid = f"{muid}@{off}"
                try:
                    operands = ins.get_operands(off)
                except Exception:
                    operands = []
                regs = [o[1] for o in operands if _is_register(o)]
                ref = _ref_operand(ins, operands)
                type_ref = _type_operand(operands) if ref is None else None
                defs, uses = dalvik.defs_and_uses(op, regs)
                props = dict(method_signature=sig, offset=off, idx=idx, bb=b, opcode=op,
                             kind=dalvik.instruction_kind(op), code=f"{op} {ins.get_output()}".strip(),
                             defs=[_reg_name(r) for r in defs], uses=[_reg_name(r) for r in uses])
                if type_ref:
                    props["type_ref"] = dalvik.descriptor_to_java(type_ref)
                last = (op, off, operands)
                if op.startswith("invoke") and ref:
                    callee = self._resolve_method(ref)
                    tcls, tname, tdesc = dalvik.parse_method_ref(ref)
                    tinfo = java_method_info(tcls, tname, tdesc)
                    props.update(target=method_sig(tcls, tname, tdesc), target_class=tinfo["class_name"],
                                 target_name=tname, target_java_signature=tinfo["java_signature"])
                    g.add_node(STATEMENT, suid, **props)
                    g.add_edge("INVOKES", suid, callee)
                    self.calls[(muid, callee)] += 1
                    self._record_call(muid, suid, callee, regs, tcls, tname, tdesc, op)
                    self.stmt_meta[suid] = (op, regs, None, tcls, None)
                elif op.startswith(("iget", "sget", "iput", "sput")) and ref:
                    fuid = self._resolve_field(ref)
                    props.update(target=ref)
                    g.add_node(STATEMENT, suid, **props)
                    if op[1:4] == "get":
                        g.add_edge("READ_BY", fuid, suid)
                    else:
                        g.add_edge("WRITES_FIELD", suid, fuid)
                elif op.startswith("const-string"):
                    literal = _string_literal(operands, ins)
                    props.update(literal=literal)
                    g.add_node(STATEMENT, suid, **props)
                    self.stmt_meta[suid] = (op, regs, None, None, literal)
                else:
                    if ref:
                        props.update(target=ref)
                    g.add_node(STATEMENT, suid, **props)
                    if op in ("new-instance", "const-class", "check-cast") or op.startswith("move-object"):
                        self.stmt_meta[suid] = (op, regs, type_ref, None, None)
                if op.startswith("return"):
                    self.returns[muid].append(suid)
                if op.startswith(("return", "throw")):
                    self.exits[muid].append(suid)
                g.add_edge("HAS_STATEMENT", muid, suid)
                stmts.append((suid, defs, uses))
                off += length
                idx += 1
            block_stmts.append(stmts)
            block_last.append(last)
        g.nodes[METHOD][muid]["instruction_count"] = idx
        g.nodes[METHOD][muid]["has_statements"] = True

        # 2. CFG edges, labelled with the branch outcome that takes them
        bb_index = {id(bb): i for i, bb in enumerate(bbs)}
        succs: list[list[tuple[int, bool]]] = [[] for _ in bbs]
        labels: list[dict[int, str]] = [{} for _ in bbs]
        for i, bb in enumerate(bbs):
            for child in bb.childs:
                j = bb_index.get(id(child[2]))
                if j is not None and (j, False) not in succs[i]:
                    succs[i].append((j, False))
                    labels[i][j] = _branch_label(block_last[i], bbs[j].get_start(), ins_at)
            if self.opts.include_exception_edges and bb.exception_analysis:
                for exc in bb.exception_analysis.exceptions:
                    j = bb_index.get(id(exc[2])) if len(exc) > 2 and exc[2] is not None else None
                    if j is not None and (j, True) not in succs[i]:
                        succs[i].append((j, True))
        first = next((s[0][0] for s in block_stmts if s), None)
        if first:
            g.add_edge("ENTRY", muid, first)
            self.entries[muid] = first
        for i, stmts in enumerate(block_stmts):
            for (a, _, _), (b, _, _) in zip(stmts, stmts[1:]):
                g.add_edge("FLOWS_TO", a, b, exception=False)
            if not stmts:
                continue
            last = stmts[-1][0]
            for j, is_exc in succs[i]:
                tgt = _first_stmt(block_stmts, succs, j)
                if tgt:
                    if is_exc:
                        g.add_edge("FLOWS_TO", last, tgt, exception=True)
                    else:
                        g.add_edge("FLOWS_TO", last, tgt, exception=False, branch=labels[i].get(j))

        # 3. Control dependence: the branch statement -> every statement it decides on
        normal = [[(j, labels[i].get(j) or "next") for j, exc in succs[i] if not exc]
                  for i in range(len(bbs))]
        for blk, controllers in control_dependence(normal).items():
            merged: dict[int, list[str]] = defaultdict(list)
            for a, label in controllers:
                merged[a].append(label)
            for a, labs in merged.items():
                if not block_stmts[a]:
                    continue
                branch_stmt = block_stmts[a][-1][0]
                for suid, _, _ in block_stmts[blk]:
                    g.add_edge("CONTROL_DEP", branch_stmt, suid, branch="|".join(sorted(set(labs))))

        # 4. Reaching definitions -> DATA_DEP (and ARG edges for internal calls)
        self._reaching_defs(muid, block_stmts, succs)

    def _record_call(self, caller_uid: str, call_uid: str, callee_uid: str, regs: list[int],
                     tcls: str, tname: str, tdesc: str, op: str) -> None:
        pdescs, ret = dalvik.split_method_descriptor(tdesc)
        args = dalvik.invoke_arg_registers(regs, pdescs, op.startswith("invoke-static"))
        self._call_args[call_uid] = (callee_uid, args)
        self.pending_calls.append((callee_uid, call_uid))
        if ret != "V":
            self.pending_returns.append((callee_uid, call_uid))
        if callee_uid not in self.params:
            # Framework / SDK code we have no statements for: may call back into the app.
            self.registrations.append((caller_uid, call_uid, tcls, tname, op, args, pdescs))

    def _reaching_defs(self, muid: str, block_stmts, succs) -> None:
        n = len(block_stmts)
        entry_state: dict[Any, frozenset] = {
            reg: frozenset([puid]) for _, reg, puid in self.params.get(muid, [])
        }
        preds: list[list[int]] = [[] for _ in range(n)]
        for i, ss in enumerate(succs):
            for j, _ in ss:
                preds[j].append(i)
        out_states: list[dict | None] = [None] * n
        in_states: list[dict] = [{} for _ in range(n)]

        def transfer(state: dict, stmts) -> dict:
            state = dict(state)
            for suid, defs, _ in stmts:
                for d in defs:
                    state[d] = frozenset([suid])
            return state

        work = deque(range(n))
        in_work = set(work)
        while work:
            i = work.popleft()
            in_work.discard(i)
            state: dict = dict(entry_state) if i == 0 else {}
            for p in preds[i]:
                ps = out_states[p]
                if ps:
                    for reg, ds in ps.items():
                        cur = state.get(reg)
                        state[reg] = ds if cur is None else cur | ds
            in_states[i] = state
            new_out = transfer(state, block_stmts[i])
            if new_out != out_states[i]:
                out_states[i] = new_out
                for j, _ in succs[i]:
                    if j not in in_work:
                        work.append(j)
                        in_work.add(j)

        g = self.g
        for i, stmts in enumerate(block_stmts):
            state = dict(in_states[i])
            for suid, defs, uses in stmts:
                if suid in self.stmt_meta:
                    self.use_defs[suid] = {u: state.get(u, frozenset()) for u in uses}
                for u in dict.fromkeys(uses):
                    for d in state.get(u, ()):
                        g.add_edge("DATA_DEP", d, suid, reg=_reg_name(u))
                call = self._call_args.pop(suid, None)
                if call:
                    callee_uid, args = call
                    callee_params = {idx: puid for idx, _, puid in self.params.get(callee_uid, [])}
                    for idx, reg in args:
                        puid = callee_params.get(idx)
                        if puid:
                            for d in state.get(reg, ()):
                                g.add_edge("ARG", d, puid, index=idx, call_site=suid)
                for d in defs:
                    state[d] = frozenset([suid])

    def _link_returns(self) -> None:
        for callee_uid, call_uid in self.pending_returns:
            for ruid in self.returns.get(callee_uid, ()):
                self.g.add_edge("RETURN", ruid, call_uid)
        # Interprocedural control flow (ICFG): into the callee and back out of it.
        for callee_uid, call_uid in self.pending_calls:
            entry = self.entries.get(callee_uid)
            if entry:
                self.g.add_edge("CALL_FLOW", call_uid, entry)
                for xuid in self.exits.get(callee_uid, ()):
                    self.g.add_edge("RETURN_FLOW", xuid, call_uid)
        self.pending_returns.clear()
        self.pending_calls.clear()

    def _add_sources(self, detailed) -> None:
        """Decompiled Java for each analysed method, the input PriGen-style captioning uses."""
        try:
            from loguru import logger
            logger.disable("androguard")
        except ImportError:
            logger = None
        t = time.time()
        n = 0
        for sig, ma in detailed:
            try:
                src = ma.get_method().get_source()
            except Exception:
                continue
            if src:
                self.g.nodes[METHOD][self.method_ids[sig]]["source"] = src.strip("\n")
                n += 1
        if logger:
            logger.enable("androguard")
        self.stats["methods_with_source"] = n
        self.stats["source_seconds"] = round(time.time() - t, 1)

    # ------------------------------------------------- overrides & entrypoints
    def _add_overrides_and_entrypoints(self) -> None:
        g = self.g
        overrides = self.overrides
        for sig in list(self.methods):
            cls, name, desc = dalvik.parse_method_ref(sig)
            muid = self.method_ids[sig]
            node = g.nodes[METHOD][muid]
            if node["is_constructor"] or node["is_static"] or "private" in node["access_flags"]:
                continue
            key = name + desc
            info = self.class_info[cls]
            todo = ([info["super"]] if info["super"] else []) + list(info["interfaces"])
            seen = set()
            while todo:
                c = todo.pop(0)
                if c in seen:
                    continue
                seen.add(c)
                if key in self.class_methods.get(c, ()):
                    tgt = self.method_ids[f"{c}->{key}"]
                    g.add_edge("OVERRIDES", muid, tgt)
                    overrides[muid].append(tgt)
                    continue
                cinfo = self.class_info.get(c)
                if cinfo is None:
                    continue
                if cinfo["external"]:
                    if c != "Ljava/lang/Object;" and (_CALLBACK_RE.match(name) or name in CALLBACK_NAMES):
                        tgt = self._method_node(f"{c}->{key}", None, external_stub=True)
                        g.add_edge("OVERRIDES", muid, tgt, inferred=True)
                        overrides[muid].append(tgt)
                    continue
                if cinfo["super"]:
                    todo.append(cinfo["super"])
                todo.extend(cinfo["interfaces"])

        memo: dict[str, bool] = {}

        def is_callback_target(uid: str) -> bool:
            node = g.nodes[METHOD][uid]
            if node["origin"] == "library":
                return True
            return node["origin"] == "framework" and (
                node["class_name"].startswith(("android.", "com.android."))
                or node["class_name"] in FRAMEWORK_CALLBACK_CLASSES)

        def framework_reachable(uid: str) -> bool:
            if uid in memo:
                return memo[uid]
            memo[uid] = False  # cycle guard
            res = any(is_callback_target(t) or framework_reachable(t)
                      for t in overrides.get(uid, ()))
            memo[uid] = res
            return res

        n_entry = 0
        for sig in self.methods:
            muid = self.method_ids[sig]
            node = g.nodes[METHOD][muid]
            if node["origin"] not in ("app", "unknown"):
                continue
            cls_name = node["class_name"]
            if framework_reachable(muid):
                kind = "component_lifecycle" if cls_name in self.component_classes else "callback"
            elif cls_name in self.component_classes and node["is_constructor"]:
                kind = "component_init"
            else:
                continue
            node["is_entrypoint"] = True
            node["entrypoint_kind"] = kind
            n_entry += 1
        self.stats["entrypoints"] = n_entry

    # ---------------------------------------------------- API -> permission map
    def _add_api_permissions(self) -> None:
        try:
            from androguard.core.api_specific_resources import load_permission_mappings
            mapping = load_permission_mappings(PERMISSION_MAPPING_API)
        except Exception:
            return
        n = 0
        for key, perms in mapping.items():
            try:
                cls, name, desc = key.split("-", 2)
            except ValueError:
                continue
            sig = method_sig(cls, name, desc)
            muid = self.method_ids.get(sig)
            if not muid:
                continue
            for p in perms:
                self.g.add_edge("API_REQUIRES_PERMISSION", muid, self._perm_node(p),
                                source=f"androguard-api{PERMISSION_MAPPING_API}")
                n += 1
            node = self.g.nodes[METHOD][muid]
            node["permissions"] = sorted(set(node.get("permissions") or []) | set(perms))
        self.stats["api_permission_edges"] = n


# ---------------------------------------------------------------- helpers
def _is_register(operand) -> bool:
    kind = operand[0]
    return getattr(kind, "name", None) == "REGISTER" or kind == 0


def _ref_operand(ins, operands: Iterable | None = None) -> str | None:
    """Return the method/field/type reference string of an instruction, if any."""
    if operands is None:
        try:
            operands = ins.get_operands(0)
        except Exception:
            return None
    for o in operands:
        if len(o) >= 3 and isinstance(o[2], str) and "->" in o[2]:
            return o[2]
    return None


def _type_operand(operands) -> str | None:
    """Type reference of new-instance / const-class / check-cast / new-array."""
    for o in operands:
        if len(o) >= 3 and isinstance(o[2], str) and "->" not in o[2] and o[2][:1] in ("L", "["):
            return o[2]
    return None


def _offset_operand(operands) -> int | None:
    for o in operands:
        if getattr(o[0], "name", None) == "OFFSET" and len(o) >= 2:
            return o[1]
    return None


def _branch_label(last: tuple | None, child_start: int, ins_at: dict) -> str | None:
    """Which outcome of a block's final instruction leads to the block at ``child_start``."""
    if last is None:
        return None
    op, off, operands = last
    imm = _offset_operand(operands)
    if op.startswith("if-") and imm is not None:
        return "true" if child_start == off + 2 * imm else "false"
    if op in ("packed-switch", "sparse-switch") and imm is not None:
        payload = ins_at.get(off + 2 * imm)
        try:
            keys, targets = payload.get_keys(), payload.get_targets()
        except Exception:
            return None
        hits = [str(k) for k, t in zip(keys, targets) if off + 2 * t == child_start]
        return ("case:" + ",".join(hits)) if hits else "default"
    if op.startswith("goto"):
        return "goto"
    return None


def _string_literal(operands, ins) -> str | None:
    for o in operands:
        if len(o) >= 3 and isinstance(o[2], str):
            return o[2]
    out = ins.get_output()
    m = re.search(r",\s*'(.*)'$", out, re.S) or re.search(r',\s*"(.*)"$', out, re.S)
    return m.group(1) if m else out


def _first_stmt(block_stmts, succs, j: int, _seen: set | None = None) -> str | None:
    """First statement of block j, skipping empty (payload-only) blocks."""
    if block_stmts[j]:
        return block_stmts[j][0][0]
    _seen = _seen or set()
    _seen.add(j)
    for k, _ in succs[j]:
        if k not in _seen:
            r = _first_stmt(block_stmts, succs, k, _seen)
            if r:
                return r
    return None


def _reg_name(r) -> str:
    return r if isinstance(r, str) else f"v{r}"


def build_apg(apk_path: str | Path, **kwargs: Any) -> tuple[APG, dict[str, Any]]:
    b = APGBuilder(apk_path, BuildOptions(**kwargs))
    g = b.build()
    return g, b.stats
