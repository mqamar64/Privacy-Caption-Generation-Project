"""Dalvik bytecode helpers: type-descriptor conversion and register def/use semantics.

Type names are emitted in the same dotted Java form the Document Analysis Module
uses (e.g. ``java.lang.String[]``) so APG API nodes can be joined against
``formatted_sources.csv`` / ``formatted_sinks.csv`` without further translation.
"""

from __future__ import annotations

import re

_PRIMITIVES = {
    "V": "void", "Z": "boolean", "B": "byte", "S": "short", "C": "char",
    "I": "int", "J": "long", "F": "float", "D": "double",
}

# Pseudo-register holding the value produced by the last invoke / filled-new-array,
# consumed by the following move-result*.
RESULT_REG = "result"


def descriptor_to_java(desc: str) -> str:
    """``[Ljava/lang/String;`` -> ``java.lang.String[]``; ``I`` -> ``int``."""
    desc = desc.strip()
    dims = 0
    while desc.startswith("["):
        dims += 1
        desc = desc[1:]
    if desc in _PRIMITIVES:
        base = _PRIMITIVES[desc]
    elif desc.startswith("L") and desc.endswith(";"):
        base = desc[1:-1].replace("/", ".")
    else:
        base = desc.replace("/", ".")
    return base + "[]" * dims


def split_method_descriptor(descriptor: str) -> tuple[list[str], str]:
    """Split ``(Ljava/lang/String; I)V`` into (["Ljava/lang/String;", "I"], "V").

    Androguard separates parameters with spaces; raw dex descriptors do not, so
    parameters are tokenised rather than split on whitespace.
    """
    m = re.match(r"\s*\((.*)\)\s*(\S+)\s*$", descriptor)
    if not m:
        raise ValueError(f"bad method descriptor: {descriptor!r}")
    body = m.group(1).replace(" ", "")
    params: list[str] = []
    i = 0
    while i < len(body):
        j = i
        while body[j] == "[":
            j += 1
        if body[j] == "L":
            j = body.index(";", j)
        params.append(body[i:j + 1])
        i = j + 1
    return params, m.group(2)


def is_wide(desc: str) -> bool:
    return desc in ("J", "D")


def parse_method_ref(ref: str) -> tuple[str, str, str]:
    """``Lpkg/Cls;->name(Desc)Ret`` -> ("Lpkg/Cls;", "name", "(Desc)Ret")."""
    cls, rest = ref.split("->", 1)
    paren = rest.index("(")
    return cls.strip(), rest[:paren], rest[paren:].strip()


def parse_field_ref(ref: str) -> tuple[str, str, str]:
    """``Lpkg/Cls;->name Ltype;`` -> ("Lpkg/Cls;", "name", "Ltype;")."""
    cls, rest = ref.split("->", 1)
    name, _, ftype = rest.strip().partition(" ")
    return cls.strip(), name, ftype.strip()


def param_registers(registers_size: int, ins_size: int, param_descs: list[str],
                    is_static: bool) -> list[tuple[int, int]]:
    """Return ``[(arg_index, register)]`` for a method's incoming arguments.

    Arguments occupy the last ``ins_size`` registers; ``this`` comes first for
    instance methods and wide (long/double) values take two registers.
    Argument index 0 is ``this`` for instance methods, matching invoke operand order.
    """
    reg = registers_size - ins_size
    out: list[tuple[int, int]] = []
    idx = 0
    if not is_static:
        out.append((idx, reg))
        idx += 1
        reg += 1
    for p in param_descs:
        out.append((idx, reg))
        idx += 1
        reg += 2 if is_wide(p) else 1
    return out


def invoke_arg_registers(regs: list[int], param_descs: list[str],
                         is_static: bool) -> list[tuple[int, int]]:
    """Map invoke operand registers to ``[(arg_index, register)]``, collapsing wide pairs."""
    out: list[tuple[int, int]] = []
    pos = 0
    idx = 0
    if not is_static and regs:
        out.append((0, regs[0]))
        pos, idx = 1, 1
    for p in param_descs:
        if pos >= len(regs):
            break
        out.append((idx, regs[pos]))
        pos += 2 if is_wide(p) else 1
        idx += 1
    return out


# --- def/use classification -------------------------------------------------

_NO_DEF_PREFIXES = (
    "invoke", "filled-new-array", "if-", "iput", "sput", "aput", "return",
    "throw", "monitor-", "packed-switch", "sparse-switch", "fill-array-data",
    "goto", "nop",
)


def defs_and_uses(opname: str, regs: list[int]) -> tuple[list, list]:
    """Return (defined, used) registers for one instruction.

    ``regs`` are the instruction's register operands in order. Wide register pairs
    are tracked by their low register only.
    """
    if opname.startswith(("move-result",)):
        return regs[:1], [RESULT_REG]
    if opname == "move-exception":
        return regs[:1], []
    if opname.startswith("filled-new-array"):
        return [RESULT_REG], list(regs)
    if opname.startswith("invoke"):
        # Instance calls that take arguments may store them in their receiver
        # (StringBuilder.append, new URL(s) via <init>, JSONObject.put ...), so the receiver
        # is redefined by the call. Argument-less calls (getters) leave it untouched,
        # which keeps e.g. info.getSSID() from tainting a later info.getBSSID().
        if len(regs) > 1 and not opname.startswith(("invoke-static", "invoke-custom", "invoke-polymorphic")):
            return [RESULT_REG, regs[0]], list(regs)
        return [RESULT_REG], list(regs)
    if opname.startswith(_NO_DEF_PREFIXES):
        return [], list(regs)
    if not regs:
        return [], []
    if opname.endswith("/2addr") or opname == "check-cast":
        return regs[:1], list(regs)
    return regs[:1], regs[1:]


def instruction_kind(opname: str) -> str:
    """Coarse statement category, handy for Cypher filtering."""
    for prefix, kind in (
        ("invoke", "invoke"), ("move-result", "move_result"), ("return", "return"),
        ("const-string", "const_string"), ("const-class", "const_class"),
        ("const", "const"), ("iget", "field_read"), ("sget", "field_read"),
        ("iput", "field_write"), ("sput", "field_write"), ("aget", "array_read"),
        ("aput", "array_write"), ("new-instance", "new_instance"),
        ("new-array", "new_array"), ("filled-new-array", "new_array"),
        ("if-", "branch"), ("packed-switch", "switch"), ("sparse-switch", "switch"),
        ("goto", "goto"), ("throw", "throw"), ("move-exception", "catch"),
        ("check-cast", "cast"), ("instance-of", "instance_of"),
        ("monitor", "monitor"), ("move", "move"),
    ):
        if opname.startswith(prefix):
            return kind
    return "other"
