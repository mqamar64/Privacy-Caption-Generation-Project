"""Control dependence between basic blocks (the SDG's control edges in VulHunter).

Block B is control dependent on branch block A with label L when taking A's L
edge guarantees B runs, but another edge out of A may skip it. Computed with
post-dominators and the Ferrante-Ottenstein-Warren walk up the post-dominator tree.
Exception edges are left out, as in VulHunter.
"""

from __future__ import annotations


def postdominators(succ: list[list[int]]) -> list[int]:
    """Post-dominator sets as bitsets; node ``len(succ)`` is a virtual exit.

    A block with no successors (return / throw) flows to the exit. Blocks that
    can never reach the exit (infinite loops) keep the full set.
    """
    n = len(succ)
    full = (1 << (n + 1)) - 1
    pdom = [full] * n + [1 << n]
    changed = True
    while changed:
        changed = False
        for i in range(n - 1, -1, -1):
            acc = full
            for s in succ[i] or [n]:
                acc &= pdom[s]
            new = acc | (1 << i)
            if new != pdom[i]:
                pdom[i] = new
                changed = True
    return pdom


def reaches_exit(succ: list[list[int]]) -> list[bool]:
    """Which blocks can reach the virtual exit (infinite loops cannot)."""
    n = len(succ)
    preds: list[list[int]] = [[] for _ in range(n + 1)]
    for i, ss in enumerate(succ):
        for s in ss or [n]:
            preds[s].append(i)
    ok = [False] * (n + 1)
    ok[n] = True
    todo = [n]
    while todo:
        for p in preds[todo.pop()]:
            if not ok[p]:
                ok[p] = True
                todo.append(p)
    return ok


def immediate_postdominators(pdom: list[int], ok: list[bool]) -> list[int | None]:
    n = len(pdom) - 1
    ipdom: list[int | None] = [None] * (n + 1)
    for i in range(n):
        if not ok[i]:
            continue
        strict = pdom[i] & ~(1 << i)
        bits = strict
        while bits:
            d = (bits & -bits).bit_length() - 1
            bits &= bits - 1
            if pdom[d] == strict:
                ipdom[i] = d
                break
    return ipdom


def control_dependence(succ: list[list[tuple[int, str]]]) -> dict[int, list[tuple[int, str]]]:
    """Map block -> [(controlling branch block, edge label)] for normal (non-exception) edges."""
    plain = [[j for j, _ in s] for s in succ]
    n = len(plain)
    pdom = postdominators(plain)
    ok = reaches_exit(plain)
    ipdom = immediate_postdominators(pdom, ok)
    deps: dict[int, list[tuple[int, str]]] = {}
    for a, edges in enumerate(succ):
        if len(edges) < 2 or not ok[a]:
            continue
        for b, label in edges:
            if not ok[b] or pdom[a] >> b & 1:
                continue  # b post-dominates a: runs whichever way a branches
            stop = ipdom[a]
            runner: int | None = b
            steps = 0
            while runner is not None and runner != stop and runner != n and steps <= n:
                deps.setdefault(runner, []).append((a, label))
                runner = ipdom[runner]
                steps += 1
    return deps
