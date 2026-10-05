from apg.controldep import control_dependence


def test_if_then_else():
    # 0: if -> 1 (true) / 2 (false); both -> 3 (join)
    succ = [[(1, "true"), (2, "false")], [(3, "next")], [(3, "next")], []]
    deps = control_dependence(succ)
    assert deps == {1: [(0, "true")], 2: [(0, "false")]}  # the join runs either way


def test_nested_if_only_direct_controller():
    # 0: if -> 1 / 3 ; 1: if -> 2 / 3 ; 2 -> 3
    succ = [[(1, "true"), (3, "false")], [(2, "true"), (3, "false")], [(3, "next")], []]
    deps = control_dependence(succ)
    assert deps[1] == [(0, "true")]
    assert deps[2] == [(1, "true")]
    assert 3 not in deps


def test_loop_body_depends_on_loop_condition():
    # 0: while-cond -> 1 (body, true) / 2 (exit, false); 1 -> 0
    succ = [[(1, "true"), (2, "false")], [(0, "next")], []]
    deps = control_dependence(succ)
    assert (0, "true") in deps[1]
    assert (0, "true") in deps[0]  # the condition re-runs only if the body ran


def test_infinite_loop_is_ignored():
    succ = [[(1, "true"), (2, "false")], [(1, "next")], []]
    assert control_dependence(succ) is not None
