from apg import dalvik
from apg.dalvik import RESULT_REG


def test_descriptor_to_java_matches_document_analysis_format():
    assert dalvik.descriptor_to_java("Ljava/lang/String;") == "java.lang.String"
    assert dalvik.descriptor_to_java("[Ljava/lang/String;") == "java.lang.String[]"
    assert dalvik.descriptor_to_java("[[I") == "int[][]"
    assert dalvik.descriptor_to_java("V") == "void"


def test_split_method_descriptor_with_and_without_spaces():
    expected = (["Landroid/content/Context;", "J", "[Ljava/lang/String;"], "V")
    assert dalvik.split_method_descriptor("(Landroid/content/Context; J [Ljava/lang/String;)V") == expected
    assert dalvik.split_method_descriptor("(Landroid/content/Context;J[Ljava/lang/String;)V") == expected
    assert dalvik.split_method_descriptor("()Ljava/lang/String;") == ([], "Ljava/lang/String;")


def test_parse_refs():
    assert dalvik.parse_method_ref("Landroid/net/wifi/WifiInfo;->getSSID()Ljava/lang/String;") == (
        "Landroid/net/wifi/WifiInfo;", "getSSID", "()Ljava/lang/String;")
    assert dalvik.parse_field_ref("Lorg/x/App;->ssid Ljava/lang/String;") == (
        "Lorg/x/App;", "ssid", "Ljava/lang/String;")


def test_param_registers_instance_method_with_wide_arg():
    # 6 registers, ins = this + long(2) + Object = 4 -> args start at v2
    regs = dalvik.param_registers(6, 4, ["J", "Ljava/lang/Object;"], is_static=False)
    assert regs == [(0, 2), (1, 3), (2, 5)]


def test_invoke_arg_registers_collapse_wide_pairs():
    regs = dalvik.invoke_arg_registers([0, 1, 2, 3], ["J", "I"], is_static=False)
    assert regs == [(0, 0), (1, 1), (2, 3)]


def test_defs_and_uses():
    assert dalvik.defs_and_uses("move-result-object", [2]) == ([2], [RESULT_REG])
    assert dalvik.defs_and_uses("invoke-static", [1, 3]) == ([RESULT_REG], [1, 3])
    # instance call with arguments may store them in the receiver
    assert dalvik.defs_and_uses("invoke-virtual", [3, 2]) == ([RESULT_REG, 3], [3, 2])
    # getters do not redefine the receiver
    assert dalvik.defs_and_uses("invoke-virtual", [8]) == ([RESULT_REG], [8])
    assert dalvik.defs_and_uses("iput-object", [0, 1]) == ([], [0, 1])
    assert dalvik.defs_and_uses("iget-object", [0, 1]) == ([0], [1])
    assert dalvik.defs_and_uses("add-int/2addr", [0, 1]) == ([0], [0, 1])
    assert dalvik.defs_and_uses("if-eqz", [4]) == ([], [4])
    assert dalvik.defs_and_uses("const-string", [1]) == ([1], [])
