from freenas_manager import Host


def test_uniqueness():
    a = Host("a:b")
    b = Host("b:c")
    c = Host("B:c")

    assert a is not b
    assert b is c
