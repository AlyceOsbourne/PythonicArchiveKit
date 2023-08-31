from pythonic_archive_kit import open_pak

if __name__ == "__main__":
    import pathlib

    if (path := pathlib.Path("test.pak")).exists():
        path.unlink()
        
    with open_pak("test.pak") as pak:
        assert not pak
        pak.a.b.c = 1
        pak.a.b.d = 2
        pak.a.b.e = 3

        assert pak.a.b.c == 1
        assert not pak.a.b.c == 2
        assert pak.a.b.d == 2
        assert not pak.a.b.d == 3
        assert pak.a.b.e == 3
        assert not pak.a.b.e == 4

        assert pak.a.b == {"c": 1, "d": 2, "e": 3}
        assert not pak.a.b == {"c": 1, "d": 2, "e": 4}
        assert pak.a == {"b": {"c": 1, "d": 2, "e": 3}}
        assert not pak.a == {"b": {"c": 1, "d": 2, "e": 4}}
        assert pak == {"a": {"b": {"c": 1, "d": 2, "e": 3}}}
        assert not pak == {"a": {"b": {"c": 1, "d": 2, "e": 4}}}
        
    with open_pak("test.pak") as pak:
        assert pak.a.b.c == 1
        assert not pak.a.b.c == 2
        assert pak.a.b.d == 2
        assert not pak.a.b.d == 3
        assert pak.a.b.e == 3
        assert not pak.a.b.e == 4

        assert pak.a.b == {"c": 1, "d": 2, "e": 3}
        assert not pak.a.b == {"c": 1, "d": 2, "e": 4}
        assert pak.a == {"b": {"c": 1, "d": 2, "e": 3}}
        assert not pak.a == {"b": {"c": 1, "d": 2, "e": 4}}
        assert pak == {"a": {"b": {"c": 1, "d": 2, "e": 3}}}
        assert not pak == {"a": {"b": {"c": 1, "d": 2, "e": 4}}}
        
        del pak.a.b.c
        del pak.a.b.d
        del pak.a.b.e
        
        assert not pak.cull()
        
        assert pak.a.b == {}
        assert pak.a == {"b": {}}
        assert pak == {"a": {"b": {}}}
        
    with open_pak("test.pak") as pak:
        assert not pak
        assert pak == {}

    with open("test.pak", "rb") as f:
        assert f.read(2) == b"\x1f\x8b"
        
