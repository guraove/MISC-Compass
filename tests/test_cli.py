import pathlib, subprocess, sys, tempfile
exe = sys.argv[1]
def run(*args):
    return subprocess.run([exe, *map(str, args)], capture_output=True, text=True)
with tempfile.TemporaryDirectory() as d:
    p = pathlib.Path(d) / "sample.bin"
    for data, expected in [(b"\x89PNG\r\n\x1a\nhello world", "PNG image"), (b"PK\x05\x06", "ZIP archive"), (b"", "unknown"), (b"hello world", "unknown")]:
        p.write_bytes(data)
        result = run(p)
        assert result.returncode == 0, result.stderr
        assert expected in result.stdout, result.stdout
        assert f"Size: {len(data)} bytes" in result.stdout
    p.write_bytes(b"A" * 8190 + b"\x89PNG\r\n\x1a\n")
    out = run(p).stdout
    assert "Embedded signature at offset 8190 (0x1FFE): PNG image" in out, out
    p.write_bytes(b"\x89PNG\r\n\x1a\n")
    assert "Embedded signature at offset" not in run(p).stdout
    p.write_bytes(b"hello world\0" + b"\x89PNG\r\n\x1a\n" + b"another string")
    out = run(p).stdout
    assert out.index("hello world") < out.index("another string") < out.index("Embedded signatures (first 10):") < out.index("Embedded signature at offset"), out
    for count in (9, 10, 11):
        p.write_bytes(b"\0" + b"PK\x03\x04\0" * count)
        out = run(p).stdout
        assert out.count("Embedded signature at offset") == min(count, 10), out
        assert ("Additional signatures omitted" in out) == (count > 10), out
    assert run().returncode == 2
    assert run("--help").returncode == 0
    assert run(pathlib.Path(d) / "missing").returncode == 1
print("CLI checks passed")
