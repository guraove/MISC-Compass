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
    assert run().returncode == 2
    assert run("--help").returncode == 0
    assert run(pathlib.Path(d) / "missing").returncode == 1
print("CLI checks passed")
