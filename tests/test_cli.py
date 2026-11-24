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
    for count in (9, 10, 11):
        for ending in (b"", b"\0"):
            p.write_bytes(b"\0".join([b"abcd"] * count) + ending)
            out = run(p).stdout
            assert ("Additional strings omitted" in out) == (count > 10), out
    p.write_bytes(b"")
    out = run(p).stdout
    assert "ASCII printable bytes: unavailable (empty file)" in out
    assert "Entropy: unavailable (empty file)" in out
    p.write_bytes(b"AAAA")
    out = run(p).stdout
    assert "ASCII printable bytes: 100.0%" in out and "Entropy: 0.000 bits/byte" in out
    sig7z = b"\x37\x7a\xbc\xaf\x27\x1c"
    p.write_bytes(sig7z)
    assert "Possible type: 7z archive" in run(p).stdout
    p.write_bytes(b"x" * 8190 + sig7z)
    assert "Embedded signature at offset 8190 (0x1FFE): 7z archive" in run(p).stdout
    p.write_bytes(sig7z[:-1])
    assert "Possible type: 7z archive" not in run(p).stdout
    sigxz = b"\xfd7zXZ\x00"
    p.write_bytes(sigxz)
    assert "Possible type: XZ stream" in run(p).stdout
    p.write_bytes(b"x" * 8190 + sigxz)
    assert "Embedded signature at offset 8190 (0x1FFE): XZ stream" in run(p).stdout
    p.write_bytes(sigxz[:-1])
    assert "Possible type: XZ stream" not in run(p).stdout
    p.write_bytes(b"\0" * 8190 + b"hello world")
    out = run(p).stdout
    assert "[offset 8190 (0x1FFE)] hello world" in out, out
    p.write_bytes(b"hello\0world\0")
    out = run(p).stdout
    assert "[offset 0 (0x0)] hello" in out and "[offset 6 (0x6)] world" in out, out
    for subtype, expected in [(b"WAVE", "RIFF/WAVE audio"), (b"WEBP", "RIFF/WEBP image"), (b"AVI ", "RIFF/AVI video"), (b"????", "RIFF container")]:
        p.write_bytes(b"RIFF" + b"\0" * 4 + subtype)
        assert "Possible type: " + expected in run(p).stdout
    p.write_bytes(b"RIFF")
    assert "Possible type: RIFF container" in run(p).stdout
    for subtype, hint in [(b"WAVE", "waveform or spectrogram"), (b"WEBP", "animation frames"), (b"AVI ", "video metadata and streams"), (b"????", "container subtype")]:
        p.write_bytes(b"RIFF" + b"\0" * 4 + subtype)
        assert hint in run(p).stdout
    for data, expected in [(b"\x1f\x8b\x08", True), (b"\x1f\x8b", False), (b"\x1f\x8b\x00", False)]:
        p.write_bytes(data)
        assert ("Possible type: gzip stream" in run(p).stdout) == expected
        p.write_bytes(b"X" * 8190 + data)
        assert ("Embedded signature at offset 8190 (0x1FFE): gzip stream" in run(p).stdout) == expected
    assert run().returncode == 2
    assert run("--help").returncode == 0
    version = run("--version")
    assert version.returncode == 0 and version.stdout.strip() == "MISC-Compass 0.2.11"
    assert run(pathlib.Path(d) / "missing").returncode == 1
print("CLI checks passed")
