"""Unit tests for static preprocessors and security helpers.
No untrusted Lua is ever executed.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from engines.preprocessors import (
    Base64Preprocessor,
    HexPreprocessor,
    StringCharPreprocessor,
    StringConcatPreprocessor,
)
from engines.base import EngineStatus
from core.security import validate_public_url
from core.pipeline import sha256_text, process
from core.detector import detect


def test_base64():
    eng = Base64Preprocessor()
    src = 'local x = "SGVsbG8gV29ybGQhISE="'  # "Hello World!!!"
    r = eng.run(src, "/tmp")
    assert r.status == EngineStatus.SUCCESS
    assert "Hello World!!!" in (r.output or "")


def test_hex():
    eng = HexPreprocessor()
    src = 'local x = "48656c6c6f576f726c64"'  # HelloWorld
    r = eng.run(src, "/tmp")
    assert r.status == EngineStatus.SUCCESS
    assert "HelloWorld" in (r.output or "")


def test_string_char():
    eng = StringCharPreprocessor()
    src = "local x = string.char(72,101,108,108,111)"
    r = eng.run(src, "/tmp")
    assert r.status == EngineStatus.SUCCESS
    assert "Hello" in (r.output or "")


def test_concat():
    eng = StringConcatPreprocessor()
    src = 'local x = "Hel" .. "lo"'
    r = eng.run(src, "/tmp")
    assert r.status == EngineStatus.SUCCESS
    assert '"Hello"' in (r.output or "")


def test_ssrf_localhost():
    try:
        validate_public_url("http://127.0.0.1/secret")
        assert False, "should have raised"
    except ValueError:
        pass


def test_ssrf_private():
    try:
        validate_public_url("http://192.168.1.1/")
        assert False, "should have raised"
    except ValueError:
        pass


def test_sha_loop_protection():
    src = 'print("hello")'
    report = process(src, Path("/tmp"), "t.lua", [])
    # no change → failed, no output file
    assert report.status == "failed"
    assert report.output_filename is None


def test_partial_status():
    src = 'local x = "SGVsbG8gV29ybGQhISE="'
    report = process(src, Path("/tmp"), "t.lua", detect(src))
    assert report.status == "partial"
    assert report.output_filename and report.output_filename.endswith("_partial.lua")


if __name__ == "__main__":
    test_base64()
    test_hex()
    test_string_char()
    test_concat()
    test_ssrf_localhost()
    test_ssrf_private()
    test_sha_loop_protection()
    test_partial_status()
    print("All tests passed")
