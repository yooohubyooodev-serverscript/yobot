"""Static-only preprocessors / normalizers.

These are NOT full deobfuscators. They only reverse common string
encodings that appear in many obfuscated scripts. They never execute
any code from the input.
"""

from __future__ import annotations

import base64
import re
from urllib.parse import unquote

from .base import BaseEngine, EngineResult, EngineStatus


def _text_score(text: str) -> float:
    if not text:
        return 0.0
    good = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    return good / len(text)


class Base64Preprocessor(BaseEngine):
    name = "Base64 preprocessor"

    def can_handle(self, source: str) -> bool:
        return bool(re.search(r"[A-Za-z0-9+/]{16,}={0,2}", source))

    def run(self, source: str, work_dir: str) -> EngineResult:
        pattern = re.compile(
            r"""(["'])([A-Za-z0-9+/]{16,}={0,2})\1"""
        )
        changed = False

        def repl(m: re.Match) -> str:
            nonlocal changed
            value = m.group(2)
            try:
                raw = base64.b64decode(value, validate=True)
                decoded = raw.decode("utf-8")
                if _text_score(decoded) >= 0.80:
                    changed = True
                    return m.group(1) + decoded + m.group(1)
            except Exception:
                pass
            return m.group(0)

        result = pattern.sub(repl, source)
        if not changed:
            return EngineResult(
                status=EngineStatus.NO_CHANGE,
                output=source,
                message="No Base64 strings decoded",
                engine_name=self.name,
            )
        return EngineResult(
            status=EngineStatus.SUCCESS,
            output=result,
            message="Decoded one or more Base64 strings",
            engine_name=self.name,
        )


class HexPreprocessor(BaseEngine):
    name = "Hex preprocessor"

    def can_handle(self, source: str) -> bool:
        return bool(re.search(r"[0-9A-Fa-f]{16,}", source))

    def run(self, source: str, work_dir: str) -> EngineResult:
        pattern = re.compile(r"""(["'])([0-9A-Fa-f]{16,})\1""")
        changed = False

        def repl(m: re.Match) -> str:
            nonlocal changed
            value = m.group(2)
            if len(value) % 2:
                return m.group(0)
            try:
                decoded = bytes.fromhex(value).decode("utf-8")
                if _text_score(decoded) >= 0.80:
                    changed = True
                    return m.group(1) + decoded + m.group(1)
            except Exception:
                pass
            return m.group(0)

        result = pattern.sub(repl, source)
        if not changed:
            return EngineResult(
                status=EngineStatus.NO_CHANGE,
                output=source,
                message="No hex strings decoded",
                engine_name=self.name,
            )
        return EngineResult(
            status=EngineStatus.SUCCESS,
            output=result,
            message="Decoded one or more hex strings",
            engine_name=self.name,
        )


class LuaEscapePreprocessor(BaseEngine):
    name = "Lua escape preprocessor"

    def can_handle(self, source: str) -> bool:
        return "\\" in source

    def run(self, source: str, work_dir: str) -> EngineResult:
        pattern = re.compile(
            r"""(["'])(.*?\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|[nrt\\]).*?)\1"""
        )
        changed = False

        def repl(m: re.Match) -> str:
            nonlocal changed
            quote, value = m.group(1), m.group(2)
            try:
                decoded = bytes(value, "utf-8").decode("unicode_escape")
                if decoded != value:
                    changed = True
                    return quote + decoded + quote
            except Exception:
                pass
            return m.group(0)

        result = pattern.sub(repl, source)
        if not changed:
            return EngineResult(
                status=EngineStatus.NO_CHANGE,
                output=source,
                message="No escape sequences decoded",
                engine_name=self.name,
            )
        return EngineResult(
            status=EngineStatus.SUCCESS,
            output=result,
            message="Decoded Lua escape sequences",
            engine_name=self.name,
        )


class StringCharPreprocessor(BaseEngine):
    name = "string.char preprocessor"

    def can_handle(self, source: str) -> bool:
        return "string.char" in source.lower()

    def run(self, source: str, work_dir: str) -> EngineResult:
        pattern = re.compile(
            r"string\.char\s*\(\s*((?:\d{1,3}\s*,?\s*)+)\)"
        )
        changed = False

        def repl(m: re.Match) -> str:
            nonlocal changed
            try:
                nums = [int(x) for x in re.findall(r"\d+", m.group(1))]
                if not nums or not all(0 <= n <= 255 for n in nums):
                    return m.group(0)
                decoded = "".join(chr(n) for n in nums)
                changed = True
                return repr(decoded)
            except Exception:
                return m.group(0)

        result = pattern.sub(repl, source)
        if not changed:
            return EngineResult(
                status=EngineStatus.NO_CHANGE,
                output=source,
                message="No string.char calls expanded",
                engine_name=self.name,
            )
        return EngineResult(
            status=EngineStatus.SUCCESS,
            output=result,
            message="Expanded string.char calls",
            engine_name=self.name,
        )


class StringConcatPreprocessor(BaseEngine):
    name = "String concat preprocessor"

    def can_handle(self, source: str) -> bool:
        return ".." in source

    def run(self, source: str, work_dir: str) -> EngineResult:
        pattern = re.compile(r'"([^"\n]*)"\s*\.\.\s*"([^"\n]*)"')
        result, count = pattern.subn(
            lambda m: '"' + m.group(1) + m.group(2) + '"',
            source,
        )
        if count == 0:
            return EngineResult(
                status=EngineStatus.NO_CHANGE,
                output=source,
                message="No simple string concatenations found",
                engine_name=self.name,
            )
        return EngineResult(
            status=EngineStatus.SUCCESS,
            output=result,
            message=f"Folded {count} string concatenations",
            engine_name=self.name,
        )
