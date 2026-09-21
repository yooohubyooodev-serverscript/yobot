from __future__ import annotations

import base64
import binascii
import re

from .base import BaseEngine, EngineResult, EngineStatus


class Base64Preprocessor(BaseEngine):
    name = "base64"

    _pattern = re.compile(
        r'(?P<quote>["\'])(?P<data>[A-Za-z0-9+/]{16,}={0,2})(?P=quote)'
    )

    def can_handle(self, source: str) -> bool:
        for match in self._pattern.finditer(source):
            data = match.group("data")
            try:
                decoded = base64.b64decode(data, validate=True)
                if decoded and any(32 <= b < 127 for b in decoded):
                    return True
            except Exception:
                pass
        return False

    def run(self, source: str) -> EngineResult:
        changed = False

        def replace(match: re.Match) -> str:
            nonlocal changed

            data = match.group("data")

            try:
                decoded = base64.b64decode(data, validate=True)

                if not decoded:
                    return match.group(0)

                text = decoded.decode("utf-8")

                if not text:
                    return match.group(0)

                changed = True
                return repr(text)

            except Exception:
                return match.group(0)

        output = self._pattern.sub(replace, source)

        return EngineResult(
            status=(
                EngineStatus.SUCCESS
                if changed
                else EngineStatus.NO_CHANGE
            ),
            output=output,
            message="Base64 decoded" if changed else "No Base64 found",
        )


class HexPreprocessor(BaseEngine):
    name = "hex"

    _pattern = re.compile(
        r'(?P<quote>["\'])(?P<data>[0-9a-fA-F]{16,})(?P=quote)'
    )

    def can_handle(self, source: str) -> bool:
        return bool(self._pattern.search(source))

    def run(self, source: str) -> EngineResult:
        changed = False

        def replace(match: re.Match) -> str:
            nonlocal changed

            data = match.group("data")

            if len(data) % 2 != 0:
                return match.group(0)

            try:
                decoded = bytes.fromhex(data)
                text = decoded.decode("utf-8")

                if not text:
                    return match.group(0)

                changed = True
                return repr(text)

            except Exception:
                return match.group(0)

        output = self._pattern.sub(replace, source)

        return EngineResult(
            status=(
                EngineStatus.SUCCESS
                if changed
                else EngineStatus.NO_CHANGE
            ),
            output=output,
            message="Hex decoded" if changed else "No Hex found",
        )


class LuaEscapePreprocessor(BaseEngine):
    name = "lua_escape"

    _pattern = re.compile(
        r'\\(?:x[0-9a-fA-F]{2}|[0-9]{1,3})'
    )

    def can_handle(self, source: str) -> bool:
        return bool(self._pattern.search(source))

    def run(self, source: str) -> EngineResult:
        if not self.can_handle(source):
            return EngineResult(
                status=EngineStatus.NO_CHANGE,
                output=source,
                message="No Lua escapes found",
            )

        try:
            output = re.sub(
                r'\\x([0-9a-fA-F]{2})',
                lambda m: chr(int(m.group(1), 16)),
                source,
            )

            output = re.sub(
                r'\\([0-9]{1,3})',
                lambda m: chr(int(m.group(1), 10))
                if int(m.group(1), 10) <= 255
                else m.group(0),
                output,
            )

            return EngineResult(
                status=(
                    EngineStatus.SUCCESS
                    if output != source
                    else EngineStatus.NO_CHANGE
                ),
                output=output,
                message="Lua escapes decoded",
            )

        except Exception as exc:
            return EngineResult(
                status=EngineStatus.ERROR,
                output=source,
                message=str(exc),
            )


class StringCharPreprocessor(BaseEngine):
    name = "string.char"

    _pattern = re.compile(
        r'string\.char\s*\(\s*'
        r'((?:\d{1,3}\s*,\s*)+\d{1,3})'
        r'\s*\)'
    )

    def can_handle(self, source: str) -> bool:
        return bool(self._pattern.search(source))

    def run(self, source: str) -> EngineResult:
        changed = False

        def replace(match: re.Match) -> str:
            nonlocal changed

            numbers = re.findall(r"\d{1,3}", match.group(1))

            try:
                values = [int(n) for n in numbers]

                if any(n > 255 for n in values):
                    return match.group(0)

                decoded = "".join(chr(n) for n in values)

                changed = True
                return repr(decoded)

            except Exception:
                return match.group(0)

        output = self._pattern.sub(replace, source)

        return EngineResult(
            status=(
                EngineStatus.SUCCESS
                if changed
                else EngineStatus.NO_CHANGE
            ),
            output=output,
            message=(
                "string.char decoded"
                if changed
                else "No string.char found"
            ),
        )


class StringConcatPreprocessor(BaseEngine):
    name = "string_concat"

    _pattern = re.compile(
        r'(["\'])(.*?)\1\s*\.\s*(["\'])(.*?)\3'
    )

    def can_handle(self, source: str) -> bool:
        return bool(self._pattern.search(source))

    def run(self, source: str) -> EngineResult:
        changed = False

        def replace(match: re.Match) -> str:
            nonlocal changed
            changed = True
            return repr(match.group(2) + match.group(4))

        output = self._pattern.sub(replace, source)

        return EngineResult(
            status=(
                EngineStatus.SUCCESS
                if changed
                else EngineStatus.NO_CHANGE
            ),
            output=output,
            message=(
                "String concatenation simplified"
                if changed
                else "No string concatenation found"
            ),
        )


class BinaryPreprocessor(BaseEngine):
    name = "binary"

    # ตัวอย่าง:
    # 01001000 01100101 01101100 01101100 01101111
    #
    # รองรับทั้งข้อความที่อยู่ตรง ๆ
    # และข้อความที่อยู่ใน string ของ Lua
    _pattern = re.compile(
        r'(?<![01])'
        r'((?:[01]{8}\s+){1,}[01]{8})'
        r'(?![01])'
    )

    def can_handle(self, source: str) -> bool:
        return bool(self._pattern.search(source))

    def run(self, source: str) -> EngineResult:
        changed = False

        def replace(match: re.Match) -> str:
            nonlocal changed

            binary_text = match.group(1)
            values = binary_text.split()

            try:
                decoded = bytes(
                    int(value, 2)
                    for value in values
                )

                text = decoded.decode("utf-8")

                if not text:
                    return match.group(0)

                changed = True
                return text

            except (ValueError, UnicodeDecodeError):
                return match.group(0)

        output = self._pattern.sub(replace, source)

        return EngineResult(
            status=(
                EngineStatus.SUCCESS
                if changed
                else EngineStatus.NO_CHANGE
            ),
            output=output,
            message=(
                "Binary decoded"
                if changed
                else "No binary sequence found"
            ),
        )


# ---------------------------------------------------------
# รายการ Preprocessors ที่ Pipeline จะเรียกใช้งาน
# ---------------------------------------------------------

PREPROCESSORS = [
    BinaryPreprocessor(),
    Base64Preprocessor(),
    HexPreprocessor(),
    LuaEscapePreprocessor(),
    StringCharPreprocessor(),
    StringConcatPreprocessor(),
]
