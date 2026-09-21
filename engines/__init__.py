"""Engine registry.

Only engines that are actually implemented and safe are registered.
Advanced deobfuscators (Luraph, MoonSec, IronBrew, Luarmor, VMP …)
are listed here as unavailable with documented reasons.
"""

from __future__ import annotations

from .base import BaseEngine, EngineResult, EngineStatus
from .preprocessors import (
    Base64Preprocessor,
    HexPreprocessor,
    LuaEscapePreprocessor,
    StringCharPreprocessor,
    StringConcatPreprocessor,
)

# Real, safe, static-only preprocessors
PREPROCESSORS: list[BaseEngine] = [
    Base64Preprocessor(),
    HexPreprocessor(),
    LuaEscapePreprocessor(),
    StringCharPreprocessor(),
    StringConcatPreprocessor(),
]

# Advanced engines – currently unavailable (see reasons below)
UNAVAILABLE_ENGINES: list[dict] = [
    {
        "name": "Luraph / Luau-VMP",
        "reason": (
            "binxgtl/luau-vmp-deobf is archived (Aug 2026) and relies on "
            "sandbox execution of parts of the input script. Violates the "
            "no-execution-of-untrusted-Lua policy."
        ),
    },
    {
        "name": "Prometheus / WeAreDevs",
        "reason": (
            "hutaoshusband/Prometheus-WeAre-Devs-Dumper executes Lua 5.1 "
            "under a mock environment. Violates the no-execution policy."
        ),
    },
    {
        "name": "Luraph-deobfuscator-py (mehCake)",
        "reason": (
            "Source was deleted by the author; README states the project "
            "is not working."
        ),
    },
    {
        "name": "Unluau (atrexus)",
        "reason": (
            ".NET Luau bytecode decompiler. Requires compiled Luau "
            "bytecode as input; most Discord uploads are source. "
            "Not integrated because binary build + runtime is not "
            "currently packaged in this bot."
        ),
    },
    {
        "name": "luauDec (xgladius)",
        "reason": (
            "C++ decompiler that needs a full CMake + Luau submodule "
            "build. Not packaged in the current Docker image."
        ),
    },
    {
        "name": "MoonSec deobfuscators",
        "reason": (
            "Existing open-source ports either execute Lua via NLua "
            "or require complex .NET / Node + native binaries that "
            "are not safely integrated yet."
        ),
    },
    {
        "name": "VortexDQ / other bytecode decompilers",
        "reason": (
            "Operate on Luau bytecode, not on typical obfuscated "
            "source. Integration deferred until a reliable source→bytecode "
            "path that never executes untrusted code is available."
        ),
    },
]


def get_all_engines() -> list[BaseEngine]:
    """Return the ordered list of engines the pipeline will try."""
    return list(PREPROCESSORS)


def get_unavailable_report() -> list[dict]:
    return list(UNAVAILABLE_ENGINES)
