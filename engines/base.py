"""Base engine interface for the deobfuscation pipeline."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class EngineStatus(str, Enum):
    SUCCESS = "success"
    NO_CHANGE = "no_change"
    UNSUPPORTED = "unsupported"
    UNAVAILABLE = "unavailable"
    ERROR = "error"
    TIMEOUT = "timeout"


@dataclass
class EngineResult:
    status: EngineStatus
    output: Optional[str] = None
    message: str = ""
    engine_name: str = ""
    extra: dict = field(default_factory=dict)


class BaseEngine(ABC):
    """
    Common interface every engine must implement.

    name            - human readable name
    is_available()  - True only if runtime/deps are actually present
    can_handle()    - quick static check whether this engine might apply
    run()           - perform the work and return EngineResult
    """

    name: str = "BaseEngine"

    def is_available(self) -> bool:
        """Return True only when the engine can actually run."""
        return True

    def can_handle(self, source: str) -> bool:
        """Cheap heuristic – does not guarantee success."""
        return True

    @abstractmethod
    def run(self, source: str, work_dir: str) -> EngineResult:
        """
        Process source. Must never execute untrusted Lua.
        work_dir is a unique temporary directory for this job.
        """
        raise NotImplementedError
