"""Deobfuscation pipeline with loop protection and honest status."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from engines import get_all_engines, get_unavailable_report
from engines.base import EngineResult, EngineStatus


MAX_ROUNDS = 8
MAX_OUTPUT_SIZE = 10 * 1024 * 1024
MAX_PIPELINE_SECONDS = 60


def sha256_text(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    return hashlib.sha256(data).hexdigest()


@dataclass
class PipelineReport:
    status: str = "failed"  # success | partial | failed
    detected: list[dict] = field(default_factory=list)
    engines: dict[str, list] = field(default_factory=lambda: {
        "success": [],
        "no_change": [],
        "unsupported": [],
        "unavailable": [],
        "error": [],
        "timeout": [],
    })
    rounds: int = 0
    pipeline: list[dict] = field(default_factory=list)
    input: dict = field(default_factory=dict)
    output: dict = field(default_factory=dict)
    errors: list[dict] = field(default_factory=list)
    final_source: str = ""
    output_filename: str | None = None  # None means do not emit a deobfuscated file


def process(
    source: str,
    work_dir: Path,
    original_filename: str,
    detected: list[dict],
) -> PipelineReport:
    report = PipelineReport()
    report.detected = detected
    report.input = {
        "filename": original_filename,
        "sha256": sha256_text(source),
    }

    # Record permanently unavailable advanced engines
    for item in get_unavailable_report():
        report.engines["unavailable"].append(item["name"])
        report.pipeline.append({
            "engine": item["name"],
            "status": "unavailable",
            "message": item["reason"],
        })

    engines = get_all_engines()
    current = source
    seen = {sha256_text(current)}
    start = time.monotonic()
    any_success = False
    round_no = 0

    for round_no in range(1, MAX_ROUNDS + 1):
        if time.monotonic() - start > MAX_PIPELINE_SECONDS:
            report.errors.append({"round": round_no, "error": "pipeline timeout"})
            break

        changed_this_round = False

        for engine in engines:
            if time.monotonic() - start > MAX_PIPELINE_SECONDS:
                break

            entry: dict[str, Any] = {
                "round": round_no,
                "engine": engine.name,
            }

            if not engine.is_available():
                entry["status"] = "unavailable"
                entry["message"] = "runtime not present"
                report.engines["unavailable"].append(engine.name)
                report.pipeline.append(entry)
                continue

            if not engine.can_handle(current):
                entry["status"] = "unsupported"
                report.engines["unsupported"].append(engine.name)
                report.pipeline.append(entry)
                continue

            try:
                result: EngineResult = engine.run(current, str(work_dir))
            except Exception as exc:
                entry["status"] = "error"
                entry["message"] = str(exc)[:500]
                report.engines["error"].append(engine.name)
                report.errors.append({
                    "round": round_no,
                    "engine": engine.name,
                    "error": str(exc)[:500],
                })
                report.pipeline.append(entry)
                continue

            entry["status"] = result.status.value
            entry["message"] = result.message

            if result.status == EngineStatus.SUCCESS and result.output:
                digest = sha256_text(result.output)
                if digest in seen:
                    entry["status"] = "loop"
                    report.pipeline.append(entry)
                    continue
                if len(result.output) > MAX_OUTPUT_SIZE:
                    entry["status"] = "error"
                    entry["message"] = "output too large"
                    report.engines["error"].append(engine.name)
                    report.pipeline.append(entry)
                    continue

                seen.add(digest)
                current = result.output
                changed_this_round = True
                any_success = True
                if engine.name not in report.engines["success"]:
                    report.engines["success"].append(engine.name)
            elif result.status == EngineStatus.NO_CHANGE:
                if engine.name not in report.engines["no_change"]:
                    report.engines["no_change"].append(engine.name)
            elif result.status == EngineStatus.TIMEOUT:
                report.engines["timeout"].append(engine.name)
            elif result.status == EngineStatus.ERROR:
                report.engines["error"].append(engine.name)
                report.errors.append({
                    "round": round_no,
                    "engine": engine.name,
                    "error": result.message,
                })
            elif result.status == EngineStatus.UNSUPPORTED:
                report.engines["unsupported"].append(engine.name)
            elif result.status == EngineStatus.UNAVAILABLE:
                report.engines["unavailable"].append(engine.name)

            report.pipeline.append(entry)

        if not changed_this_round:
            break

    report.rounds = round_no
    report.final_source = current

    # Decide final status and whether to emit a file
    if any_success and current != source:
        # Preprocessors only → treat as partial, never full success
        report.status = "partial"
        stem = Path(original_filename).stem
        report.output_filename = f"{stem}_partial.lua"
        report.output = {
            "filename": report.output_filename,
            "sha256": sha256_text(current),
        }
    else:
        report.status = "failed"
        report.output_filename = None  # do NOT emit a deobfuscated/partial file
        report.output = {
            "filename": None,
            "sha256": None,
        }

    return report
