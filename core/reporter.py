"""Helpers for writing report.json and deciding Discord message."""

from __future__ import annotations

import json
from pathlib import Path

from .pipeline import PipelineReport


def write_report(report: PipelineReport, path: Path) -> None:
    data = {
        "status": report.status,
        "detected": report.detected,
        "engines": report.engines,
        "rounds": report.rounds,
        "pipeline": report.pipeline,
        "input": report.input,
        "output": report.output,
        "errors": report.errors,
    }
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def build_discord_message(report: PipelineReport) -> str:
    if report.status == "partial":
        engines = ", ".join(report.engines["success"]) or "-"
        return (
            f"⚠️ ถอดได้บางส่วน (partial)\n\n"
            f"Status: `partial`\n"
            f"Engine ที่ทำงานได้:\n`{engines}`\n\n"
            f"Rounds: `{report.rounds}`\n"
            f"Output: `{report.output_filename}`\n\n"
            f"(ผลลัพธ์มาจาก preprocessor เท่านั้น — ไม่ใช่ full deobfuscation)"
        )

    # failed
    unavailable = ", ".join(report.engines["unavailable"][:5]) or "-"
    return (
        f"❌ ไม่สามารถถอดได้\n\n"
        f"Status: `failed`\n"
        f"Rounds: `{report.rounds}`\n"
        f"Engine ที่ unavailable (ตัวอย่าง):\n`{unavailable}`\n\n"
        f"ดูรายละเอียดใน report.json"
    )
