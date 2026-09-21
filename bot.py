"""
Discord Lua/Luau deobfuscation bot.

Only static preprocessors are active. Advanced engines are reported
as unavailable with documented reasons. No untrusted Lua is ever
executed.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import uuid
from pathlib import Path

import discord
from discord import app_commands
from discord.ext import commands

from core.detector import detect
from core.downloader import download_url, MAX_FILE_SIZE
from core.pipeline import process
from core.reporter import build_discord_message, write_report

TOKEN = os.getenv("DISCORD_TOKEN")
WORK_ROOT = Path("work")
WORK_ROOT.mkdir(exist_ok=True)

intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)


def clean_filename(name: str) -> str:
    name = Path(name).name
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return name or "input.lua"


@bot.tree.command(name="deobf", description="ถอด/วิเคราะห์ Lua หรือ Luau (static only)")
@app_commands.describe(
    url="URL ของไฟล์ Lua/Luau",
    file="ไฟล์ .lua หรือ .luau",
)
async def deobf(
    interaction: discord.Interaction,
    url: str | None = None,
    file: discord.Attachment | None = None,
):
    if url and file:
        await interaction.response.send_message(
            "❌ เลือก URL หรือไฟล์อย่างใดอย่างหนึ่ง",
            ephemeral=True,
        )
        return
    if not url and not file:
        await interaction.response.send_message(
            "❌ ใส่ URL หรือแนบไฟล์",
            ephemeral=True,
        )
        return

    await interaction.response.defer()

    job_id = str(uuid.uuid4())
    work_dir = WORK_ROOT / job_id
    work_dir.mkdir(parents=True, exist_ok=True)

    try:
        # ---- input ----
        if url:
            data, filename = await download_url(url)
        else:
            if file.size and file.size > MAX_FILE_SIZE:
                raise ValueError("ไฟล์ใหญ่เกิน 10 MB")
            data = await file.read()
            if len(data) > MAX_FILE_SIZE:
                raise ValueError("ไฟล์ใหญ่เกิน 10 MB")
            filename = file.filename or "input.lua"

        source = data.decode("utf-8", errors="replace")
        if not source.strip():
            raise ValueError("ไฟล์ว่าง")

        safe_name = clean_filename(filename)
        detected = detect(source)

        # ---- pipeline (CPU-bound → thread) ----
        report = await asyncio.to_thread(
            process,
            source,
            work_dir,
            safe_name,
            detected,
        )

        # ---- write files ----
        report_path = work_dir / "report.json"
        write_report(report, report_path)

        files_to_send: list[discord.File] = [
            discord.File(report_path, filename="report.json"),
        ]

        if report.output_filename and report.final_source:
            out_path = work_dir / report.output_filename
            out_path.write_text(report.final_source, encoding="utf-8")
            files_to_send.insert(
                0,
                discord.File(out_path, filename=report.output_filename),
            )

        msg = build_discord_message(report)
        await interaction.followup.send(content=msg, files=files_to_send)

    except Exception as exc:
        await interaction.followup.send(
            f"❌ เกิดข้อผิดพลาด:\n```text\n{str(exc)[:3000]}\n```"
        )
    finally:
        # cleanup job directory
        try:
            shutil.rmtree(work_dir, ignore_errors=True)
        except Exception:
            pass


@bot.event
async def on_ready():
    try:
        synced = await bot.tree.sync()
        print(f"Bot: {bot.user}")
        print(f"Slash commands: {len(synced)}")
    except Exception as exc:
        print(f"Sync error: {exc}")


if not TOKEN:
    raise RuntimeError("DISCORD_TOKEN is not set")

bot.run(TOKEN)
