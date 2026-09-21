"""
Discord Lua/Luau deobfuscation bot.

Static preprocessors only.
No untrusted Lua/Luau code is executed.
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


async def read_discord_attachment(
    attachment: discord.Attachment,
) -> tuple[bytes, str]:

    if attachment.size and attachment.size > MAX_FILE_SIZE:
        raise ValueError("ไฟล์ใหญ่เกิน 10 MB")

    last_error: Exception | None = None

    # ลองดาวน์โหลดสูงสุด 3 ครั้ง
    for attempt in range(1, 4):
        try:
            data = await attachment.read(use_cached=False)

            if not data:
                raise ValueError("ไฟล์ว่าง")

            if len(data) > MAX_FILE_SIZE:
                raise ValueError("ไฟล์ใหญ่เกิน 10 MB")

            filename = attachment.filename or "input.lua"

            return data, filename

        except Exception as exc:
            last_error = exc

            if attempt < 3:
                await asyncio.sleep(2)

    raise RuntimeError(
        f"ไม่สามารถดาวน์โหลดไฟล์จาก Discord ได้หลังจากลอง 3 ครั้ง: "
        f"{last_error}"
    )


@bot.tree.command(
    name="deobf",
    description="ถอด/วิเคราะห์ Lua หรือ Luau (static only)",
)
@app_commands.describe(
    url="URL ของไฟล์ Lua/Luau",
    file="ไฟล์ .lua หรือ .luau",
)
async def deobf(
    interaction: discord.Interaction,
    url: str | None = None,
    file: discord.Attachment | None = None,
):

    # ต้องเลือกอย่างใดอย่างหนึ่ง
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

        # =========================================================
        # INPUT
        # =========================================================

        if url:

            data, filename = await download_url(url)

        else:

            # ดาวน์โหลดไฟล์จาก Discord พร้อม Retry
            data, filename = await read_discord_attachment(file)

        # =========================================================
        # DECODE INPUT
        # =========================================================

        source = data.decode(
            "utf-8",
            errors="replace",
        )

        if not source.strip():
            raise ValueError("ไฟล์ว่าง")

        safe_name = clean_filename(filename)

        # =========================================================
        # DETECTION
        # =========================================================

        detected = detect(source)

        # =========================================================
        # PIPELINE
        # =========================================================

        report = await asyncio.to_thread(
            process,
            source,
            work_dir,
            safe_name,
            detected,
        )

        # =========================================================
        # REPORT
        # =========================================================

        report_path = work_dir / "report.json"

        write_report(
            report,
            report_path,
        )

        # =========================================================
        # FILES TO SEND
        # =========================================================

        files_to_send: list[discord.File] = [
            discord.File(
                report_path,
                filename="report.json",
            )
        ]

        # =========================================================
        # OUTPUT
        # =========================================================

        if report.output_filename and report.final_source:

            out_path = work_dir / report.output_filename

            out_path.write_text(
                report.final_source,
                encoding="utf-8",
            )

            files_to_send.insert(
                0,
                discord.File(
                    out_path,
                    filename=report.output_filename,
                ),
            )

        # =========================================================
        # SEND RESULT
        # =========================================================

        msg = build_discord_message(report)

        await interaction.followup.send(
            content=msg,
            files=files_to_send,
        )

    except Exception as exc:

        error_text = str(exc)

        await interaction.followup.send(
            "❌ เกิดข้อผิดพลาด:\n"
            "```text\n"
            f"{error_text[:3000]}\n"
            "```"
        )

    finally:

        # ลบไฟล์ชั่วคราวหลังจบงาน
        try:
            shutil.rmtree(
                work_dir,
                ignore_errors=True,
            )
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


# =============================================================
# TOKEN CHECK
# =============================================================

if not TOKEN:
    raise RuntimeError(
        "DISCORD_TOKEN is not set"
    )


# =============================================================
# START BOT
# =============================================================

bot.run(TOKEN)N)
