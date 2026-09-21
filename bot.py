import os
import re
import json
import base64
import hashlib
import asyncio
from pathlib import Path
from urllib.parse import urlparse, unquote
from ipaddress import ip_address

import aiohttp
import discord
from discord import app_commands
from discord.ext import commands


# ============================================================
# CONFIG
# ============================================================

TOKEN = os.getenv("DISCORD_TOKEN")

MAX_FILE_SIZE = 10 * 1024 * 1024
MAX_OUTPUT_SIZE = 10 * 1024 * 1024
MAX_ROUNDS = 15
DOWNLOAD_TIMEOUT = 30

WORK_DIR = Path("work")
WORK_DIR.mkdir(exist_ok=True)


# ============================================================
# DISCORD
# ============================================================

intents = discord.Intents.default()

bot = commands.Bot(
    command_prefix="!",
    intents=intents
)


# ============================================================
# HELPERS
# ============================================================

def sha256(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    return hashlib.sha256(data).hexdigest()


def clean_filename(name: str) -> str:
    name = Path(name).name
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return name or "input.lua"


def text_score(text: str) -> float:
    if not text:
        return 0.0
    good = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    return good / len(text)


def decode_bytes(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def changed(old: str, new: str) -> bool:
    return isinstance(new, str) and new.strip() and new != old


# ============================================================
# URL SAFETY
# ============================================================

def valid_public_host(host: str) -> bool:
    if not host:
        return False

    host = host.lower()

    if host in ("localhost", "localhost.localdomain"):
        return False

    try:
        ip = ip_address(host)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        ):
            return False
    except ValueError:
        pass

    return True


async def download_url(url: str) -> tuple[bytes, str]:
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("URL ต้องเป็น http:// หรือ https://")

    if not valid_public_host(parsed.hostname):
        raise ValueError("URL นี้ไม่อนุญาตให้เข้าถึง")

    timeout = aiohttp.ClientTimeout(total=DOWNLOAD_TIMEOUT)
    headers = {"User-Agent": "Discord-Lua-Deobfuscator/1.0"}

    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        async with session.get(url, allow_redirects=True) as response:
            if response.status != 200:
                raise ValueError(f"ดาวน์โหลดไม่สำเร็จ HTTP {response.status}")

            final_host = urlparse(str(response.url)).hostname
            if not valid_public_host(final_host):
                raise ValueError("ปลายทาง redirect ไม่อนุญาต")

            length = response.headers.get("Content-Length")
            if length:
                try:
                    if int(length) > MAX_FILE_SIZE:
                        raise ValueError("ไฟล์ใหญ่เกิน 10 MB")
                except ValueError as e:
                    if "ใหญ่เกิน" in str(e):
                        raise

            data = await response.read()

            if len(data) > MAX_FILE_SIZE:
                raise ValueError("ไฟล์ใหญ่เกิน 10 MB")

            filename = (
                Path(urlparse(str(response.url)).path).name or "input.lua"
            )

            return data, filename


# ============================================================
# DETECTOR
# ============================================================

def detect(source: str) -> list[str]:
    text = source.lower()

    signatures = {
        "Luraph": ["luraph", "lph", "initv4"],
        "LuaU VMP": ["luau", "opcode", "vm"],
        "MoonSec": ["moonsec"],
        "IronBrew": ["ironbrew", "getfenv", "setfenv"],
        "Prometheus": ["prometheus"],
        "Luarmor": ["luarmor"],
        "WeAreDevs": ["wearedevs"],
        "Veil": ["veil"],
        "Base64": ["base64"],
    }

    found = []
    for name, patterns in signatures.items():
        if any(p in text for p in patterns):
            found.append(name)

    return found


# ============================================================
# ENGINE 1 - BASE64
# ============================================================

def engine_base64(source: str) -> str:
    pattern = re.compile(
        r"""(["'])([A-Za-z0-9+/]{16,}={0,2})\1"""
    )
    success = False

    def replace(match):
        nonlocal success
        value = match.group(2)
        try:
            raw = base64.b64decode(value, validate=True)
            decoded = raw.decode("utf-8")
            if text_score(decoded) >= 0.80:
                success = True
                return match.group(1) + decoded + match.group(1)
        except Exception:
            pass
        return match.group(0)

    result = pattern.sub(replace, source)
    if not success:
        raise RuntimeError("Base64 engine ไม่พบข้อมูล")
    return result


# ============================================================
# ENGINE 2 - HEX
# ============================================================

def engine_hex(source: str) -> str:
    pattern = re.compile(
        r"""(["'])([0-9A-Fa-f]{16,})\1"""
    )
    success = False

    def replace(match):
        nonlocal success
        value = match.group(2)
        if len(value) % 2:
            return match.group(0)
        try:
            decoded = bytes.fromhex(value).decode("utf-8")
            if text_score(decoded) >= 0.80:
                success = True
                return match.group(1) + decoded + match.group(1)
        except Exception:
            pass
        return match.group(0)

    result = pattern.sub(replace, source)
    if not success:
        raise RuntimeError("Hex engine ไม่พบข้อมูล")
    return result


# ============================================================
# ENGINE 3 - URL ENCODING
# ============================================================

def engine_url(source: str) -> str:
    pattern = re.compile(r"""(["'])(.*?)\1""")
    success = False

    def replace(match):
        nonlocal success
        value = match.group(2)
        if "%" not in value:
            return match.group(0)
        decoded = unquote(value)
        if decoded != value and text_score(decoded) >= 0.80:
            success = True
            return match.group(1) + decoded + match.group(1)
        return match.group(0)

    result = pattern.sub(replace, source)
    if not success:
        raise RuntimeError("URL decoder ไม่พบข้อมูล")
    return result


# ============================================================
# ENGINE 4 - LUA ESCAPE
# ============================================================

def engine_escape(source: str) -> str:
    success = False

    def decode_match(match):
        nonlocal success
        quote = match.group(1)
        value = match.group(2)
        try:
            decoded = bytes(value, "utf-8").decode("unicode_escape")
            if decoded != value:
                success = True
                return quote + decoded + quote
        except Exception:
            pass
        return match.group(0)

    pattern = re.compile(
        r"""(["'])(.*?\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|n|r|t).*?)\1"""
    )
    result = pattern.sub(decode_match, source)
    if not success:
        raise RuntimeError("Escape decoder ไม่พบข้อมูล")
    return result


# ============================================================
# ENGINE 5 - BYTE ARRAY
# ============================================================

def engine_byte_array(source: str) -> str:
    pattern = re.compile(
        r"\[\s*((?:\d{1,3}\s*,\s*){7,}\d{1,3})\s*\]"
    )
    success = False

    def replace(match):
        nonlocal success
        try:
            numbers = [int(x.strip()) for x in match.group(1).split(",")]
            if not all(0 <= x <= 255 for x in numbers):
                return match.group(0)
            decoded = bytes(numbers).decode("utf-8")
            if text_score(decoded) >= 0.80:
                success = True
                return repr(decoded)
        except Exception:
            pass
        return match.group(0)

    result = pattern.sub(replace, source)
    if not success:
        raise RuntimeError("Byte-array decoder ไม่พบข้อมูล")
    return result


# ============================================================
# ENGINE 6 - SIMPLE STRING CONCAT
# ============================================================

def engine_string_concat(source: str) -> str:
    pattern = re.compile(r'"([^"\n]*)"\s*\.\.\s*"([^"\n]*)"')
    result, count = pattern.subn(
        lambda m: '"' + m.group(1) + m.group(2) + '"',
        source
    )
    if count == 0:
        raise RuntimeError("String concat ไม่พบข้อมูล")
    return result


# ============================================================
# ENGINE 7 - CONSTANT DECODER (string.char)
# ============================================================

def engine_constants(source: str) -> str:
    pattern = re.compile(
        r"string\.char\s*\(\s*((?:\d{1,3}\s*,?\s*)+)\)"
    )
    success = False

    def replace(match):
        nonlocal success
        try:
            nums = [int(x) for x in re.findall(r"\d+", match.group(1))]
            if not nums:
                return match.group(0)
            if not all(0 <= n <= 255 for n in nums):
                return match.group(0)
            result = "".join(chr(n) for n in nums)
            success = True
            return repr(result)
        except Exception:
            return match.group(0)

    result = pattern.sub(replace, source)
    if not success:
        raise RuntimeError("string.char decoder ไม่พบข้อมูล")
    return result


# ============================================================
# ENGINE PIPELINE
# ============================================================

ENGINES = [
    ("Base64", engine_base64),
    ("Hex", engine_hex),
    ("URL", engine_url),
    ("Lua Escape", engine_escape),
    ("Byte Array", engine_byte_array),
    ("String Concat", engine_string_concat),
    ("string.char", engine_constants),
]


def process(source: str):
    """
    Returns:
        result_source,
        history (list),
        success_engines (list[str]),
        error_engines (list[str]),
        unavailable_engines (list[str]),
        rounds (int),
        status (str: "success" | "partial" | "failed")
    """
    current = source
    seen = {sha256(current)}
    history = []

    success_engines = []
    error_engines = []
    # engines that never ran successfully and never errored meaningfully
    # (we treat ones that only produced "no data" as error)

    for round_no in range(1, MAX_ROUNDS + 1):
        changed_round = False

        for name, engine in ENGINES:
            before = current

            try:
                result = engine(before)

                if not changed(before, result):
                    raise RuntimeError("ผลลัพธ์ไม่เปลี่ยน")

                if len(result) > MAX_OUTPUT_SIZE:
                    raise RuntimeError("ผลลัพธ์ใหญ่เกินกำหนด")

                digest = sha256(result)

                if digest in seen:
                    history.append({
                        "round": round_no,
                        "engine": name,
                        "status": "loop"
                    })
                    continue

                seen.add(digest)
                current = result
                changed_round = True

                if name not in success_engines:
                    success_engines.append(name)

                history.append({
                    "round": round_no,
                    "engine": name,
                    "status": "success"
                })

            except Exception as exc:
                history.append({
                    "round": round_no,
                    "engine": name,
                    "status": "error",
                    "error": str(exc)
                })
                if name not in error_engines and name not in success_engines:
                    error_engines.append(name)
                continue

        if not changed_round:
            break

    rounds = max((x["round"] for x in history), default=0)

    # Determine overall status
    if success_engines:
        # If we made at least one successful transformation
        if current != source:
            status = "success"
        else:
            status = "partial"
    else:
        status = "failed"

    # Engines that never appeared in any success or error are unavailable
    all_engine_names = [name for name, _ in ENGINES]
    unavailable_engines = [
        name for name in all_engine_names
        if name not in success_engines and name not in error_engines
    ]

    return (
        current,
        history,
        success_engines,
        error_engines,
        unavailable_engines,
        rounds,
        status
    )


# ============================================================
# DISCORD COMMAND
# ============================================================

@bot.tree.command(
    name="deobf",
    description="ถอด/วิเคราะห์ Lua หรือ Luau"
)
@app_commands.describe(
    url="URL ของไฟล์ Lua/Luau",
    file="ไฟล์ Lua/Luau"
)
async def deobf(
    interaction: discord.Interaction,
    url: str | None = None,
    file: discord.Attachment | None = None
):
    if url and file:
        await interaction.response.send_message(
            "❌ เลือก URL หรือไฟล์อย่างใดอย่างหนึ่งครับ",
            ephemeral=True
        )
        return

    if not url and not file:
        await interaction.response.send_message(
            "❌ ใส่ URL หรือแนบไฟล์ก่อนครับ",
            ephemeral=True
        )
        return

    await interaction.response.defer()

    try:
        # ----------------------------------------------------
        # INPUT
        # ----------------------------------------------------
        if url:
            data, filename = await download_url(url)
        else:
            if file.size and file.size > MAX_FILE_SIZE:
                raise ValueError("ไฟล์ใหญ่เกิน 10 MB")
            data = await file.read()
            if len(data) > MAX_FILE_SIZE:
                raise ValueError("ไฟล์ใหญ่เกิน 10 MB")
            filename = file.filename

        source = decode_bytes(data)

        if not source.strip():
            raise ValueError("ไฟล์ว่าง")

        # ----------------------------------------------------
        # DETECT
        # ----------------------------------------------------
        detected = detect(source)

        # ----------------------------------------------------
        # RUN PIPELINE
        # ----------------------------------------------------
        (
            result,
            history,
            success_engines,
            error_engines,
            unavailable_engines,
            rounds,
            status
        ) = await asyncio.to_thread(process, source)

        # ----------------------------------------------------
        # SAVE OUTPUT FILES
        # ----------------------------------------------------
        safe = clean_filename(filename)
        stem = Path(safe).stem

        output_filename = f"{stem}_deobfuscated.lua"
        report_filename = f"{stem}_report.json"

        output_file = WORK_DIR / output_filename
        report_file = WORK_DIR / report_filename

        # Always write the final pipeline output (even if failed → original or partial)
        output_file.write_text(result, encoding="utf-8")

        report = {
            "status": status,
            "detected": detected,
            "engines": {
                "success": success_engines,
                "error": error_engines,
                "unavailable": unavailable_engines
            },
            "rounds": rounds,
            "input": {
                "filename": safe,
                "size": len(data),
                "sha256": sha256(data)
            },
            "output": {
                "filename": output_filename,
                "size": len(result.encode("utf-8", errors="replace")),
                "sha256": sha256(result)
            },
            "pipeline": history,
            "errors": [
                {
                    "round": h["round"],
                    "engine": h["engine"],
                    "error": h.get("error", "")
                }
                for h in history
                if h["status"] == "error"
            ]
        }

        report_file.write_text(
            json.dumps(report, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )

        # ----------------------------------------------------
        # BUILD DISCORD RESPONSE (ตามกฎที่กำหนด)
        # ----------------------------------------------------
        files_to_send = [
            discord.File(output_file, filename=output_filename),
            discord.File(report_file, filename=report_filename)
        ]

        if status == "success":
            engine_text = ", ".join(success_engines) if success_engines else "-"
            msg = (
                f"✅ ถอดเสร็จแล้ว\n\n"
                f"Engine:\n`{engine_text}`\n\n"
                f"Rounds:\n`{rounds}`\n\n"
                f"Output:\n`{output_filename}`"
            )
            await interaction.followup.send(content=msg, files=files_to_send)

        elif status == "partial":
            engine_text = ", ".join(success_engines) if success_engines else "-"
            msg = (
                f"⚠️ ถอดได้บางส่วน (partial)\n\n"
                f"Engine:\n`{engine_text}`\n\n"
                f"Rounds:\n`{rounds}`\n\n"
                f"Output:\n`{output_filename}`\n\n"
                f"(ผลลัพธ์เป็น partial — ไม่ใช่การถอดสำเร็จสมบูรณ์)"
            )
            await interaction.followup.send(content=msg, files=files_to_send)

        else:  # failed
            msg = (
                f"❌ ไม่สามารถถอดได้\n\n"
                f"Engine ที่ error:\n`{', '.join(error_engines) if error_engines else '-'}`\n\n"
                f"Rounds:\n`{rounds}`\n\n"
                f"ดูรายละเอียดใน `{report_filename}`"
            )
            # ยังส่งไฟล์ผลลัพธ์ (อาจเป็น source เดิม) + report ตามกฎ
            await interaction.followup.send(content=msg, files=files_to_send)

    except Exception as exc:
        await interaction.followup.send(
            "❌ เกิดข้อผิดพลาด:\n"
            f"```text\n{str(exc)[:3500]}\n```"
        )


# ============================================================
# READY
# ============================================================

@bot.event
async def on_ready():
    try:
        synced = await bot.tree.sync()
        print(f"Bot: {bot.user}")
        print(f"Slash commands: {len(synced)}")
    except Exception as exc:
        print(f"Sync error: {exc}")


# ============================================================
# START
# ============================================================

if not TOKEN:
    raise RuntimeError("DISCORD_TOKEN ยังไม่ได้ตั้งค่า")

bot.run(TOKEN)
