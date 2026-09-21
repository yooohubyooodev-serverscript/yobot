import os
import re
import json
import base64
import binascii
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

def sha256(data: str) -> str:
    return hashlib.sha256(
        data.encode("utf-8", errors="replace")
    ).hexdigest()


def clean_filename(name: str) -> str:
    name = Path(name).name

    name = re.sub(
        r"[^A-Za-z0-9._-]",
        "_",
        name
    )

    return name or "input.lua"


def text_score(text: str) -> float:
    if not text:
        return 0

    good = sum(
        1
        for c in text
        if c.isprintable() or c in "\r\n\t"
    )

    return good / len(text)


def decode_bytes(data: bytes) -> str:
    return data.decode(
        "utf-8",
        errors="replace"
    )


def changed(old: str, new: str) -> bool:
    return (
        isinstance(new, str)
        and new.strip()
        and new != old
    )


# ============================================================
# URL SAFETY
# ============================================================

def valid_public_host(host: str) -> bool:
    if not host:
        return False

    host = host.lower()

    if host in (
        "localhost",
        "localhost.localdomain"
    ):
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

    if parsed.scheme not in (
        "http",
        "https"
    ):
        raise ValueError(
            "URL ต้องเป็น http:// หรือ https://"
        )

    if not valid_public_host(
        parsed.hostname
    ):
        raise ValueError(
            "URL นี้ไม่อนุญาตให้เข้าถึง"
        )

    timeout = aiohttp.ClientTimeout(
        total=DOWNLOAD_TIMEOUT
    )

    headers = {
        "User-Agent":
        "Discord-Lua-Deobfuscator/1.0"
    }

    async with aiohttp.ClientSession(
        timeout=timeout,
        headers=headers
    ) as session:

        async with session.get(
            url,
            allow_redirects=True
        ) as response:

            if response.status != 200:
                raise ValueError(
                    f"ดาวน์โหลดไม่สำเร็จ HTTP {response.status}"
                )

            final_host = urlparse(
                str(response.url)
            ).hostname

            if not valid_public_host(
                final_host
            ):
                raise ValueError(
                    "ปลายทาง redirect ไม่อนุญาต"
                )

            length = response.headers.get(
                "Content-Length"
            )

            if length:

                try:
                    if int(length) > MAX_FILE_SIZE:
                        raise ValueError(
                            "ไฟล์ใหญ่เกิน 10 MB"
                        )
                except ValueError as e:
                    if "ใหญ่เกิน" in str(e):
                        raise

            data = await response.read()

            if len(data) > MAX_FILE_SIZE:
                raise ValueError(
                    "ไฟล์ใหญ่เกิน 10 MB"
                )

            filename = (
                Path(
                    urlparse(
                        str(response.url)
                    ).path
                ).name
                or "input.lua"
            )

            return data, filename


# ============================================================
# DETECTOR
# ============================================================

def detect(source: str) -> list[str]:

    text = source.lower()

    signatures = {
        "Luraph": [
            "luraph",
            "lph",
            "initv4"
        ],

        "LuaU VMP": [
            "luau",
            "opcode",
            "vm"
        ],

        "MoonSec": [
            "moonsec"
        ],

        "IronBrew": [
            "ironbrew",
            "getfenv",
            "setfenv"
        ],

        "Prometheus": [
            "prometheus"
        ],

        "Luarmor": [
            "luarmor"
        ],

        "WeAreDevs": [
            "wearedevs"
        ],

        "Veil": [
            "veil"
        ],

        "Base64": [
            "base64"
        ]
    }

    found = []

    for name, patterns in signatures.items():

        if any(
            p in text
            for p in patterns
        ):
            found.append(name)

    return found


# ============================================================
# ENGINE 1
# BASE64
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

            raw = base64.b64decode(
                value,
                validate=True
            )

            decoded = raw.decode(
                "utf-8"
            )

            if text_score(decoded) >= 0.80:

                success = True

                return (
                    match.group(1)
                    + decoded
                    + match.group(1)
                )

        except Exception:
            pass

        return match.group(0)

    result = pattern.sub(
        replace,
        source
    )

    if not success:
        raise RuntimeError(
            "Base64 engine ไม่พบข้อมูล"
        )

    return result


# ============================================================
# ENGINE 2
# HEX
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

            decoded = bytes.fromhex(
                value
            ).decode(
                "utf-8"
            )

            if text_score(decoded) >= 0.80:

                success = True

                return (
                    match.group(1)
                    + decoded
                    + match.group(1)
                )

        except Exception:
            pass

        return match.group(0)

    result = pattern.sub(
        replace,
        source
    )

    if not success:
        raise RuntimeError(
            "Hex engine ไม่พบข้อมูล"
        )

    return result


# ============================================================
# ENGINE 3
# URL ENCODING
# ============================================================

def engine_url(source: str) -> str:

    pattern = re.compile(
        r"""(["'])(.*?)\1"""
    )

    success = False

    def replace(match):

        nonlocal success

        value = match.group(2)

        if "%" not in value:
            return match.group(0)

        decoded = unquote(value)

        if (
            decoded != value
            and text_score(decoded) >= 0.80
        ):

            success = True

            return (
                match.group(1)
                + decoded
                + match.group(1)
            )

        return match.group(0)

    result = pattern.sub(
        replace,
        source
    )

    if not success:
        raise RuntimeError(
            "URL decoder ไม่พบข้อมูล"
        )

    return result


# ============================================================
# ENGINE 4
# LUA ESCAPE
# ============================================================

def engine_escape(source: str) -> str:

    success = False

    def decode_match(match):

        nonlocal success

        quote = match.group(1)
        value = match.group(2)

        try:

            decoded = bytes(
                value,
                "utf-8"
            ).decode(
                "unicode_escape"
            )

            if decoded != value:

                success = True

                return (
                    quote
                    + decoded
                    + quote
                )

        except Exception:
            pass

        return match.group(0)

    pattern = re.compile(
        r"""(["'])(.*?\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|n|r|t).*?)\1"""
    )

    result = pattern.sub(
        decode_match,
        source
    )

    if not success:
        raise RuntimeError(
            "Escape decoder ไม่พบข้อมูล"
        )

    return result


# ============================================================
# ENGINE 5
# BYTE ARRAY
# ============================================================

def engine_byte_array(source: str) -> str:

    pattern = re.compile(
        r"\[\s*((?:\d{1,3}\s*,\s*){7,}\d{1,3})\s*\]"
    )

    success = False

    def replace(match):

        nonlocal success

        try:

            numbers = [
                int(x.strip())
                for x in match.group(1).split(",")
            ]

            if not all(
                0 <= x <= 255
                for x in numbers
            ):
                return match.group(0)

            decoded = bytes(
                numbers
            ).decode(
                "utf-8"
            )

            if text_score(decoded) >= 0.80:

                success = True

                return repr(decoded)

        except Exception:
            pass

        return match.group(0)

    result = pattern.sub(
        replace,
        source
    )

    if not success:
        raise RuntimeError(
            "Byte-array decoder ไม่พบข้อมูล"
        )

    return result


# ============================================================
# ENGINE 6
# SIMPLE STRING CONCAT
# ============================================================

def engine_string_concat(source: str) -> str:

    pattern = re.compile(
        r'"([^"\n]*)"\s*\.\.\s*"([^"\n]*)"'
    )

    result, count = pattern.subn(
        lambda m: '"' + m.group(1) + m.group(2) + '"',
        source
    )

    if count == 0:
        raise RuntimeError(
            "String concat ไม่พบข้อมูล"
        )

    return result


# ============================================================
# ENGINE 7
# CONSTANT DECODER
# ============================================================

def engine_constants(source: str) -> str:

    pattern = re.compile(
        r"string\.char\s*\(\s*((?:\d{1,3}\s*,?\s*)+)\)"
    )

    success = False

    def replace(match):

        nonlocal success

        try:

            nums = [
                int(x)
                for x in re.findall(
                    r"\d+",
                    match.group(1)
                )
            ]

            if not nums:
                return match.group(0)

            if not all(
                0 <= n <= 255
                for n in nums
            ):
                return match.group(0)

            result = "".join(
                chr(n)
                for n in nums
            )

            success = True

            return repr(result)

        except Exception:
            return match.group(0)

    result = pattern.sub(
        replace,
        source
    )

    if not success:
        raise RuntimeError(
            "string.char decoder ไม่พบข้อมูล"
        )

    return result


# ============================================================
# ENGINE PIPELINE
# ============================================================

ENGINES = [
    (
        "Base64",
        engine_base64
    ),
    (
        "Hex",
        engine_hex
    ),
    (
        "URL",
        engine_url
    ),
    (
        "Lua Escape",
        engine_escape
    ),
    (
        "Byte Array",
        engine_byte_array
    ),
    (
        "String Concat",
        engine_string_concat
    ),
    (
        "string.char",
        engine_constants
    )
]


def process(source: str):

    current = source

    seen = {
        sha256(current)
    }

    history = []

    for round_no in range(
        1,
        MAX_ROUNDS + 1
    ):

        changed_round = False

        for name, engine in ENGINES:

            before = current

            try:

                result = engine(
                    before
                )

                if not changed(
                    before,
                    result
                ):
                    raise RuntimeError(
                        "ผลลัพธ์ไม่เปลี่ยน"
                    )

                if len(result) > MAX_OUTPUT_SIZE:
                    raise RuntimeError(
                        "ผลลัพธ์ใหญ่เกินกำหนด"
                    )

                digest = sha256(
                    result
                )

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

                history.append({
                    "round": round_no,
                    "engine": name,
                    "status": "success",
                    "before": len(before),
                    "after": len(result)
                })

            except Exception as exc:

                history.append({
                    "round": round_no,
                    "engine": name,
                    "status": "error",
                    "error": str(exc)
                })

                # ตัวนี้พัง -> ตัวถัดไป
                continue

        if not changed_round:
            break

    return current, history


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

            data, filename = await download_url(
                url
            )

        else:

            if file.size and file.size > MAX_FILE_SIZE:
                raise ValueError(
                    "ไฟล์ใหญ่เกิน 10 MB"
                )

            data = await file.read()

            if len(data) > MAX_FILE_SIZE:
                raise ValueError(
                    "ไฟล์ใหญ่เกิน 10 MB"
                )

            filename = file.filename

        source = decode_bytes(
            data
        )

        if not source.strip():
            raise ValueError(
                "ไฟล์ว่าง"
            )

        # ----------------------------------------------------
        # DETECT
        # ----------------------------------------------------

        detected = detect(
            source
        )

        # ----------------------------------------------------
        # RUN
        # ----------------------------------------------------

        result, history = await asyncio.to_thread(
            process,
            source
        )

        # ----------------------------------------------------
        # SAVE
        # ----------------------------------------------------

        safe = clean_filename(
            filename
        )

        stem = Path(
            safe
        ).stem

        output_file = (
            WORK_DIR /
            f"{stem}_deobfuscated.lua"
        )

        report_file = (
            WORK_DIR /
            f"{stem}_report.json"
        )

        output_file.write_text(
            result,
            encoding="utf-8"
        )

        report = {
            "input": {
                "filename": safe,
                "size": len(data),
                "sha256": hashlib.sha256(
                    data
                ).hexdigest()
            },

            "detected": detected,

            "output": {
                "size": len(result),
                "sha256": sha256(result)
            },

            "pipeline": history
        }

        report_file.write_text(
            json.dumps(
                report,
                ensure_ascii=False,
                indent=2
            ),
            encoding="utf-8"
        )

        # ----------------------------------------------------
        # STATS
        # ----------------------------------------------------

        successes = sum(
            1
            for x in history
            if x["status"] == "success"
        )

        errors = sum(
            1
            for x in history
            if x["status"] == "error"
        )

        embed = discord.Embed(
            title="✅ Deobfuscation เสร็จแล้ว",
            color=discord.Color.green()
        )

        embed.add_field(
            name="ตรวจพบ",
            value=(
                ", ".join(detected)
                if detected
                else "ไม่ทราบชนิด"
            ),
            inline=False
        )

        embed.add_field(
            name="Engine สำเร็จ",
            value=str(successes)
        )

        embed.add_field(
            name="Engine Error",
            value=str(errors)
        )

        embed.add_field(
            name="รอบที่ทำ",
            value=str(
                max(
                    [
                        x["round"]
                        for x in history
                    ],
                    default=0
                )
            )
        )

        await interaction.followup.send(
            embed=embed,
            files=[
                discord.File(
                    output_file,
                    filename=output_file.name
                ),
                discord.File(
                    report_file,
                    filename=report_file.name
                )
            ]
        )

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

        print(
            f"Bot: {bot.user}"
        )

        print(
            f"Slash commands: {len(synced)}"
        )

    except Exception as exc:

        print(
            f"Sync error: {exc}"
        )


# ============================================================
# START
# ============================================================

if not TOKEN:
    raise RuntimeError(
        "DISCORD_TOKEN ยังไม่ได้ตั้งค่า"
    )

bot.run(TOKEN)
