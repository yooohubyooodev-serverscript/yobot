"""Safe HTTP downloader with size and redirect limits."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import aiohttp

from .security import validate_public_url

MAX_FILE_SIZE = 10 * 1024 * 1024
DOWNLOAD_TIMEOUT = 30
MAX_REDIRECTS = 5


async def download_url(url: str) -> tuple[bytes, str]:
    clean = validate_public_url(url)

    timeout = aiohttp.ClientTimeout(total=DOWNLOAD_TIMEOUT)
    headers = {"User-Agent": "Discord-Lua-Deobfuscator/2.0"}

    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        async with session.get(clean, allow_redirects=True, max_redirects=MAX_REDIRECTS) as resp:
            if resp.status != 200:
                raise ValueError(f"HTTP {resp.status}")

            # Re-validate final URL after redirects
            final = str(resp.url)
            validate_public_url(final)

            length = resp.headers.get("Content-Length")
            if length and int(length) > MAX_FILE_SIZE:
                raise ValueError("File larger than 10 MB")

            data = await resp.read()
            if len(data) > MAX_FILE_SIZE:
                raise ValueError("File larger than 10 MB")

            name = Path(urlparse(final).path).name or "input.lua"
            return data, name
