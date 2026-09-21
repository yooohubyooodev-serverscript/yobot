# Discord Lua/Luau Deobfuscator Bot

Static-analysis Discord bot that attempts to normalize / partially recover Lua and Luau scripts.

## Important limitations

This bot **does not** claim full deobfuscation of commercial protectors such as:

- Luraph
- MoonSec
- IronBrew
- Luarmor
- LuaU VMP

Open-source projects that target those protectors were evaluated. Most either:

- execute the input script (forbidden by the security policy of this bot),
- are archived / incomplete / source-deleted,
- require complex native toolchains not packaged here,
- or operate only on bytecode while typical uploads are source.

Those engines are therefore reported as **unavailable** with explicit reasons inside `report.json`.

What the bot *does* provide are safe static **preprocessors**:

- Base64 string decoding
- Hex string decoding
- Lua escape-sequence decoding
- `string.char(...)` expansion
- simple string-concatenation folding

These are normalizers, not full deobfuscators. Successful runs are always reported as **partial**.

## Features

- Slash command `/deobf`
- Accepts `.lua` / `.luau` attachment or public HTTP(S) URL
- Fallback pipeline with SHA-256 loop protection and round limit
- Per-job temporary directories (no shared state)
- SSRF-hardened URL downloader (DNS resolution checked)
- Honest `report.json` (no fake success)
- Failed jobs never rename the original source to `*_deobfuscated.lua`

## Requirements

- Python 3.10+
- Discord bot token

```bash
pip install -r requirements.txt
export DISCORD_TOKEN=your_token_here
python bot.py
```

## Docker

```bash
docker build -t yobot .
docker run -e DISCORD_TOKEN=your_token_here yobot
```

## Discord usage

```
/deobf file:<attachment>
/deobf url:https://example.com/script.lua
```

## Output rules

| Status   | Files sent                         | Meaning                                      |
|----------|------------------------------------|----------------------------------------------|
| partial  | `*_partial.lua` + `report.json`    | Preprocessors changed the source             |
| failed   | `report.json` only                 | No useful transformation                     |

A file named `*_deobfuscated.lua` is **never** produced, because no full deobfuscator is currently available.

## report.json shape

```json
{
  "status": "partial | failed",
  "detected": [],
  "engines": {
    "success": [],
    "no_change": [],
    "unsupported": [],
    "unavailable": [],
    "error": [],
    "timeout": []
  },
  "rounds": 0,
  "pipeline": [],
  "input": { "filename": "", "sha256": "" },
  "output": { "filename": null, "sha256": null },
  "errors": []
}
```

## Security

- Untrusted Lua is never executed (`loadstring`, `eval`, shell, etc. are forbidden)
- URL downloads are size-limited and SSRF-checked (private IPs rejected after DNS)
- Each job uses an isolated temporary directory that is deleted afterwards
- Token is read only from the `DISCORD_TOKEN` environment variable

## Project layout

```
yobot/
├── bot.py
├── requirements.txt
├── Dockerfile
├── core/
│   ├── detector.py
│   ├── downloader.py
│   ├── pipeline.py
│   ├── reporter.py
│   └── security.py
├── engines/
│   ├── __init__.py
│   ├── base.py
│   └── preprocessors.py
└── tests/
```

## License notes

Third-party deobfuscator projects that were evaluated retain their original licenses. None of them are currently vendored or executed by this bot.
