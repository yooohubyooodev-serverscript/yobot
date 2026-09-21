# Discord Lua/Luau Deobfuscator Bot

Discord Bot สำหรับวิเคราะห์และถอดโค้ด Lua/Luau แบบเป็นขั้นตอน

## Features

- `/deobf`
- รับไฟล์ `.lua` / `.luau`
- รับ URL ของไฟล์
- ตรวจจับ signature ของ obfuscator
- ระบบ fallback engine
- ถ้า engine หนึ่ง error จะข้ามไป engine ถัดไป
- ป้องกันการวนลูปของผลลัพธ์
- ประมวลผลหลายรอบ
- ส่งไฟล์ผลลัพธ์กลับ Discord เป็น attachment
- สร้าง `report.json` แยก
- จำกัดขนาดไฟล์เพื่อป้องกันการใช้ทรัพยากรมากเกินไป

## Output Rules (หลัง /deobf)

1. สร้างไฟล์ผลลัพธ์จริงจาก pipeline:
   - `<ชื่อไฟล์เดิม>_deobfuscated.lua`
2. สร้าง `report.json` ที่เก็บ:
   - status (`success` / `partial` / `failed`)
   - engines.success
   - engines.error
   - engines.unavailable
   - rounds
   - input/output size + SHA-256
   - pipeline history
3. ข้อความตอบกลับ Discord แสดงเฉพาะข้อมูลที่เชื่อถือได้ (ไม่แสดงขนาดเปรียบเทียบ)
4. ส่งทั้งไฟล์ `.lua` และ `report.json` เป็น attachment
5. ไม่ส่ง source code ทั้งก้อนเป็นข้อความ

## Project Structure

```text
yobot/
├── bot.py
├── requirements.txt
├── Dockerfile
├── README.md
└── .gitignore
```

## Environment

ตั้งค่า environment variable:

```bash
DISCORD_TOKEN=your_bot_token_here
```

## Run

```bash
pip install -r requirements.txt
export DISCORD_TOKEN=...
python bot.py
```

หรือใช้ Docker:

```bash
docker build -t yobot .
docker run -e DISCORD_TOKEN=... yobot
```
