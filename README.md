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
- ส่งไฟล์ผลลัพธ์กลับ Discord
- สร้าง report JSON
- จำกัดขนาดไฟล์เพื่อป้องกันการใช้ทรัพยากรมากเกินไป

## Project Structure

```text
Discord-Deobfuscator/
├── bot.py
├── requirements.txt
├── README.md
└── .gitignore
