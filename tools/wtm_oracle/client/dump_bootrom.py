from wtmclient import *

c = WTMClient()

ROM_BASE = 0xFFE00000
ROM_SIZE = 0x00020000

rom = b""
for i in range(ROM_SIZE // 4):
    rom += c.wtm_read32(ROM_BASE + i * 4).to_bytes(4, "little")

with open("rom.bin", "wb") as f:
    f.write(rom)
