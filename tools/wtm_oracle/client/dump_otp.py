from wtmclient import *

c = WTMClient()

OTP_BASE = 0xD1D22800
OTP_SIZE = 0x800

o = b""
for i in range(OTP_BASE, OTP_BASE + OTP_SIZE, 4):
    o += struct.pack("<I", c.wtm_read32(i))

with open("otp.bin", "wb") as f:
    f.write(o)
