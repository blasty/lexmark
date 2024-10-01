from wtmclient import *
from util import hexdump
from Crypto.Cipher import AES

c = WTMClient()

wkey = open("wkey.bin", "rb").read()
c.scratch_write(0, wkey)

c.wtm_cmd(WTM_CMD_KEY_UNWRAP_LOAD, [MODE_AES_256_CBC, c.scratch])
rv = c.io_read32(REG_CMD_RETURN_STATUS)

c.scratch_write(0, b"\xAA" * 0x100)
c.wtm_cmd(WTM_CMD_STORE_ENGINE_CONTEXT_EXTERNAL, [MODE_AES_256_CBC, c.scratch])
rv = c.io_read32(REG_CMD_RETURN_STATUS)
print("Store engine context status: 0x%08x" % rv)
blob = c.scratch_read(0, 0x100)
unwrapped_aes_key = blob[0x88 : 0x88 + 0x20]

print("Unwrapped AES key: %s" % unwrapped_aes_key.hex())
