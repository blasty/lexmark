from wtmclient import *
from util import hexdump

c = WTMClient()

scratch = c.get_scratch()
c.wtm_cmd(WTM_CMD_RNG, [0x80, scratch])
hexdump(c.scratch_read(0, 16))
