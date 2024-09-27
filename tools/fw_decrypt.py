#!/usr/bin/env python3

import sys
import os
import struct
import binascii
from Crypto.Cipher import AES

DEFAULT_KEY_INDEX = 2
RSA_BLOCKSIZE = 256
AES_BLOCKSIZE = 0x10
AES_CHUNKSIZE = 0x800000
MAIN_MAGIC = 0x7C42494E
TAG_DATA = 0xFFAA00C7

from keys import KEYS

CONTENT_ID_MAP = {
    1: "uboot",
    2: "initramfs",
    3: "rootfs",
    4: "license",
}


class LexmarkFirmwareUnpacker:
    def __init__(self, filename):
        if not os.path.exists(filename):
            self.err("could not open file '%s'" % filename)
        self.filename = filename
        self.fh = open(self.filename, "rb")
        self.parse_pjl_header()

        self.sections = [
            {
                "name": "flasher",
                "size": self.pjl_properties["KERNELCOUNT"],
                "pos": 0,
            },
            {
                "name": "main",
                "size": self.pjl_properties["TYPECOUNT"],
                "pos": 0,
            },
            {
                "name": "fksign",
                "size": self.pjl_properties["FKSIGNSZ"],
                "pos": 0,
            },
        ]

        pos = self.fh.tell()
        for i in range(len(self.sections)):
            self.sections[i]["pos"] = pos
            pos += self.sections[i]["size"]

    def err(self, s):
        print("ERROR: %s" % s)
        exit(0)

    def info(self, s):
        print("INFO: %s" % s)

    def section(self, name):
        for i in range(len(self.sections)):
            if self.sections[i]["name"] == name:
                return self.sections[i]
        return None

    def unpad(self, blob):
        if blob[0] != 0x01:
            self.err("invalid PKCS start byte (0x%02x)" % blob[0])
        pos = 1
        while blob[pos] == 0xFF:
            pos = pos + 1
        if blob[pos] != 0x00:
            self.err("invalid PKCS end byte (0x%02x)" % blob[pos])
        return blob[pos + 1 :]

    def rsa(self, ctext, key_idx) -> bytes:
        # pow(block1, rsa_exp, rsa_mod)
        if len(ctext) != RSA_BLOCKSIZE:
            self.err("rsa block is wrong size (%d)" % len(ctext))
        ctext_int = 0
        for i in range(RSA_BLOCKSIZE):
            ctext_int <<= 8
            ctext_int |= ctext[i]

        dtext_int = pow(ctext_int, KEYS[key_idx]["exp"], KEYS[key_idx]["mod"])
        o = b""

        for i in range(RSA_BLOCKSIZE - 1):
            v = (dtext_int >> ((RSA_BLOCKSIZE - 2 - i) * 8)) & 0xFF
            o += bytes([v])
        return o

    def parse_pjl_header(self):
        a = self.fh.readline()
        if a != b"\x1b%-12345X@PJL \n":
            self.err("invalid header line")
        pjl_line_a = self.fh.readline().decode("utf8")
        pjl_line_b = self.fh.readline().decode("utf8")

        if not pjl_line_a.startswith("@PJL") or not pjl_line_b.startswith("@PJL"):
            self.err("invalid PJL header line")

        parts = pjl_line_b.split(" ")
        if parts[1] != "LPROGRAMRIP":
            self.err("unexpected pjl instruction '%s'" % parts[1])

        self.pjl_properties = {}

        for i in range(2, len(parts)):
            name, value = parts[i].split("=", 1)
            if value.startswith('"'):
                self.pjl_properties[name] = value[1 : len(value) - 1]
            else:
                self.pjl_properties[name] = int(value, 0)

    def dword_at(self, blob, pos):
        return struct.unpack("<L", blob[pos : pos + 4])[0]

    def build_iv(self, v):
        o = [v[i] for i in range(16)]
        o[0] ^= 0x49
        for i in range(1, 16):
            o[i] ^= o[i - 1]
        return bytes(o)

    def decrypt_section(self, section_name, output_filename):
        self.fh.seek(self.section(section_name)["pos"])

        section_hdr = self.unpad(self.rsa(self.fh.read(0x100), DEFAULT_KEY_INDEX))
        section_hdr += self.unpad(self.rsa(self.fh.read(0x100), DEFAULT_KEY_INDEX))

        if len(section_hdr) != 296:
            self.err(
                "decrypted section header size mismatch! (%d vs %d)"
                % (len(section_hdr), 296)
            )

        self.sig_size = self.dword_at(section_hdr, 0xC)
        self.aes_key_size = self.dword_at(section_hdr, 0x118)
        self.aes_key_byte_size = self.dword_at(section_hdr, 0x11C)
        self.aes_mode = self.dword_at(section_hdr, 0x120)
        self.data_size = self.dword_at(section_hdr, 0x124)

        print("> section header:")
        print("  - decrypted signature size : 0x%08x" % self.sig_size)
        print("  - decrypted aes key size   : 0x%08x" % self.aes_key_size)
        print("  - aes key byte size        : 0x%08x" % self.aes_key_byte_size)
        print("  - aes mode                 : 0x%08x" % self.aes_mode)
        print("  - decrypted data size      : 0x%08x" % self.data_size)
        print("")

        signature = self.unpad(self.rsa(self.fh.read(0x100), DEFAULT_KEY_INDEX))
        if len(signature) != self.sig_size:
            self.err("signature has invalid length!")

        print("> signature : %s" % binascii.hexlify(signature).decode("utf8"))

        aes_key = self.unpad(self.rsa(self.fh.read(0x100), DEFAULT_KEY_INDEX))
        if len(aes_key) != self.aes_key_byte_size:
            self.err("aes key has invalid length!")

        print("> AES key   : %s" % binascii.hexlify(aes_key).decode("utf8"))

        iv = self.build_iv(aes_key)

        cipher = AES.new(aes_key, AES.MODE_CBC, iv)

        fo = open(output_filename, "wb")

        left = self.data_size
        sys.stdout.write("> unpacking section '%s': " % section_name)
        sys.stdout.flush()
        while left > 0:
            sys.stdout.write(".")
            sys.stdout.flush()
            chunk_size = AES_CHUNKSIZE
            if chunk_size > left:
                chunk_size = left
            pt = cipher.decrypt(self.fh.read(chunk_size))
            fo.write(pt)
            left -= chunk_size

        fo.close()
        print(" done!\n")

    def unpack_main(self, inputfile, outputdir):
        d = open(inputfile, "rb").read()
        pos = 0

        magic, file_size = struct.unpack(">LL", d[pos : pos + 8])
        pos += 8
        n = 0

        assert magic == MAIN_MAGIC
        assert file_size <= len(d)

        while pos < file_size:
            tag, size = struct.unpack(">LL", d[pos : pos + 8])
            if tag == 0:
                break

            pos += 8

            print("POS: %08x TAG: %08X SIZE: %08X" % (pos, tag, size))
            data = d[pos : pos + size]

            if size > 0 and tag != TAG_DATA:
                with open(
                    os.path.join(outputdir, "%02d_%08X.bin" % (n, tag)), "wb"
                ) as f:
                    f.write(data)
            elif tag == TAG_DATA:
                content_index, content_size = struct.unpack(">LL", data[0:8])

                assert content_index in CONTENT_ID_MAP
                assert content_size == size - 8
                content_name = CONTENT_ID_MAP[content_index]
                ofn = os.path.join(outputdir, "content_%s.bin" % content_name)
                with open(ofn, "wb") as f:
                    f.write(data[8:])

            n += 1
            pos += size


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: %s <firmware.fls> <output_dir>" % sys.argv[0])
        exit(0)

    firmware_file, output_dir = sys.argv[1:]

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    lfd = LexmarkFirmwareUnpacker(firmware_file)
    # unpack all raw sections
    for section in lfd.sections:
        if section["name"] in ["flasher", "main"]:
            lfd.decrypt_section(
                section["name"],
                os.path.join(output_dir, "section_" + section["name"] + ".bin"),
            )

    if not os.path.exists(os.path.join(output_dir, "main")):
        os.makedirs(os.path.join(output_dir, "main"))

    lfd.unpack_main(
        os.path.join(output_dir, "section_main.bin"), os.path.join(output_dir, "main")
    )
