#!/usr/bin/env python3

import sys
import os
import struct
import binascii

DEFAULT_KEY_INDEX = 2
RSA_BLOCKSIZE = 256
AES_BLOCKSIZE = 0x10
AES_CHUNKSIZE = 0x10000

from keys import KEYS

class LexmarkFirmwareDecrypter:
    def __init__(self, filename):
        if not os.path.exists(filename):
            self.err("could not open file '%s'" % filename)
        self.filename = filename
        self.fh = open(self.filename, "rb")
        self.parse_pjl_header()
        # decrypt kernel section
        self.decrypt_section("kernel.bin")
        self.decrypt_section("data.bin")

    def err(self, s):
        print("ERROR: %s" % s)
        exit(0)

    def info(self, s):
        print("INFO: %s" % s)

    def unpad(self, blob):
        if blob[0] != 0x01:
            self.err("invalid PKCS start byte (0x%02x)" % blob[0])
        pos = 1
        while blob[pos] == 0xff:
            pos = pos + 1
        if blob[pos] != 0x00:
            self.err("invalid PKCS end byte (0x%02x)" % blob[pos])
        return blob[pos+1:]

    def rsa(self, ctext, key_idx) -> bytes:
        # pow(block1, rsa_exp, rsa_mod)
        if len(ctext) != RSA_BLOCKSIZE:
            self.err("rsa block is wrong size (%d)" % len(ctext))
        ctext_int = 0
        for i in range(RSA_BLOCKSIZE):
            ctext_int <<= 8
            ctext_int |= ctext[i]

        dtext_int = pow(ctext_int, KEYS[key_idx]['exp'], KEYS[key_idx]['mod'])
        o = b''

        for i in range(RSA_BLOCKSIZE-1):
            v = (dtext_int >> ((RSA_BLOCKSIZE - 2 - i) * 8)) & 0xff
            o += bytes([v])
        return o

    # unused, we hardcode keyz
    def _load_keys(self, filename):
        if not os.path.exists(filename):
            self.err("could not open keys file '%s'" % filename)
        keydata = open(filename, "rb").read()

        self.keys = []

        pos = 0
        while pos < len(keydata):
            key_blob = keydata[pos:pos+288]
            self.keys.append(key_blob[0x10:0x10+270])
            pos += 288
        self.info("loaded %d keys from '%s'" % (len(self.keys), filename))

    def parse_pjl_header(self):
        a = self.fh.readline()
        if a != b'\x1b%-12345X@PJL \n':
            self.err("invalid header line")
        pjl_line_a = self.fh.readline().decode('utf8')
        pjl_line_b = self.fh.readline().decode('utf8')

        if not pjl_line_a.startswith("@PJL"):
            self.err("invalid header line (a)")
        if not pjl_line_b.startswith("@PJL"):
            self.err("invalid header line (b)")

        parts = pjl_line_b.split(" ")
        if parts[1] != "LPROGRAMRIP":
            self.err("unexpected pjl instruction '%s'" % parts[1])

        self.program_properties = {}

        for i in range(2, len(parts)):
            prop_name, prop_value = parts[i].split("=", 1)
            if prop_value.startswith('"'):
                self.program_properties[prop_name] = prop_value[1:len(prop_value)-1]
            else:
                self.program_properties[prop_name] = int(prop_value, 0)

    def dword_at(self, blob, pos):
        return struct.unpack("<L", blob[pos:pos+4])[0]

    def build_iv(self, v):
        o=[]
        for i in range(16):
            o.append(v[i])
        o[0] ^= 0x49
        for i in range(1, 16):
            o[i] ^= o[i-1]
        ob = b''
        for v in o:
            ob += bytes([v])
        return ob

    def decrypt_section(self, output_filename):
        section_hdr = self.unpad(self.rsa(self.fh.read(0x100), DEFAULT_KEY_INDEX))
        section_hdr += self.unpad(self.rsa(self.fh.read(0x100), DEFAULT_KEY_INDEX))

        if len(section_hdr) != 296:
            self.err("decrypted section header size mismatch! (%d vs %d)" % (len(section_hdr), 296))

        self.sig_size = self.dword_at(section_hdr, 0xc)
        self.aes_key_size = self.dword_at(section_hdr, 0x118)
        self.aes_key_byte_size = self.dword_at(section_hdr, 0x11c)
        self.aes_mode = self.dword_at(section_hdr, 0x120)
        self.data_size = self.dword_at(section_hdr, 0x124)

        print("> SECTION HEADER:")
        print("  - decrypted signature size : 0x%08x" % self.sig_size)
        print("  - decrypted aes key size   : 0x%08x" % self.aes_key_size)
        print("  - aes key byte size        : 0x%08x" % self.aes_key_byte_size)
        print("  - aes mode                 : 0x%08x" % self.aes_mode)
        print("  - decrypted data size      : 0x%08x" % self.data_size)
        print("")

        signature = self.unpad(self.rsa(self.fh.read(0x100), DEFAULT_KEY_INDEX))
        if len(signature) != self.sig_size:
            self.err("signature has invalid length!")

        print("> signature : %s" % binascii.hexlify(signature).decode('utf8'))

        aes_key = self.unpad(self.rsa(self.fh.read(0x100), DEFAULT_KEY_INDEX))
        if len(aes_key) != self.aes_key_byte_size:
            self.err("aes key has invalid length!")

        print("> AES key   : %s" % binascii.hexlify(aes_key).decode('utf8'))

        from Crypto.Cipher import AES

        iv = self.build_iv(aes_key)

        cipher = AES.new(aes_key, AES.MODE_CBC, iv)

        fo = open(output_filename, "wb")

        left = self.data_size
        sys.stdout.write("unpacking: ")
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
        print("done! (0x%x)\n" % self.fh.tell())


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: %s <firmware.fls>" %  sys.argv[0])
        exit(0)

    firmware_file = sys.argv[1]

    lfd = LexmarkFirmwareDecrypter(firmware_file)
