#!/usr/bin/env python3

import sys
import gzip
import io
import os
import struct
import socket

from pycramfs import Cramfs
from pycramfs.extract import extract_dir, extract_file
from Crypto.Cipher import AES
from tqdm import tqdm

UBOOT_MAGIC = b"\x27\x05\x19\x56"
CPIO_HEADER_LEN = 6 + (13 * 8)
CPIO_MAGIC_NEW = b"\x07\x07\x01"
SECTOR_SIZE = 0x200

pad = lambda x, y: x + (y - (x % y)) if (x % y) != 0 else x


def cramfs_get_file(cramfs_filename, path):
    with Cramfs.from_file(cramfs_filename) as cramfs:
        if path not in cramfs:
            return None
        return cramfs.select(path).read_bytes()
    return None


def cpio_get_file(blob, path):
    pos = 0
    while pos < len(blob):
        header = blob[pos : pos + CPIO_HEADER_LEN]
        header = bytes.fromhex(header.decode())
        assert header[0:3] == CPIO_MAGIC_NEW
        h = struct.unpack(">" + "L" * 13, header[3:])
        c_filesize = h[6]
        c_namesize = h[11]
        pos += CPIO_HEADER_LEN
        filename = blob[pos : pos + c_namesize - 1].decode()
        if filename == "TRAILER!!!":
            break
        pos += c_namesize
        pos = pad(pos, 4)
        if filename == path:
            return blob[pos : pos + c_filesize]
        pos += c_filesize
        pos = pad(pos, 4)
    return None


def wtm_oracle_unwrap_key(api, wkey, rootfskey):
    s = socket.create_connection((api, 0x4444))
    RPC_COMMAND_UNWRAP_KEY = 1
    body = wkey + rootfskey[0x10:] + rootfskey[0:0x10]
    s.sendall(struct.pack("<LL", RPC_COMMAND_UNWRAP_KEY, len(body)) + body)

    r = s.recv(0x20)
    s.close()
    if r == b"":
        return None
    return r


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: %s <inputdir> <wtm_oracle_ip>" % sys.argv[0])
        exit(0)

    inputdir, wtm_oracle_ip = sys.argv[1:]

    cramfs_path = os.path.join(inputdir, "main/content_initramfs.bin")
    rootfskey = cramfs_get_file(cramfs_path, "/rootfs.key")
    if rootfskey is None:
        print("failed to extract rootfs.key")
        exit(1)

    print("> wrapped rootfs key   : %s" % rootfskey.hex())

    uinitramfs = cramfs_get_file(cramfs_path, "/uInitramfs")
    if uinitramfs is None:
        print("failed to extract uInitramfs")
        exit(1)

    # unpack and decompress uboot image
    uboot_header = uinitramfs[:64]
    assert uboot_header[0:4] == UBOOT_MAGIC
    ramdisk_size = int.from_bytes(uboot_header[12:16], byteorder="big")
    ramdisk_compressed = uinitramfs[64 : 64 + ramdisk_size]
    ramdisk_stream = io.BytesIO(ramdisk_compressed)
    ramdisk_uncompressed = gzip.GzipFile(fileobj=ramdisk_stream).read()

    wkey_unwrapped = None
    # we'll only try wkey4 for now, I've not seen the other ones being used
    for i in [4]:
        wkey_data = cpio_get_file(
            ramdisk_uncompressed, "usr/share/wtm-crypt/wkey%d.bin" % i
        )

        if wkey_data is None:
            break

        try:
            wkey_unwrapped = wtm_oracle_unwrap_key(wtm_oracle_ip, wkey_data, rootfskey)
            if wkey_unwrapped is not None:
                break
        except:
            pass

    if wkey_unwrapped is None:
        print("failed to unwrap any wkey")
        exit(1)

    print("> unwrapped rootfs key : %s" % wkey_unwrapped.hex())

    # decrypt rootfs
    rootfs_path = os.path.join(inputdir, "main/content_rootfs.bin")
    rootfs_dec_path = os.path.join(inputdir, "main/content_rootfs_dec.bin")

    blob = open(rootfs_path, "rb").read()

    sector_cnt = os.path.getsize(rootfs_path) // SECTOR_SIZE

    with open(rootfs_dec_path, "wb") as f:
        for sector in tqdm(range(sector_cnt)):
            offs = sector * SECTOR_SIZE
            data = blob[offs : offs + SECTOR_SIZE]
            iv = b"\x00" * 8 + struct.pack(">Q", sector)
            cipher = AES.new(wkey_unwrapped, AES.MODE_CBC, iv)
            f.write(cipher.decrypt(data))

    print("> decrypted rootfs written to %s" % rootfs_dec_path)
    print("")
