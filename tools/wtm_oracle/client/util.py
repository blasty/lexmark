import os

# lazy schmazy
def hexdump(data):
    with open("/tmp/tmp.bin", "wb") as f:
        f.write(data)
    os.system("xxd /tmp/tmp.bin > /tmp/tmp.hex")
    print(open("/tmp/tmp.hex", "r").read())
