#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include "wtmio_client.h"
#include "debug.h"

#define LKM_CMD_PATH "/sys/kernel/debug/hax/cmd"

int wtm_send_cmd(uint16_t cmd, uint16_t arg0, uint32_t arg1, void *argbuf, size_t argbuflen)
{
    FILE *f = fopen(LKM_CMD_PATH, "wb");
    if (f == NULL)
    {
        perror("fopen");
        return -1;
    }

    wtmio_cmd_t wtmio_cmd = {
        .cmd = cmd,
        .arg0 = arg0,
        .arg1 = arg1,
    };

    uint8_t *buf = malloc(sizeof(wtmio_cmd) + argbuflen);
    if (buf == NULL)
    {
        perror("malloc");
        return -1;
    }
    memcpy(buf, &wtmio_cmd, sizeof(wtmio_cmd));
    memcpy(buf + sizeof(wtmio_cmd), argbuf, argbuflen);

    ssize_t r = write(fileno(f), buf, sizeof(wtmio_cmd) + argbuflen);
    if (r != sizeof(wtmio_cmd) + argbuflen)
    {
        DPRINTF("short write to %s (got %d bytes, expected %d)\n", LKM_CMD_PATH, r, sizeof(wtmio_cmd) + argbuflen);
        perror("write");
        return -1;
    }

    fclose(f);
    return 0;
}

int wtm_send_cmd0(uint16_t cmd, uint16_t arg0, uint32_t arg1)
{
    return wtm_send_cmd(cmd, arg0, arg1, NULL, 0);
}

size_t wtm_read_reply(void *outbuf, size_t len)
{
    FILE *f = fopen(LKM_CMD_PATH, "rb");
    if (f == NULL)
    {
        perror("fopen");
        return -1;
    }

    ssize_t r = read(fileno(f), outbuf, len);
    if (r != len)
    {
        DPRINTF("short read from %s (got %d bytes, expected %d)\n", LKM_CMD_PATH, r, len);
        perror("read");
        return -1;
    }
    fclose(f);

    return r;
}

uint8_t wtm_io_read8(uint16_t reg)
{
    uint8_t val;
    wtm_send_cmd0(LKM_CMD_READ8, reg, 0);
    wtm_read_reply(&val, sizeof(val));
    return val;
}

uint16_t wtm_io_read16(uint16_t reg)
{
    uint16_t val;
    wtm_send_cmd0(LKM_CMD_READ16, reg, 0);
    wtm_read_reply(&val, sizeof(val));
    return val;
}

uint32_t wtm_io_read32(uint16_t reg)
{
    uint32_t val;
    wtm_send_cmd0(LKM_CMD_READ32, reg, 0);
    wtm_read_reply(&val, sizeof(val));
    return val;
}

void wtm_io_write8(uint16_t reg, uint8_t val)
{
    wtm_send_cmd0(LKM_CMD_WRITE8, reg, val);
}

void wtm_io_write16(uint16_t reg, uint16_t val)
{
    wtm_send_cmd0(LKM_CMD_WRITE16, reg, val);
}

void wtm_io_write32(uint16_t reg, uint32_t val)
{
    wtm_send_cmd0(LKM_CMD_WRITE32, reg, val);
}

uint32_t wtm_get_scratch()
{
    uint32_t val = 0;
    wtm_send_cmd0(LKM_CMD_GET_SCRATCH, 0, 0);
    wtm_read_reply(&val, sizeof(val));
    return val;
}

void wtm_exec_cmd(uint16_t cmd, uint8_t *a, uint32_t args_len)
{
    uint8_t args[4 * 16];
    memset(args, 0, sizeof(args));
    memcpy(args, a, args_len);
    wtm_send_cmd(LKM_CMD_WTM_EXEC_CMD, 0, cmd, args, sizeof(args));
}