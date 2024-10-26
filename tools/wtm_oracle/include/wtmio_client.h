#pragma once

#include <stdint.h>
#include <unistd.h>

#define LKM_CMD_WRITE8 1
#define LKM_CMD_WRITE16 2
#define LKM_CMD_WRITE32 3
#define LKM_CMD_READ8 4
#define LKM_CMD_READ16 5
#define LKM_CMD_READ32 6
#define LKM_CMD_GET_SCRATCH 7
#define LKM_CMD_WTM_EXEC_CMD 8

typedef struct
{
    uint16_t cmd;
    uint16_t arg0;
    uint32_t arg1;
} wtmio_cmd_t;

int wtm_send_cmd(uint16_t cmd, uint16_t arg0, uint32_t arg1, void *argbuf, size_t argbuflen);
int wtm_send_cmd0(uint16_t cmd, uint16_t arg0, uint32_t arg1);
size_t wtm_read_reply(void *outbuf, size_t len);
uint8_t wtm_io_read8(uint16_t reg);
uint16_t wtm_io_read16(uint16_t reg);
uint32_t wtm_io_read32(uint16_t reg);
void wtm_io_write8(uint16_t reg, uint8_t val);
void wtm_io_write16(uint16_t reg, uint16_t val);
void wtm_io_write32(uint16_t reg, uint32_t val);
void wtm_exec_cmd(uint16_t cmd, uint8_t *a, uint32_t args_len);
uint32_t wtm_get_scratch();