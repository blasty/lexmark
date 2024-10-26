#pragma once

#include <stdint.h>
#include <unistd.h>

void hexdump(void *ptr, int buflen);
uint8_t le8(uint8_t *p);
uint16_t le16(uint8_t *p);
uint32_t le32(uint8_t *p);
void read_phys(off_t addr, uint32_t length, void *outbuf);
void write_phys(off_t addr, uint32_t length, void *inbuf);