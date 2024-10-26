#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef DEBUG
void hexdump(void *ptr, int buflen)
{
    unsigned char *buf = (unsigned char *)ptr;
    int i, j;
    for (i = 0; i < buflen; i += 16)
    {
        printf("%06x: ", i);
        for (j = 0; j < 16; j++)
        {
            if (i + j < buflen)
            {
                printf("%02x ", buf[i + j]);
            }
            else
            {
                printf("   ");
            }
        }
        printf(" ");
        for (j = 0; j < 16; j++)
        {
            if (i + j < buflen)
            {
                printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
            }
        }
        printf("\n");
    }
}
#else
void hexdump(void *ptr, int buflen)
{
    return;
}
#endif

uint8_t le8(uint8_t *p)
{
    return p[0];
}

uint16_t le16(uint8_t *p)
{
    return p[0] | (p[1] << 8);
}

uint32_t le32(uint8_t *p)
{
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}

void read_phys(off_t addr, uint32_t length, void *outbuf)
{
    int f = open("/dev/mem", O_RDONLY);
    if (f < 0)
    {
        perror("open");
        return;
    }
    lseek(f, addr, SEEK_SET);
    read(f, outbuf, length);
    close(f);
}

void write_phys(off_t addr, uint32_t length, void *inbuf)
{
    int f = open("/dev/mem", O_WRONLY);
    if (f < 0)
    {
        perror("open");
        return;
    }
    lseek(f, addr, SEEK_SET);
    write(f, inbuf, length);
    close(f);
}