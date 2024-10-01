#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <stdint.h>
#include <ctype.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "debug.h"
#include "util.h"
#include "tcp.h"
#include "wtmio_client.h"

#define PORT 0x4444
#define BUFFER_SIZE 1024

#define NETLINK_GENERIC 16
#define WTM_UNWRAP_REPLY1_LEN 0x5c
#define WTM_UNWRAP_REPLY2_LEN 0x24
#define WRAPPED_LEN 0x268

enum RPC_COMMAND
{
  RPC_COMMAND_INVALID = 0,
  RPC_COMMAND_UNWRAP_KEY,
  RPC_COMMAND_IO_WRITE8,
  RPC_COMMAND_IO_WRITE16,
  RPC_COMMAND_IO_WRITE32,
  RPC_COMMAND_IO_READ8,
  RPC_COMMAND_IO_READ16,
  RPC_COMMAND_IO_READ32,
  RPC_COMMAND_SCRATCH_READ,
  RPC_COMMAND_SCRATCH_WRITE,
  RPC_COMMAND_WTM_EXEC_CMD,
  RPC_COMMAND_GET_SCRATCH,
  RPC_COMMAND_READ_PHYS,
  RPC_COMMAND_WRITE_PHYS,
  RPC_COMMAND_MAX,
};

typedef struct
{
  uint32_t cmd_id;
  uint32_t data_len;
} cmd_t;

uint32_t g_scratch_addr = 0;

int wtm_unwrap_key(uint8_t *wrapped, uint32_t wrapped_len, uint8_t *unwrapped_out)
{
  uint8_t pkt_hello[] = {
      0x24, 0x00, 0x00, 0x00, 0x10, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x03, 0x02, 0x00, 0x00, 0x10, 0x00, 0x02, 0x00,
      0x77, 0x74, 0x6d, 0x2d, 0x6d, 0x61, 0x69, 0x6c, 0x62, 0x6f, 0x78, 0x00};

  uint8_t pkt_unwrap_header[] = {
      0x8c, 0x02, 0x00, 0x00, 0x17, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x75, 0x02, 0x02, 0x00,
      0x05, 0x06, 0x01, 0x01, 0x20, 0x00, 0x00, 0x00, 0x01};

  int sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
  if (sock < 0)
  {
    return -1;
  }

  uint8_t r[0x100];

  if (sendto(sock, pkt_hello, sizeof(pkt_hello), 0, NULL, 0) < 0)
  {
    return -1;
  }

  if (recvfrom(sock, r, sizeof(r), 0, NULL, NULL) != WTM_UNWRAP_REPLY1_LEN)
  {
    return -1;
  }

  if (recvfrom(sock, r, sizeof(r), 0, NULL, NULL) != WTM_UNWRAP_REPLY2_LEN)
  {
    return -1;
  }

  uint32_t pkt_len = sizeof(pkt_unwrap_header) + wrapped_len + 3;
  uint8_t *pkt = malloc(pkt_len);
  memset(pkt, 0, pkt_len);
  memcpy(pkt, pkt_unwrap_header, sizeof(pkt_unwrap_header));
  memcpy(pkt + sizeof(pkt_unwrap_header), wrapped, wrapped_len);

  if (sendto(sock, pkt, pkt_len, 0, NULL, 0) < 0)
  {
    free(pkt);
    perror("write");
    return -1;
  }

  free(pkt);

  ssize_t nr = 0;

  if ((nr = recvfrom(sock, r, 0x40, 0, NULL, NULL)) != 0x40)
  {
    DPRINTF(
        "short read from netlink socket (got %d bytes, expected %d)\n",
        nr, 0x40);
    hexdump(r, nr);
    return -1;
  }

  close(sock);

  memcpy(unwrapped_out, r + 0x20, 0x20);

  return 0;
}

void cmd_unwrap_key(int client_fd, uint8_t *body, uint32_t data_len)
{
  uint8_t unwrapped[0x20];

  if (data_len != WRAPPED_LEN)
  {
    DPRINTF("invalid wrapped key length\n");
    return;
  }

  if (wtm_unwrap_key(body, data_len, unwrapped) < 0)
  {
    DPRINTF("failed to unwrap key somehow...\n");
    return;
  }

  if (send(client_fd, unwrapped, sizeof(unwrapped), 0) < 0)
  {
    perror("send");
    return;
  }
}

void cmd_wtm_exec_cmd(int client_fd, uint8_t *body, uint32_t data_len)
{
  wtm_exec_cmd(le16(body), body + 2, data_len - 2);
}

void cmd_get_scratch(int client_fd, uint8_t *body, uint32_t data_len)
{
  uint32_t scratch = wtm_get_scratch();
  DPRINTF("SENDING SCRATCH:\n");
  hexdump(&scratch, sizeof(scratch));
  write(client_fd, &scratch, sizeof(scratch));
}

void cmd_scratch_read(int client_fd, uint8_t *body, uint32_t data_len)
{
  if (data_len != 8)
  {
    DPRINTF("invalid body length\n");
    return;
  }

  uint32_t offset = le32(body);
  uint32_t len = le32(body + 4);

  uint8_t *rbuf = malloc(len);
  read_phys(g_scratch_addr + offset, len, rbuf);
  write(client_fd, rbuf, len);
  free(rbuf);
}

void cmd_scratch_write(int client_fd, uint8_t *body, uint32_t data_len)
{
  if (data_len < 8)
  {
    DPRINTF("invalid body length\n");
    return;
  }

  uint32_t offset = le32(body);
  uint32_t len = le32(body + 4);

  write_phys(g_scratch_addr + offset, len, body + 8);
}

void cmd_read_phys(int client_fd, uint8_t *body, uint32_t data_len)
{
  if (data_len != 8)
  {
    DPRINTF("invalid body length\n");
    return;
  }

  uint32_t addr = le32(body);
  uint32_t len = le32(body + 4);

  uint8_t *rbuf = malloc(len);
  read_phys(addr, len, rbuf);
  write(client_fd, rbuf, len);
  free(rbuf);
}

void cmd_write_phys(int client_fd, uint8_t *body, uint32_t data_len)
{
  if (data_len < 8)
  {
    DPRINTF("invalid body length\n");
    return;
  }

  uint32_t addr = le32(body);
  uint32_t len = le32(body + 4);

  write_phys(addr, len, body + 8);
}

#define cmd_io_read(width)                                                 \
  void cmd_io_read##width(int client_fd, uint8_t *body, uint32_t data_len) \
  {                                                                        \
    if (data_len != 2)                                                     \
    {                                                                      \
      DPRINTF("invalid body length\n");                                    \
      return;                                                              \
    }                                                                      \
    uint16_t reg = le16(body);                                             \
    uint##width##_t val = wtm_io_read##width(reg);                         \
    write(client_fd, &val, sizeof(val));                                   \
  }

#define cmd_io_write(width)                                                 \
  void cmd_io_write##width(int client_fd, uint8_t *body, uint32_t data_len) \
  {                                                                         \
    if (data_len != 2 + (width >> 3))                                       \
    {                                                                       \
      DPRINTF("invalid body length\n");                                     \
      return;                                                               \
    }                                                                       \
    uint16_t reg = le16(body);                                              \
    uint##width##_t val = le##width(body + 2);                              \
    wtm_io_write##width(reg, val);                                          \
  }

cmd_io_read(8);
cmd_io_read(16);
cmd_io_read(32);
cmd_io_write(8);
cmd_io_write(16);
cmd_io_write(32);

int handle_client(int client_fd)
{
  uint8_t *body = NULL;

  while (1)
  {

    cmd_t cmd;

    int nread = read(client_fd, &cmd, sizeof(cmd));
    if (nread == 0)
    {
      DPRINTF("client disconnected\n");
      return 0;
    }
    if (nread != sizeof(cmd))
    {
      DPRINTF(
          "short read from client (got 0x%x bytes, expected 0x%x)\n",
          nread, sizeof(cmd));

      close(client_fd);
      return -1;
    }

    if (cmd.data_len > 0)
    {
      body = malloc(cmd.data_len);
      if (body == NULL)
      {
        DPRINTF("failed to allocate memory for body\n");
        close(client_fd);
        return -1;
      }
      nread = read(client_fd, body, cmd.data_len);

      if (nread != cmd.data_len)
      {
        DPRINTF(
            "short read from client (got %d bytes, expected %d)\n",
            nread, cmd.data_len);
        free(body);
        return -1;
      }
    }

    DPRINTF("cmd_id: 0x%08x\n", cmd.cmd_id);

    switch (cmd.cmd_id)
    {
    case RPC_COMMAND_UNWRAP_KEY:
      cmd_unwrap_key(client_fd, body, cmd.data_len);
      break;

    case RPC_COMMAND_IO_READ8:
      cmd_io_read8(client_fd, body, cmd.data_len);
      break;

    case RPC_COMMAND_IO_READ16:
      cmd_io_read16(client_fd, body, cmd.data_len);
      break;

    case RPC_COMMAND_IO_READ32:
      cmd_io_read32(client_fd, body, cmd.data_len);
      break;

    case RPC_COMMAND_IO_WRITE8:
      cmd_io_write8(client_fd, body, cmd.data_len);
      break;

    case RPC_COMMAND_IO_WRITE16:
      cmd_io_write16(client_fd, body, cmd.data_len);
      break;

    case RPC_COMMAND_IO_WRITE32:
      cmd_io_write32(client_fd, body, cmd.data_len);
      break;

    case RPC_COMMAND_SCRATCH_READ:
      cmd_scratch_read(client_fd, body, cmd.data_len);
      break;

    case RPC_COMMAND_SCRATCH_WRITE:
      cmd_scratch_write(client_fd, body, cmd.data_len);
      break;

    case RPC_COMMAND_WTM_EXEC_CMD:
      cmd_wtm_exec_cmd(client_fd, body, cmd.data_len);
      break;

    case RPC_COMMAND_GET_SCRATCH:
      cmd_get_scratch(client_fd, body, cmd.data_len);
      break;

    case RPC_COMMAND_READ_PHYS:
      cmd_read_phys(client_fd, body, cmd.data_len);
      break;

    case RPC_COMMAND_WRITE_PHYS:
      cmd_write_phys(client_fd, body, cmd.data_len);
      break;

    default:
      DPRINTF("invalid command id\n");
      break;
    }

    if (body != NULL)
    {
      free(body);
      body = NULL;
    }
  }
}

int main()
{
  int server_fd, client_fd;
  struct sockaddr_in address;
  int addr_len = sizeof(address);

  server_fd = tcp_listen(PORT);

  g_scratch_addr = wtm_get_scratch();
  DPRINTF("scratch addr: 0x%08x\n", g_scratch_addr);

  if (server_fd < 0)
  {
    printf("failed to listen on port %d\n", PORT);
    return -1;
  }

  printf("listening on port %d\n", PORT);

  while (1)
  {
    client_fd = accept(
        server_fd, (struct sockaddr *)&address, (socklen_t *)&addr_len);

    if (client_fd < 0)
    {
      perror("accept");
      close(server_fd);
      exit(EXIT_FAILURE);
    }

    DPRINTF("client connected\n");

    handle_client(client_fd);
    close(client_fd);
  }
  close(server_fd);

  return 0;
}