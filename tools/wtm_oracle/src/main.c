#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <stdint.h>
#include <ctype.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 0x4444
#define BUFFER_SIZE 1024

#define NETLINK_GENERIC 16
#define WTM_UNWRAP_REPLY1_LEN 0x5c
#define WTM_UNWRAP_REPLY2_LEN 0x24
#define WRAPPED_LEN 0x268

void hexdump(void *ptr, int buflen)
{
  unsigned char *buf = (unsigned char *)ptr;
  int i, j;
  for (i = 0; i < buflen; i += 16)
  {
    printf("%06x: ", i);
    for (j = 0; j < 16; j++)
      if (i + j < buflen)
        printf("%02x ", buf[i + j]);
      else
        printf("   ");
    printf(" ");
    for (j = 0; j < 16; j++)
      if (i + j < buflen)
        printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
    printf("\n");
  }
}

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

  printf("A\n");
  if (sendto(sock, pkt_hello, sizeof(pkt_hello), 0, NULL, 0) < 0)
  {
    return -1;
  }

  printf("B\n");
  if (recvfrom(sock, r, sizeof(r), 0, NULL, NULL) != WTM_UNWRAP_REPLY1_LEN)
  {
    return -1;
  }

  printf("C\n");
  if (recvfrom(sock, r, sizeof(r), 0, NULL, NULL) != WTM_UNWRAP_REPLY2_LEN)
  {
    return -1;
  }

  uint32_t pkt_len = sizeof(pkt_unwrap_header) + wrapped_len + 3;
  uint8_t *pkt = malloc(pkt_len);
  memset(pkt, 0, pkt_len);
  memcpy(pkt, pkt_unwrap_header, sizeof(pkt_unwrap_header));
  memcpy(pkt + sizeof(pkt_unwrap_header), wrapped, wrapped_len);

  printf("D %x\n", sizeof(pkt_unwrap_header) + wrapped_len);
  if (sendto(sock, pkt, pkt_len, 0, NULL, 0) < 0)
  {
    free(pkt);
    perror("write");
    return -1;
  }

  free(pkt);

  printf("E\n");
  if (recvfrom(sock, r, 0x40, 0, NULL, NULL) != 0x40)
  {
    perror("recvfrom");
    return -1;
  }

  close(sock);

  memcpy(unwrapped_out, r + 0x20, 0x20);

  return 0;
}

int tcp_listen(uint16_t port)
{
  int server_fd;
  struct sockaddr_in address;
  int opt = 1;

  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
  {
    perror("socket");
    return -1;
  }

  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
  {
    perror("setsockopt");
    close(server_fd);
    return -1;
  }

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(PORT);

  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
  {
    perror("bind");
    close(server_fd);
    return -1;
  }

  if (listen(server_fd, 3) < 0)
  {
    perror("listen");
    close(server_fd);
    return -1;
  }

  return server_fd;
}

int main()
{
  int server_fd, client_fd;
  struct sockaddr_in address;
  int addr_len = sizeof(address);

  server_fd = tcp_listen(PORT);

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

    printf("client connected\n");

    uint8_t wrapped[WRAPPED_LEN];

    int bytes_received = read(client_fd, wrapped, WRAPPED_LEN);
    if (bytes_received != WRAPPED_LEN)
    {
      printf(
          "short read from client (got %d bytes, expected %d)\n",
          bytes_received, WRAPPED_LEN);

      close(client_fd);
      continue;
    }

    printf("got wrapped key\n");
    hexdump(wrapped, WRAPPED_LEN);

    uint8_t unwrapped[0x20];

    if (wtm_unwrap_key(wrapped, WRAPPED_LEN, unwrapped) < 0)
    {
      printf("failed to unwrap key somehow...\n");
      close(client_fd);
      continue;
    }

    printf("Unwrapped key:\n");
    hexdump(unwrapped, 0x20);

    if (send(client_fd, unwrapped, sizeof(unwrapped), 0) < 0)
    {
      perror("send");
      close(client_fd);
      continue;
    }

    close(client_fd);
  }
  close(server_fd);

  return 0;
}