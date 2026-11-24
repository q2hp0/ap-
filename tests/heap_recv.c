#define _GNU_SOURCE
#include "apabi.h"
#include "apsys.h"
#include "aptransport.h"

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
  char keypath[AP_TRANSPORT_MAX_PATH];
  uint8_t key[AP_TRANSPORT_KEY_LEN];
  int fd = -1;
  int expected = argc > 2 ? atoi(argv[2]) : 3;
  int seen = 0;

  if (argc < 2 || ap_sys_server_open(argv[1], &fd) != AP_OK) {
    fprintf(stderr, "heap_recv: cannot bind socket\n");
    return 1;
  }
  if (ap_transport_key_create(argv[1], key) != AP_OK) {
    fprintf(stderr, "heap_recv: cannot create transport key\n");
    close(fd);
    unlink(argv[1]);
    return 1;
  }
  while (seen < expected) {
    struct pollfd pfd;
    ap_event event;
    size_t received = 0;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    if (poll(&pfd, 1, 3000) <= 0) break;
    if (ap_sys_recv_sealed(fd, key, &event, sizeof(event), &received) != AP_OK) break;
    if (event.kind == AP_KIND_HEAP && event.size == sizeof(event)) {
      printf("%u %s\n", event.subkind, event.text);
      fflush(stdout);
      ++seen;
    }
  }
  close(fd);
  unlink(argv[1]);
  if (ap_transport_key_path(argv[1], keypath, sizeof(keypath)) == AP_OK) unlink(keypath);
  return seen == expected ? 0 : 1;
}
