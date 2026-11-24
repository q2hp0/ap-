#define _GNU_SOURCE
#include "apabi.h"
#include "apsys.h"
#include "aptransport.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures = 0;

static void check(bool condition, const char *name) {
  if (!condition) {
    fprintf(stderr, "audit test fail: %s\n", name);
    ++failures;
  }
}

static void test_exact_key_path(const char *dir) {
  char path[256];
  uint8_t first[AP_TRANSPORT_KEY_LEN];
  uint8_t second[AP_TRANSPORT_KEY_LEN];
  struct stat st;

  snprintf(path, sizeof(path), "%s/audit.exact.key", dir);
  unlink(path);
  check(ap_transport_key_create_path(path, first) == AP_OK, "create exact key path");
  check(stat(path, &st) == 0 && S_ISREG(st.st_mode), "exact key is a regular file");
  check((st.st_mode & 0077) == 0, "exact key is private");
  check(ap_transport_key_load_path(path, second) == AP_OK, "load exact key path");
  check(memcmp(first, second, sizeof(first)) == 0, "exact key bytes match");
  unlink(path);
}

static void test_frames(void) {
  uint8_t payload[16];
  uint8_t received[AP_AUDIT_MAX_PAYLOAD];
  uint8_t oversized[AP_AUDIT_MAX_PAYLOAD + 1u];
  uint8_t bad_header[4];
  size_t len = 0u;
  int fds[2];

  memset(payload, 0x41, sizeof(payload));
  memset(received, 0, sizeof(received));
  memset(oversized, 0x42, sizeof(oversized));
  check(pipe(fds) == 0, "audit pipe open");
  if (fds[0] < 0 || fds[1] < 0) return;

  check(ap_audit_send(fds[1], payload, sizeof(payload)) == AP_OK, "send framed payload");
  check(ap_audit_recv(fds[0], received, sizeof(received), &len) == AP_OK, "recv framed payload");
  check(len == sizeof(payload) && memcmp(payload, received, len) == 0, "framed payload bytes");

  check(ap_audit_send(fds[1], oversized, sizeof(oversized)) == AP_ERR_RANGE,
        "oversized frame rejected");

  bad_header[0] = 0xffu;
  bad_header[1] = 0xffu;
  bad_header[2] = 0xffu;
  bad_header[3] = 0xffu;
  check(write(fds[1], bad_header, sizeof(bad_header)) == (ssize_t)sizeof(bad_header),
        "write bad header");
  check(ap_audit_recv(fds[0], received, sizeof(received), &len) == AP_ERR_RANGE,
        "oversized header rejected");

  close(fds[0]);
  close(fds[1]);
}

int main(void) {
  char dir[] = "/tmp/ap-audit-test-XXXXXX";

  if (mkdtemp(dir) == NULL) {
    fprintf(stderr, "audit test: cannot create temp dir\n");
    return 1;
  }
  test_exact_key_path(dir);
  test_frames();
  rmdir(dir);
  if (failures == 0) printf("audit tests: ok\n");
  return failures == 0 ? 0 : 1;
}
