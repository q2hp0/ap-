#define _GNU_SOURCE
#include "apabi.h"
#include "apsys.h"
#include "aptransport.h"

#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int failures = 0;

static void check(bool condition, const char *name) {
  if (!condition) {
    fprintf(stderr, "ipc test fail: %s\n", name);
    ++failures;
  }
}

static int wait_input(int fd) {
  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = POLLIN;
  pfd.revents = 0;
  return poll(&pfd, 1, 2000);
}

static void test_regular_file(const char *dir) {
  char path[256];
  char data[16];
  int fd = -1;
  FILE *file;
  size_t count;

  snprintf(path, sizeof(path), "%s/keep.txt", dir);
  file = fopen(path, "w");
  check(file != NULL, "create regular file");
  if (file == NULL) return;
  fputs("keep", file);
  fclose(file);

  check(ap_sys_server_open(path, &fd) == AP_ERR_STATE, "regular file rejected");
  file = fopen(path, "r");
  check(file != NULL, "regular file still present");
  if (file == NULL) return;
  count = fread(data, 1, sizeof(data) - 1u, file);
  data[count] = '\0';
  check(strcmp(data, "keep") == 0, "regular file contents intact");
  fclose(file);
}

static void test_symlink(const char *dir) {
  char target[256];
  char link[256];
  struct stat st;
  int fd = -1;

  snprintf(target, sizeof(target), "%s/target.sock", dir);
  snprintf(link, sizeof(link), "%s/link.sock", dir);
  if (symlink(target, link) != 0) {
    check(0, "create symlink");
    return;
  }
  check(ap_sys_server_open(link, &fd) == AP_ERR_STATE, "symlink rejected");
  check(lstat(link, &st) == 0 && S_ISLNK(st.st_mode), "symlink still present");
}

static void expect_auth(int fd, int cfd, const uint8_t *key, ap_packet *packet,
                        const char *name) {
  ap_event out;
  size_t received = 0;
  check(ap_sys_write_all(cfd, packet->data, sizeof(packet->data)) == AP_OK, name);
  check(wait_input(fd) == 1, name);
  check(ap_sys_recv_sealed(fd, key, &out, sizeof(out), &received) == AP_ERR_AUTH, name);
}

static void test_exact_size(const char *dir) {
  char path[256];
  char keypath[256];
  char raw[sizeof(ap_event) + 16u];
  ap_event event;
  ap_event out;
  ap_verdict verdict;
  ap_packet packet;
  uint8_t key[AP_TRANSPORT_KEY_LEN];
  uint8_t loaded[AP_TRANSPORT_KEY_LEN];
  struct stat st;
  unsigned char *sink;
  size_t received = 0;
  int sfd = -1;
  int cfd = -1;

  snprintf(path, sizeof(path), "%s/exact.sock", dir);
  check(ap_sys_server_open(path, &sfd) == AP_OK, "server open");
  check(ap_sys_client_open(path, &cfd) == AP_OK, "client open");
  check(ap_transport_key_create(path, key) == AP_OK, "key create");
  check(ap_transport_key_load(path, loaded) == AP_OK, "key load");
  check(memcmp(key, loaded, sizeof(key)) == 0, "key reload");
  check(ap_transport_key_path(path, keypath, sizeof(keypath)) == AP_OK, "key path");
  check(stat(keypath, &st) == 0 && (st.st_mode & 0777) == 0600, "key mode 0600");
  if (sfd < 0 || cfd < 0) {
    if (sfd >= 0) close(sfd);
    if (cfd >= 0) close(cfd);
    unlink(path);
    unlink(keypath);
    return;
  }

  ap_event_init(&event, AP_KIND_HEARTBEAT);
  event.seq = 7;
  check(ap_sys_send_sealed(cfd, key, &event) == AP_OK, "send sealed event");
  check(wait_input(sfd) == 1, "sealed event ready");
  memset(&out, 0, sizeof(out));
  check(ap_sys_recv_sealed(sfd, key, &out, sizeof(out), &received) == AP_OK,
        "sealed datagram accepted");
  check(received == sizeof(ap_event) && out.seq == 7 && out.kind == AP_KIND_HEARTBEAT,
        "sealed datagram contents");

  check(ap_sys_send_sealed(cfd, key, &event) == AP_OK, "send capacity event");
  check(wait_input(sfd) == 1, "capacity event ready");
  sink = (unsigned char *)&verdict;
  check(ap_sys_recv_sealed(sfd, key, sink, sizeof(verdict), &received) == AP_ERR_RANGE,
        "small receive capacity rejected");
  check(wait_input(sfd) == 1, "capacity event still queued");
  check(ap_sys_recv_sealed(sfd, key, &out, sizeof(out), &received) == AP_OK,
        "capacity event preserved");
  check(out.seq == 7, "capacity event contents");

  memset(raw, 0x41, sizeof(raw));
  check(ap_sys_write_all(cfd, raw, 8u) == AP_OK, "send short datagram");
  check(wait_input(sfd) == 1, "short datagram ready");
  check(ap_sys_recv_sealed(sfd, key, &out, sizeof(out), &received) == AP_ERR_RANGE,
        "short datagram rejected");

  check(ap_sys_write_all(cfd, raw, sizeof(raw)) == AP_OK, "send oversized datagram");
  check(wait_input(sfd) == 1, "oversized datagram ready");
  check(ap_sys_recv_sealed(sfd, key, &out, sizeof(out), &received) == AP_ERR_RANGE,
        "oversized datagram rejected");

  check(ap_sys_write_all(cfd, &event, sizeof(event)) == AP_OK, "send unsigned event");
  check(wait_input(sfd) == 1, "unsigned event ready");
  check(ap_sys_recv_sealed(sfd, key, &out, sizeof(out), &received) == AP_ERR_RANGE,
        "unsigned event rejected");

  check(ap_transport_seal(key, &event, &packet) == AP_OK, "seal tamper base");
  packet.data[AP_TRANSPORT_HEADER_LEN] ^= 0x01u;
  expect_auth(sfd, cfd, key, &packet, "modified event rejected");

  check(ap_transport_seal(key, &event, &packet) == AP_OK, "seal magic base");
  packet.data[0] ^= 0x01u;
  expect_auth(sfd, cfd, key, &packet, "bad magic rejected");

  check(ap_transport_seal(key, &event, &packet) == AP_OK, "seal version base");
  packet.data[4] = (uint8_t)(AP_TRANSPORT_VERSION + 1u);
  expect_auth(sfd, cfd, key, &packet, "bad version rejected");

  check(ap_transport_seal(key, &event, &packet) == AP_OK, "seal tag base");
  packet.data[AP_TRANSPORT_PACKET_LEN - 1u] ^= 0x80u;
  expect_auth(sfd, cfd, key, &packet, "bad tag rejected");

  close(cfd);
  close(sfd);
  unlink(path);
  unlink(keypath);
}

static void test_key_permissions(const char *dir) {
  char path[256];
  char keypath[256];
  uint8_t key[AP_TRANSPORT_KEY_LEN];
  uint8_t bytes[AP_TRANSPORT_KEY_LEN];
  FILE *file;

  snprintf(path, sizeof(path), "%s/perm.sock", dir);
  check(ap_transport_key_path(path, keypath, sizeof(keypath)) == AP_OK, "perm key path");
  memset(bytes, 0, sizeof(bytes));
  file = fopen(keypath, "wb");
  check(file != NULL, "create loose key");
  if (file == NULL) return;
  check(fwrite(bytes, 1u, sizeof(bytes), file) == sizeof(bytes), "write loose key");
  fclose(file);
  check(chmod(keypath, 0644) == 0, "loose key mode");
  check(ap_transport_key_load(path, key) == AP_ERR_STATE, "loose key rejected");
  unlink(keypath);
}

static void write_key_file(const char *path, const uint8_t *key) {
  FILE *file = fopen(path, "wb");
  check(file != NULL, "create client key file");
  if (file == NULL) return;
  check(fwrite(key, 1u, AP_TRANSPORT_KEY_LEN, file) == AP_TRANSPORT_KEY_LEN,
        "write client key file");
  fclose(file);
  check(chmod(path, 0600) == 0, "client key mode");
}

static void test_client_keys(const char *dir) {
  char path[256];
  char first_path[256];
  char second_path[256];
  uint8_t first[AP_TRANSPORT_KEY_LEN];
  uint8_t second[AP_TRANSPORT_KEY_LEN];
  uint8_t loaded[AP_TRANSPORT_KEY_LEN];
  ap_client_keys keys;
  ap_event event;
  ap_event out;
  size_t received = 0;
  int sfd = -1;
  int cfd = -1;

  snprintf(path, sizeof(path), "%s/client.sock", dir);
  snprintf(first_path, sizeof(first_path), "%s/client.first.key", dir);
  snprintf(second_path, sizeof(second_path), "%s/client.second.key", dir);
  memset(first, 0x31, sizeof(first));
  memset(second, 0x72, sizeof(second));
  write_key_file(first_path, first);
  write_key_file(second_path, second);
  check(ap_transport_key_load_path(first_path, loaded) == AP_OK, "load explicit key path");
  check(memcmp(first, loaded, sizeof(first)) == 0, "explicit key bytes");

  check(ap_sys_server_open(path, &sfd) == AP_OK, "client key server open");
  check(ap_sys_client_open(path, &cfd) == AP_OK, "client key client open");
  check(ap_client_keys_init(&keys) == AP_OK, "client keys init");
  check(ap_client_keys_add(&keys, (uint32_t)getpid(), first) == AP_OK, "client keys add");
  ap_event_init(&event, AP_KIND_HEARTBEAT);
  event.seq = 77u;

  check(ap_sys_send_sealed(cfd, first, &event) == AP_OK, "send mapped key event");
  check(wait_input(sfd) == 1, "mapped key event ready");
  check(ap_sys_recv_sealed_client(sfd, &keys, &out, sizeof(out), &received, NULL, 0) == AP_OK,
        "mapped key accepted");
  check(received == sizeof(ap_event) && out.seq == 77u, "mapped key contents");
  check(keys.matched == 1u && keys.unmatched == 0u, "mapped key counters");

  check(ap_sys_send_sealed(cfd, second, &event) == AP_OK, "send wrong key event");
  check(wait_input(sfd) == 1, "wrong key event ready");
  check(ap_sys_recv_sealed_client(sfd, &keys, &out, sizeof(out), &received, NULL, 0) == AP_ERR_AUTH,
        "wrong key rejected");
  check(keys.matched == 2u && keys.unmatched == 0u, "wrong key counters");

  check(ap_client_keys_init(&keys) == AP_OK, "unmapped keys init");
  check(ap_client_keys_add(&keys, (uint32_t)getpid() + 1000u, second) == AP_OK,
        "unmapped keys add");
  check(ap_sys_send_sealed(cfd, first, &event) == AP_OK, "send unmapped event");
  check(wait_input(sfd) == 1, "unmapped event ready");
  check(ap_sys_recv_sealed_client(sfd, &keys, &out, sizeof(out), &received, NULL, 0) == AP_ERR_AUTH,
        "unmapped pid rejected");
  check(keys.matched == 0u && keys.unmatched == 1u, "unmapped counters");

  if (cfd >= 0) close(cfd);
  if (sfd >= 0) close(sfd);
  unlink(path);
  unlink(first_path);
  unlink(second_path);
}

static void test_foreign_uid(const char *dir) {
  char path[256];
  char keypath[256];
  ap_event event;
  uint8_t key[AP_TRANSPORT_KEY_LEN];
  size_t received = 0;
  int sfd = -1;
  int status = 0;
  pid_t child;

  snprintf(path, sizeof(path), "%s/uid.sock", dir);
  check(ap_sys_server_open(path, &sfd) == AP_OK, "uid server open");
  if (sfd < 0) return;
  check(ap_transport_key_create(path, key) == AP_OK, "uid key create");
  check(ap_transport_key_path(path, keypath, sizeof(keypath)) == AP_OK, "uid key path");
  check(chmod(path, 0666) == 0, "allow foreign sender connect");

  child = fork();
  if (child == 0) {
    int cfd = -1;
    if (setuid(65534) != 0) _exit(2);
    if (ap_sys_client_open(path, &cfd) != AP_OK) _exit(3);
    ap_event_init(&event, AP_KIND_HEARTBEAT);
    if (ap_sys_send_sealed(cfd, key, &event) != AP_OK) _exit(4);
    close(cfd);
    _exit(0);
  }
  check(child > 0, "foreign sender fork");
  if (child > 0) {
    check(waitpid(child, &status, 0) == child, "foreign sender exit");
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0 && geteuid() != 65534) {
      check(wait_input(sfd) == 1, "foreign datagram ready");
      check(ap_sys_recv_sealed(sfd, key, &event, sizeof(event), &received) == AP_ERR_STATE,
            "foreign uid rejected");
    } else if (geteuid() == 0) {
      check(0, "foreign sender setup");
    }
  }
  close(sfd);
  unlink(path);
  unlink(keypath);
}

int main(void) {
  char dir[] = "/tmp/ap-ipc-test-XXXXXX";
  struct stat st;

  if (mkdtemp(dir) == NULL) {
    fprintf(stderr, "ipc test: cannot create temp dir\n");
    return 1;
  }
  test_regular_file(dir);
  test_symlink(dir);
  test_exact_size(dir);
  test_key_permissions(dir);
  test_client_keys(dir);
  if (chmod(dir, 0755) == 0) {
    test_foreign_uid(dir);
  }
  check(stat(dir, &st) == 0, "temp dir intact");
  {
    char path[256];
    snprintf(path, sizeof(path), "%s/keep.txt", dir);
    unlink(path);
    snprintf(path, sizeof(path), "%s/link.sock", dir);
    unlink(path);
  }
  rmdir(dir);
  printf("ipc tests: %s\n", failures == 0 ? "ok" : "failed");
  return failures == 0 ? 0 : 1;
}
