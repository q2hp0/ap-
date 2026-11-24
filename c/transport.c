#define _GNU_SOURCE
#include "aptransport.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

_Static_assert(sizeof(ap_event) == AP_TRANSPORT_EVENT_LEN, "event layout changed");
_Static_assert(AP_TRANSPORT_HEADER_LEN + AP_TRANSPORT_EVENT_LEN + AP_TRANSPORT_TAG_LEN ==
                   AP_TRANSPORT_PACKET_LEN,
               "transport layout changed");

static int ap_read_exact(int fd, void *buf, size_t len) {
  uint8_t *bytes = (uint8_t *)buf;
  size_t done = 0u;
  while (done < len) {
    ssize_t count = read(fd, bytes + done, len - done);
    if (count > 0) {
      done += (size_t)count;
      continue;
    }
    if (count < 0 && errno == EINTR) continue;
    return AP_ERR_IO;
  }
  return AP_OK;
}

static int ap_write_exact(int fd, const void *buf, size_t len) {
  const uint8_t *bytes = (const uint8_t *)buf;
  size_t done = 0u;
  while (done < len) {
    ssize_t count = write(fd, bytes + done, len - done);
    if (count > 0) {
      done += (size_t)count;
      continue;
    }
    if (count < 0 && errno == EINTR) continue;
    return AP_ERR_IO;
  }
  return AP_OK;
}

static int ap_random_bytes(void *buf, size_t len) {
  uint8_t *bytes = (uint8_t *)buf;
  size_t done = 0u;
#ifdef SYS_getrandom
  while (done < len) {
    ssize_t count = syscall(SYS_getrandom, bytes + done, len - done, 0u);
    if (count > 0) {
      done += (size_t)count;
      continue;
    }
    if (count < 0 && errno == EINTR) continue;
    if (count < 0 && errno == ENOSYS) break;
    return AP_ERR_IO;
  }
#endif
  if (done == len) return AP_OK;
  {
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    int status;
    if (fd < 0) return AP_ERR_IO;
    status = ap_read_exact(fd, bytes + done, len - done);
    close(fd);
    return status;
  }
}

int ap_transport_key_path(const char *socket_path, char *out, size_t cap) {
  size_t len;
  if (socket_path == NULL || out == NULL || cap == 0u || *socket_path == '\0') return AP_ERR_ARG;
  len = strlen(socket_path);
  if (len > AP_TRANSPORT_MAX_PATH || len + 5u > cap) return AP_ERR_RANGE;
  memcpy(out, socket_path, len);
  memcpy(out + len, ".key", 5u);
  return AP_OK;
}

static int ap_key_read_path(const char *path, uint8_t key[AP_TRANSPORT_KEY_LEN]) {
  struct stat st;
  int fd;
  int status;

  fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return AP_ERR_IO;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size != AP_TRANSPORT_KEY_LEN ||
      st.st_uid != geteuid() || (st.st_mode & 0077) != 0) {
    close(fd);
    return AP_ERR_STATE;
  }
  status = ap_read_exact(fd, key, AP_TRANSPORT_KEY_LEN);
  close(fd);
  return status;
}

static int ap_key_create_path(const char *path, uint8_t key[AP_TRANSPORT_KEY_LEN]) {
  uint8_t fresh[AP_TRANSPORT_KEY_LEN];
  int fd;
  int status;

  status = ap_key_read_path(path, key);
  if (status == AP_OK) return AP_OK;
  if (status != AP_ERR_IO) return status;

  status = ap_random_bytes(fresh, sizeof(fresh));
  if (status != AP_OK) return status;
  fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0) {
    if (errno == EEXIST) return ap_key_read_path(path, key);
    return AP_ERR_IO;
  }
  status = ap_write_exact(fd, fresh, sizeof(fresh));
  if (status == AP_OK && fsync(fd) != 0) status = AP_ERR_IO;
  if (close(fd) != 0) status = AP_ERR_IO;
  if (status != AP_OK) {
    unlink(path);
    return status;
  }
  memcpy(key, fresh, sizeof(fresh));
  return AP_OK;
}

int ap_transport_key_create(const char *socket_path, uint8_t key[AP_TRANSPORT_KEY_LEN]) {
  char path[AP_TRANSPORT_MAX_PATH];
  int status;

  if (key == NULL) return AP_ERR_ARG;
  status = ap_transport_key_path(socket_path, path, sizeof(path));
  if (status != AP_OK) return status;
  return ap_key_create_path(path, key);
}

int ap_transport_key_create_path(const char *path, uint8_t key[AP_TRANSPORT_KEY_LEN]) {
  if (path == NULL || key == NULL || *path == '\0') return AP_ERR_ARG;
  if (strlen(path) > AP_TRANSPORT_MAX_PATH) return AP_ERR_RANGE;
  return ap_key_create_path(path, key);
}

int ap_transport_key_load(const char *socket_path, uint8_t key[AP_TRANSPORT_KEY_LEN]) {
  char path[AP_TRANSPORT_MAX_PATH];
  int status;

  if (key == NULL) return AP_ERR_ARG;
  status = ap_transport_key_path(socket_path, path, sizeof(path));
  if (status != AP_OK) return status;
  return ap_key_read_path(path, key);
}

int ap_transport_key_load_path(const char *path, uint8_t key[AP_TRANSPORT_KEY_LEN]) {
  if (path == NULL || key == NULL || *path == '\0') return AP_ERR_ARG;
  if (strlen(path) > AP_TRANSPORT_MAX_PATH) return AP_ERR_RANGE;
  return ap_key_read_path(path, key);
}

int ap_transport_seal(const uint8_t key[AP_TRANSPORT_KEY_LEN], const ap_event *event,
                      ap_packet *packet) {
  size_t covered = AP_TRANSPORT_PACKET_LEN - AP_TRANSPORT_TAG_LEN;

  if (key == NULL || event == NULL || packet == NULL) return AP_ERR_ARG;
  memset(packet->data, 0, sizeof(packet->data));
  packet->data[0] = (uint8_t)(AP_TRANSPORT_MAGIC >> 24);
  packet->data[1] = (uint8_t)(AP_TRANSPORT_MAGIC >> 16);
  packet->data[2] = (uint8_t)(AP_TRANSPORT_MAGIC >> 8);
  packet->data[3] = (uint8_t)AP_TRANSPORT_MAGIC;
  packet->data[4] = (uint8_t)AP_TRANSPORT_VERSION;
  packet->data[5] = (uint8_t)AP_TRANSPORT_TYPE_EVENT;
  memcpy(packet->data + AP_TRANSPORT_HEADER_LEN, event, sizeof(ap_event));
  ap_hmac_sha256(key, AP_TRANSPORT_KEY_LEN, packet->data, covered,
                 packet->data + covered);
  return AP_OK;
}

int ap_transport_open(const uint8_t key[AP_TRANSPORT_KEY_LEN], const ap_packet *packet,
                      size_t len, ap_event *event) {
  uint8_t expected[AP_TRANSPORT_TAG_LEN];
  size_t covered = AP_TRANSPORT_PACKET_LEN - AP_TRANSPORT_TAG_LEN;

  if (key == NULL || packet == NULL || event == NULL) return AP_ERR_ARG;
  if (len != AP_TRANSPORT_PACKET_LEN) return AP_ERR_RANGE;
  if (packet->data[0] != (uint8_t)(AP_TRANSPORT_MAGIC >> 24) ||
      packet->data[1] != (uint8_t)(AP_TRANSPORT_MAGIC >> 16) ||
      packet->data[2] != (uint8_t)(AP_TRANSPORT_MAGIC >> 8) ||
      packet->data[3] != (uint8_t)AP_TRANSPORT_MAGIC ||
      packet->data[4] != (uint8_t)AP_TRANSPORT_VERSION ||
      packet->data[5] != (uint8_t)AP_TRANSPORT_TYPE_EVENT ||
      packet->data[6] != 0u || packet->data[7] != 0u) {
    return AP_ERR_AUTH;
  }
  ap_hmac_sha256(key, AP_TRANSPORT_KEY_LEN, packet->data, covered, expected);
  if (!ap_constant_time_eq(expected, packet->data + covered, AP_TRANSPORT_TAG_LEN)) {
    return AP_ERR_AUTH;
  }
  memcpy(event, packet->data + AP_TRANSPORT_HEADER_LEN, sizeof(ap_event));
  return AP_OK;
}
