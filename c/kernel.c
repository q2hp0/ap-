#define _POSIX_C_SOURCE 200809L
#include "apkernel.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

_Static_assert(sizeof(ap_event) == 216u, "kernel event abi must be 216 bytes");

static const uint8_t ap_kernel_magic[4] = { 'a', 'p', 'k', '1' };

struct ap_kernel {
  uint32_t count;
  uint32_t next;
  ap_event *events;
  ap_kernel_counters stats;
};

static int read_exact_fd(int fd, uint8_t *out, size_t len) {
  size_t have = 0u;

  while (have < len) {
    ssize_t received = read(fd, out + have, len - have);
    if (received > 0) {
      have += (size_t)received;
      continue;
    }
    if (received == 0) return AP_ERR_IO;
    if (errno == EINTR) continue;
    return AP_ERR_IO;
  }
  return AP_OK;
}

static ap_kernel *kernel_new(uint32_t raw_count) {
  ap_kernel *kernel = (ap_kernel *)calloc(1u, sizeof(*kernel));

  if (kernel == NULL) return NULL;
  kernel->stats.frames = raw_count;
  if (raw_count > 0u) {
    kernel->events = (ap_event *)calloc(raw_count, sizeof(ap_event));
    if (kernel->events == NULL) {
      free(kernel);
      return NULL;
    }
  }
  return kernel;
}

static int event_valid(const ap_event *event) {
  if (event->size != sizeof(ap_event)) return 0;
  if (event->abi_version != AP_ABI_VERSION) return 0;
  if (event->kind == AP_KIND_NONE || event->kind > AP_KIND_HEARTBEAT) return 0;
  return memchr(event->text, 0, sizeof(event->text)) != NULL;
}

ap_kernel *ap_kernel_open_file(const char *path) {
  uint8_t header[AP_KERNEL_HEADER_SIZE];
  struct stat info;
  ap_kernel *kernel;
  uint32_t raw_count;
  uint64_t expected;
  int fd;
  int status;
  uint32_t index;
  uint32_t valid = 0u;

  if (path == NULL || path[0] == '\0') return NULL;
  fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return NULL;
  if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode)) {
    close(fd);
    return NULL;
  }
  if (read_exact_fd(fd, header, sizeof(header)) != AP_OK) {
    close(fd);
    return NULL;
  }
  if (memcmp(header, ap_kernel_magic, sizeof(ap_kernel_magic)) != 0) {
    close(fd);
    return NULL;
  }
  raw_count = (uint32_t)header[4] |
              ((uint32_t)header[5] << 8) |
              ((uint32_t)header[6] << 16) |
              ((uint32_t)header[7] << 24);
  if (raw_count > AP_KERNEL_MAX_EVENTS) {
    close(fd);
    return NULL;
  }
  expected = (uint64_t)AP_KERNEL_HEADER_SIZE +
             (uint64_t)raw_count * (uint64_t)sizeof(ap_event);
  if (info.st_size < 0 || (uint64_t)info.st_size != expected) {
    close(fd);
    return NULL;
  }
  kernel = kernel_new(raw_count);
  if (kernel == NULL) {
    close(fd);
    return NULL;
  }
  status = raw_count == 0u
               ? AP_OK
               : read_exact_fd(fd, (uint8_t *)kernel->events,
                               (size_t)(expected - AP_KERNEL_HEADER_SIZE));
  close(fd);
  if (status != AP_OK) {
    ap_kernel_free(kernel);
    return NULL;
  }
  for (index = 0u; index < raw_count; ++index) {
    ap_event *event = &kernel->events[index];
    if (!event_valid(event)) {
      ++kernel->stats.invalid;
      continue;
    }
    if (event->kind != AP_KIND_NET) {
      event->arg[3] = AP_KERNEL_SOURCE_MARK;
    }
    kernel->events[valid] = *event;
    ++valid;
  }
  kernel->count = valid;
  return kernel;
}

void ap_kernel_free(ap_kernel *kernel) {
  if (kernel == NULL) return;
  free(kernel->events);
  free(kernel);
}

uint32_t ap_kernel_pending(const ap_kernel *kernel) {
  if (kernel == NULL || kernel->next >= kernel->count) return 0u;
  return kernel->count - kernel->next;
}

int ap_kernel_poll(ap_kernel *kernel, uint32_t max_events,
                   ap_kernel_cb callback, void *user) {
  uint32_t handled = 0u;

  if (kernel == NULL || max_events == 0u) return AP_ERR_ARG;
  while (kernel->next < kernel->count && handled < max_events) {
    const ap_event *event = &kernel->events[kernel->next];
    ++kernel->next;
    ++handled;
    if (callback != NULL && callback(event, user) != 0) {
      ++kernel->stats.errors;
      return AP_ERR_STATE;
    }
    ++kernel->stats.parsed;
  }
  return AP_OK;
}

int ap_kernel_stats(const ap_kernel *kernel, ap_kernel_counters *out) {
  if (kernel == NULL || out == NULL) return AP_ERR_ARG;
  *out = kernel->stats;
  return AP_OK;
}
