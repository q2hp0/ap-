#define _GNU_SOURCE
#include "apcapture.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define AP_CAPTURE_IFACE 0u
#define AP_CAPTURE_FILE 1u

struct ap_capture {
  int fd;
  uint32_t mode;
  uint32_t snaplen;
  uint64_t seq;
  uint8_t pending[2];
  uint32_t pending_have;
  ap_capture_counters stats;
};

static ap_capture *capture_alloc(int fd, uint32_t mode, uint32_t snaplen) {
  ap_capture *capture;

  if (fd < 0 || snaplen < AP_CAPTURE_SNAP_MIN || snaplen > AP_CAPTURE_SNAP_MAX) {
    if (fd >= 0) close(fd);
    return NULL;
  }
  capture = (ap_capture *)calloc(1u, sizeof(*capture));
  if (capture == NULL) {
    close(fd);
    return NULL;
  }
  capture->fd = fd;
  capture->mode = mode;
  capture->snaplen = snaplen;
  return capture;
}

ap_capture *ap_capture_open_iface(const char *ifname, uint32_t snaplen) {
  struct sockaddr_ll address;
  int fd;
  int buffer = 1024 * 1024;

  if (ifname == NULL || ifname[0] == '\0') return NULL;
  fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
              htons((uint16_t)ETH_P_ALL));
  if (fd < 0) return NULL;
  (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buffer, sizeof(buffer));
  memset(&address, 0, sizeof(address));
  address.sll_family = AF_PACKET;
  address.sll_protocol = htons((uint16_t)ETH_P_ALL);
  if (strcmp(ifname, "any") != 0) {
    address.sll_ifindex = (int)if_nametoindex(ifname);
    if (address.sll_ifindex == 0) {
      close(fd);
      return NULL;
    }
  }
  if (bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
    close(fd);
    return NULL;
  }
  return capture_alloc(fd, AP_CAPTURE_IFACE, snaplen);
}

ap_capture *ap_capture_open_file(const char *path, uint32_t snaplen) {
  int fd;

  if (path == NULL || path[0] == '\0') return NULL;
  fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0) return NULL;
  return capture_alloc(fd, AP_CAPTURE_FILE, snaplen);
}

void ap_capture_free(ap_capture *capture) {
  if (capture == NULL) return;
  if (capture->fd >= 0) close(capture->fd);
  free(capture);
}

int ap_capture_fd(const ap_capture *capture) {
  return capture == NULL ? -1 : capture->fd;
}

static size_t link_offset(const uint8_t *frame, size_t len, uint16_t *type) {
  size_t offset = (size_t)ETH_HLEN;
  uint16_t value;

  if (len < offset) return 0;
  value = (uint16_t)(((uint16_t)frame[12] << 8) | frame[13]);
  for (uint32_t tags = 0u; tags < 2u; ++tags) {
    if (value != ETH_P_8021Q && value != ETH_P_8021AD) break;
    if (len < offset + 4u) return 0;
    value = (uint16_t)(((uint16_t)frame[offset + 2] << 8) | frame[offset + 3]);
    offset += 4u;
  }
  *type = value;
  if (value != ETH_P_IP && value != ETH_P_IPV6) return 0;
  return len > offset ? offset : 0;
}

static void emit_frame(ap_capture *capture, const uint8_t *frame, size_t len,
                       ap_capture_cb callback, void *user) {
  uint16_t type = 0u;
  size_t offset = link_offset(frame, len, &type);
  size_t ip_len;
  char hex[AP_TEXT_LEN];
  ap_event event;

  ++capture->stats.frames;
  if (offset == 0u) {
    ++capture->stats.invalid;
    return;
  }
  ip_len = len - offset;
  if (ip_len > capture->snaplen) {
    ip_len = capture->snaplen;
    ++capture->stats.truncated;
  }
  if (ip_len == 0u || (ip_len * 2u + 1u) > sizeof(hex)) {
    ++capture->stats.invalid;
    return;
  }
  if (ap_hex_encode(frame + offset, ip_len, hex, sizeof(hex)) != AP_OK) {
    ++capture->stats.invalid;
    return;
  }
  ap_event_init(&event, AP_KIND_NET);
  event.seq = ++capture->seq;
  event.ts_ns = ap_clock_ns();
  event.pid = -1;
  event.tid = -1;
  event.subkind = AP_NET_PACKET;
  event.severity = AP_SEV_HIGH;
  event.confidence_x1000 = 900u;
  event.arg[3] = AP_CAPTURE_SOURCE_MARK;
  memcpy(event.text, hex, strlen(hex) + 1u);
  if (callback != NULL && callback(&event, user) != 0) {
    ++capture->stats.errors;
  }
  ++capture->stats.parsed;
}

static int read_af_packet(ap_capture *capture, ap_capture_cb callback, void *user) {
  uint8_t frame[AP_CAPTURE_FRAME_MAX];
  ssize_t received;

  received = recv(capture->fd, frame, sizeof(frame), MSG_DONTWAIT);
  if (received > 0) {
    emit_frame(capture, frame, (size_t)received, callback, user);
    return AP_OK;
  }
  if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return AP_OK;
  ++capture->stats.errors;
  return AP_ERR_IO;
}

static int read_exact(ap_capture *capture, uint8_t *out, size_t len, int *eof) {
  size_t have = 0u;

  while (have < len) {
    ssize_t received = read(capture->fd, out + have, len - have);
    if (received > 0) {
      have += (size_t)received;
      continue;
    }
    if (received == 0) {
      *eof = 1;
      return AP_ERR_IO;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) return AP_OK;
    ++capture->stats.errors;
    return AP_ERR_IO;
  }
  return AP_OK;
}

static int read_file_frame(ap_capture *capture, ap_capture_cb callback, void *user) {
  uint8_t frame[AP_CAPTURE_FRAME_MAX];
  uint32_t initial;
  uint16_t len;
  int status;
  int eof = 0;

  if (capture->pending_have < 2u) {
    initial = capture->pending_have;
    status = read_exact(capture, capture->pending + initial,
                        2u - initial, &eof);
    if (status != AP_OK) {
      if (eof != 0 && initial != 0u) ++capture->stats.invalid;
      return status;
    }
    capture->pending_have = 2u;
  }
  len = (uint16_t)((uint16_t)capture->pending[0] |
                   ((uint16_t)capture->pending[1] << 8));
  capture->pending_have = 0u;
  if (len == 0u || len > sizeof(frame)) {
    ++capture->stats.invalid;
    return AP_OK;
  }
  status = read_exact(capture, frame, (size_t)len, &eof);
  if (status != AP_OK) {
    if (eof != 0) ++capture->stats.invalid;
    return status;
  }
  emit_frame(capture, frame, (size_t)len, callback, user);
  return AP_OK;
}

int ap_capture_poll(ap_capture *capture, uint32_t max_frames,
                    ap_capture_cb callback, void *user, int timeout_ms) {
  struct pollfd descriptor;
  uint32_t handled = 0u;

  if (capture == NULL || max_frames == 0u) return AP_ERR_ARG;
  if (max_frames > AP_CAPTURE_MAX_FRAMES) max_frames = AP_CAPTURE_MAX_FRAMES;
  descriptor.fd = capture->fd;
  descriptor.events = POLLIN;
  descriptor.revents = 0;
  int ready = poll(&descriptor, 1u, timeout_ms);
  if (ready < 0) {
    if (errno == EINTR) return AP_OK;
    ++capture->stats.errors;
    return AP_ERR_IO;
  }
  if (ready == 0 || (descriptor.revents & POLLIN) == 0) return AP_OK;
  while (handled < max_frames) {
    int status = capture->mode == AP_CAPTURE_IFACE
                     ? read_af_packet(capture, callback, user)
                     : read_file_frame(capture, callback, user);
    if (status != AP_OK) return status;
    ++handled;
    if (capture->mode == AP_CAPTURE_FILE && capture->pending_have != 0u) break;
  }
  return AP_OK;
}

int ap_capture_stats(const ap_capture *capture, ap_capture_counters *out) {
  if (capture == NULL || out == NULL) return AP_ERR_ARG;
  *out = capture->stats;
  return AP_OK;
}
