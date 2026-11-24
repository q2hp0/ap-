#define _GNU_SOURCE
#include "apheap.h"
#include "aptransport.h"

#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#define AP_HEAP_MAGIC 0x4150484541503031ull
#define AP_HEAP_ACTIVE 0x4150435449564500ull
#define AP_HEAP_DEAD 0x4455414442454144ull
#define AP_HEAP_GUARD 0xa5a5c3c3f00d1234ull

typedef void *(*ap_alloc_fn)(size_t);
typedef void (*ap_free_fn)(void *);
typedef struct ap_block {
  uint64_t magic;
  uint64_t size;
  uint64_t canary;
  uint64_t state;
  uint64_t offset;
  uint64_t owner;
} ap_block;

extern void *__libc_malloc(size_t) __attribute__((weak));
extern void __libc_free(void *) __attribute__((weak));
static ap_alloc_fn heap_alloc = NULL;
static ap_free_fn heap_free_fn = NULL;
static pthread_mutex_t heap_lock = PTHREAD_MUTEX_INITIALIZER;
static __thread int heap_in_hook = 0;
static int heap_socket_fd = -1;
static int heap_socket_tried = 0;
static uint8_t heap_key[AP_TRANSPORT_KEY_LEN];
static int heap_key_tried = 0;
static int heap_key_ready = 0;
static void *heap_ring[AP_HEAP_QUARANTINE];
static uint32_t heap_ring_pos = 0;

static void *heap_raw_alloc(size_t size) {
  if (heap_alloc != NULL) return heap_alloc(size);
  if (__libc_malloc != NULL) return __libc_malloc(size);
  return NULL;
}

static void heap_raw_free(void *ptr) {
  if (heap_free_fn != NULL) {
    heap_free_fn(ptr);
  } else if (__libc_free != NULL) {
    __libc_free(ptr);
  }
}

__attribute__((constructor)) static void heap_init(void) {
  if (heap_alloc == NULL) heap_alloc = (ap_alloc_fn)dlsym(RTLD_NEXT, "malloc");
  if (heap_free_fn == NULL) heap_free_fn = (ap_free_fn)dlsym(RTLD_NEXT, "free");
}

static uint64_t heap_tid(void) {
#ifdef SYS_gettid
  return (uint64_t)syscall(SYS_gettid);
#else
  return (uint64_t)getpid();
#endif
}

static int heap_socket(void) {
  struct sockaddr_un addr;
  const char *path;
  int fd;

  if (heap_socket_tried) return heap_socket_fd;
  heap_socket_tried = 1;
  path = getenv(AP_HEAP_ENV_SOCKET);
  if (path == NULL || *path == '\0' || strlen(path) >= sizeof(addr.sun_path)) {
    return -1;
  }
  fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return -1;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(fd);
    return -1;
  }
  heap_socket_fd = fd;
  return fd;
}

static int heap_key_load(void) {
  const char *path;
  if (heap_key_tried) return heap_key_ready;
  heap_key_tried = 1;
  path = getenv(AP_HEAP_ENV_SOCKET);
  if (path == NULL || *path == '\0') return 0;
  if (ap_transport_key_load(path, heap_key) == AP_OK) heap_key_ready = 1;
  return heap_key_ready;
}

static void heap_report(uint32_t subkind, const void *ptr, size_t size, const char *detail) {
  ap_event event;
  ap_packet packet;
  int fd;

  fd = heap_socket();
  if (fd < 0 || !heap_key_load()) return;
  ap_event_init(&event, AP_KIND_HEAP);
  event.pid = getpid();
  event.tid = (int64_t)heap_tid();
  event.subkind = subkind;
  event.severity = subkind == AP_HEAP_DOUBLE_FREE || subkind == AP_HEAP_OVERFLOW
                       ? AP_SEV_HIGH : AP_SEV_MEDIUM;
  event.confidence_x1000 = 930u;
  event.arg[0] = (uint64_t)(uintptr_t)ptr;
  event.arg[1] = (uint64_t)size;
  event.arg[2] = heap_tid();
  snprintf(event.text, sizeof(event.text), "%s", detail);
  if (ap_transport_seal(heap_key, &event, &packet) != AP_OK) return;
  (void)send(fd, packet.data, sizeof(packet.data), MSG_NOSIGNAL | MSG_DONTWAIT);
}

static uint64_t heap_canary(const void *base, uint64_t size) {
  uint64_t value = AP_HEAP_MAGIC ^ size ^ ((uint64_t)(uintptr_t)base * 1099511628211ull);
  return value ^ AP_HEAP_GUARD;
}

static size_t heap_align(size_t value, size_t alignment) {
  return (value + alignment - 1u) & ~(alignment - 1u);
}

static void *heap_allocate(size_t size, size_t alignment) {
  ap_block *block;
  void *base;
  uint8_t *user;
  uint64_t aligned;
  size_t total;

  if (alignment < 16u) alignment = 16u;
  aligned = heap_align(size ? size : 1u, 16u);
  total = sizeof(ap_block) + alignment + (size_t)aligned + sizeof(uint64_t);
  if (total < size || total > (size_t)-1 / 2u) {
    return NULL;
  }
  pthread_mutex_lock(&heap_lock);
  heap_in_hook = 1;
  base = heap_raw_alloc(total);
  if (base == NULL) {
    heap_in_hook = 0;
    pthread_mutex_unlock(&heap_lock);
    return NULL;
  }
  user = (uint8_t *)heap_align((uintptr_t)base + sizeof(ap_block), alignment);
  block = (ap_block *)(user - sizeof(ap_block));
  block->magic = AP_HEAP_MAGIC;
  block->size = (uint64_t)size;
  block->canary = heap_canary(base, (uint64_t)size);
  block->state = AP_HEAP_ACTIVE;
  block->offset = (uint64_t)(user - (uint8_t *)base);
  block->owner = heap_tid();
  memcpy(user + aligned, &block->canary, sizeof(uint64_t));
  heap_in_hook = 0;
  pthread_mutex_unlock(&heap_lock);
  return user;
}

void *malloc(size_t size) {
  return heap_allocate(size, 16u);
}

void *calloc(size_t count, size_t size) {
  void *ptr;
  if (count != 0u && size > (size_t)-1 / count) {
    return NULL;
  }
  ptr = heap_allocate(count * size, 16u);
  if (ptr != NULL) {
    memset(ptr, 0, count * size);
  }
  return ptr;
}

void free(void *ptr) {
  ap_block *block;
  void *base;
  uint8_t *user;
  uint64_t trailing;
  uint64_t aligned;
  int invalid = 0;

  if (ptr == NULL) return;
  pthread_mutex_lock(&heap_lock);
  heap_in_hook = 1;
  user = (uint8_t *)ptr;
  block = (ap_block *)(user - sizeof(ap_block));
  if (block->offset < sizeof(ap_block) || block->offset > 8192u ||
      block->magic != AP_HEAP_MAGIC) {
    heap_report(AP_HEAP_INVALID_FREE, ptr, 0, "invalid_free_header");
    invalid = 1;
  } else {
    base = user - block->offset;
    if (block->canary != heap_canary(base, block->size) ||
        block->state > AP_HEAP_DEAD) {
      heap_report(AP_HEAP_INVALID_FREE, ptr, (size_t)block->size, "invalid_free_canary");
      invalid = 1;
    } else if (block->state == AP_HEAP_DEAD) {
      heap_report(AP_HEAP_DOUBLE_FREE, ptr, (size_t)block->size, "double_free");
      invalid = 1;
    } else {
      aligned = heap_align(block->size ? (size_t)block->size : 1u, 16u);
      memcpy(&trailing, user + aligned, sizeof(trailing));
      if (trailing != block->canary) {
        heap_report(AP_HEAP_OVERFLOW, ptr, (size_t)block->size, "trailing_canary");
      }
      block->state = AP_HEAP_DEAD;
      memset(user, 0x7e, (size_t)aligned);
      base = heap_ring[heap_ring_pos];
      heap_ring[heap_ring_pos] = user - block->offset;
      heap_ring_pos = (heap_ring_pos + 1u) % AP_HEAP_QUARANTINE;
      if (base != NULL) {
        heap_raw_free(base);
      }
    }
  }
  heap_in_hook = 0;
  pthread_mutex_unlock(&heap_lock);
  (void)invalid;
}

void *realloc(void *ptr, size_t size) {
  void *next;
  ap_block *block;

  if (ptr == NULL) return malloc(size);
  if (size == 0u) {
    free(ptr);
    return NULL;
  }
  block = (ap_block *)((uint8_t *)ptr - sizeof(ap_block));
  if (block->magic != AP_HEAP_MAGIC || block->state != AP_HEAP_ACTIVE ||
      block->offset < sizeof(ap_block) || block->offset > 8192u) {
    heap_report(AP_HEAP_INVALID_FREE, ptr, 0, "realloc_invalid");
    return NULL;
  }
  next = heap_allocate(size, 16u);
  if (next == NULL) return NULL;
  memcpy(next, ptr, (size_t)block->size < size ? (size_t)block->size : size);
  free(ptr);
  return next;
}

int posix_memalign(void **out, size_t alignment, size_t size) {
  if (alignment == 0u || (alignment & (alignment - 1u)) != 0u) {
    return EINVAL;
  }
  *out = heap_allocate(size, alignment);
  return *out == NULL ? ENOMEM : 0;
}

int ap_heap_event_validate(const ap_event *event) {
  if (event == NULL || event->size != sizeof(ap_event) ||
      event->abi_version != AP_ABI_VERSION || event->kind != AP_KIND_HEAP) {
    return AP_ERR_ARG;
  }
  return AP_OK;
}

const char *ap_heap_sub_name(uint32_t subkind) {
  switch (subkind) {
    case AP_HEAP_OVERFLOW: return "overflow";
    case AP_HEAP_DOUBLE_FREE: return "double_free";
    case AP_HEAP_INVALID_FREE: return "invalid_free";
    case AP_HEAP_QUARANTINE: return "quarantine";
    default: return "unknown";
  }
}
