#ifndef APSYS_H
#define APSYS_H

#include "apabi.h"
#include "apreplay.h"
#include "aptransport.h"

#include <sys/types.h>

#define AP_CLIENT_KEY_MAX 16u
#define AP_AUDIT_MAX_FRAME 4096u
#define AP_AUDIT_MAX_PAYLOAD (AP_AUDIT_MAX_FRAME - 4u)

typedef struct ap_proc_io {
  uint64_t rchar;
  uint64_t wchar;
  uint64_t syscr;
  uint64_t syscw;
  uint64_t read_bytes;
  uint64_t write_bytes;
  uint64_t cancelled_write_bytes;
} ap_proc_io;

typedef struct ap_client_keys {
  uint32_t pids[AP_CLIENT_KEY_MAX];
  uint8_t keys[AP_CLIENT_KEY_MAX][AP_TRANSPORT_KEY_LEN];
  uint32_t count;
  uint64_t matched;
  uint64_t unmatched;
} ap_client_keys;

#ifdef __cplusplus
extern "C" {
#endif

int ap_client_keys_init(ap_client_keys *keys);
int ap_client_keys_add(ap_client_keys *keys, uint32_t pid,
                       const uint8_t key[AP_TRANSPORT_KEY_LEN]);

int ap_sys_init(void);
int ap_sys_self_harden(void);
int ap_sys_capability_state(void);

int ap_sys_read_maps(pid_t pid, ap_region_cb callback, void *user);
int ap_sys_proc_uid(pid_t pid, uint32_t *uid, uint32_t *euid);
int ap_sys_proc_comm(pid_t pid, char *out, size_t out_len);
int ap_sys_proc_starttime(pid_t pid, uint64_t *out);
int ap_sys_proc_io(pid_t pid, ap_proc_io *out);

int ap_sys_server_open(const char *path, int *fd);
int ap_sys_client_open(const char *path, int *fd);
int ap_sys_recv_sealed(int fd, const uint8_t key[AP_TRANSPORT_KEY_LEN], void *data, size_t cap,
                       size_t *received);
int ap_sys_recv_sealed_filtered(int fd, const uint8_t key[AP_TRANSPORT_KEY_LEN], void *data,
                                size_t cap, size_t *received, ap_replay *replay);
int ap_sys_recv_sealed_sequenced(int fd, const uint8_t key[AP_TRANSPORT_KEY_LEN], void *data,
                                 size_t cap, size_t *received, ap_replay *replay);
int ap_sys_recv_sealed_client(int fd, ap_client_keys *client_keys, void *data, size_t cap,
                              size_t *received, ap_replay *replay, int strict);
int ap_sys_send_sealed(int fd, const uint8_t key[AP_TRANSPORT_KEY_LEN], const ap_event *event);
int ap_sys_write_all(int fd, const void *data, size_t len);
int ap_audit_writer_spawn(const char *store, const char *key, int *write_fd, int *child_pid);
int ap_audit_send(int fd, const uint8_t *data, size_t len);
int ap_audit_recv(int fd, uint8_t *data, size_t cap, size_t *len);
void ap_sys_path_fingerprint(const char *path, uint64_t *out);

#ifdef __cplusplus
}
#endif

#endif
