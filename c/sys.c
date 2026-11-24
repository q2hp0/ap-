#define _GNU_SOURCE
#include "apsys.h"
#include "apcap.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#if defined(__x86_64__)
#define AP_SYS_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define AP_SYS_ARCH AUDIT_ARCH_AARCH64
#else
#define AP_SYS_ARCH 0
#endif

int ap_sys_init(void) {
  return AP_OK;
}

int ap_client_keys_init(ap_client_keys *keys) {
  if (keys == NULL) return AP_ERR_ARG;
  memset(keys, 0, sizeof(*keys));
  return AP_OK;
}

int ap_client_keys_add(ap_client_keys *keys, uint32_t pid,
                       const uint8_t key[AP_TRANSPORT_KEY_LEN]) {
  uint32_t index;

  if (keys == NULL || key == NULL || pid == 0u) return AP_ERR_ARG;
  if (keys->count >= AP_CLIENT_KEY_MAX) return AP_ERR_RANGE;
  for (index = 0u; index < keys->count; ++index) {
    if (keys->pids[index] == pid) return AP_ERR_STATE;
  }
  keys->pids[keys->count] = pid;
  memcpy(keys->keys[keys->count], key, AP_TRANSPORT_KEY_LEN);
  keys->count += 1u;
  return AP_OK;
}

int ap_sys_capability_state(void) {
  return (int)ap_cap_probe();
}

static struct sock_filter ap_bpf_stmt(unsigned short code, uint32_t k) {
  struct sock_filter f;
  f.code = code;
  f.jt = 0;
  f.jf = 0;
  f.k = k;
  return f;
}

static struct sock_filter ap_bpf_jump(unsigned short code, uint32_t k, unsigned char jt,
                                      unsigned char jf) {
  struct sock_filter f;
  f.code = code;
  f.jt = jt;
  f.jf = jf;
  f.k = k;
  return f;
}

static int ap_sys_deny_nr(int nr) {
  switch (nr) {
#ifdef SYS_ptrace
    case SYS_ptrace:
#endif
#ifdef SYS_init_module
    case SYS_init_module:
#endif
#ifdef SYS_finit_module
    case SYS_finit_module:
#endif
#ifdef SYS_delete_module
    case SYS_delete_module:
#endif
#ifdef SYS_kexec_load
    case SYS_kexec_load:
#endif
#ifdef SYS_kexec_file_load
    case SYS_kexec_file_load:
#endif
#ifdef SYS_bpf
    case SYS_bpf:
#endif
#ifdef SYS_open_by_handle_at
    case SYS_open_by_handle_at:
#endif
#ifdef SYS_process_vm_writev
    case SYS_process_vm_writev:
#endif
#ifdef SYS_userfaultfd
    case SYS_userfaultfd:
#endif
#ifdef SYS_io_uring_setup
    case SYS_io_uring_setup:
#endif
#ifdef SYS_mount
    case SYS_mount:
#endif
#ifdef SYS_umount2
    case SYS_umount2:
#endif
#ifdef SYS_setns
    case SYS_setns:
#endif
      return 1;
    default:
      return 0;
  }
}

int ap_sys_self_harden(void) {
  struct sock_filter filter[64];
  struct sock_fprog prog;
  unsigned int i = 0;
  int nr;
  int min_nr = 1 << 30;
  int max_nr = -1;
  int nr_count = 0;

  if (AP_SYS_ARCH == 0) {
    return AP_ERR_UNSUPPORTED;
  }
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    return AP_ERR_UNSUPPORTED;
  }

  filter[i++] = ap_bpf_stmt(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
  filter[i++] = ap_bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, AP_SYS_ARCH, 0, 2);
  filter[i++] = ap_bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
  filter[i++] = ap_bpf_stmt(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));

  for (nr = 0; nr < 1000; ++nr) {
    if (ap_sys_deny_nr(nr)) {
      if (nr_count == 0) min_nr = nr;
      max_nr = nr;
      ++nr_count;
    }
  }
  if (nr_count == 0 || (size_t)(i + (size_t)nr_count + 2u) > sizeof(filter) / sizeof(filter[0])) {
    return AP_ERR_UNSUPPORTED;
  }
  for (nr = min_nr; nr <= max_nr; ++nr) {
    if (!ap_sys_deny_nr(nr)) {
      continue;
    }
    filter[i++] = ap_bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1);
    filter[i++] = ap_bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
  }
  filter[i++] = ap_bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

  prog.len = (unsigned short)i;
  prog.filter = filter;
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
    return AP_ERR_UNSUPPORTED;
  }
  return AP_OK;
}

int ap_sys_read_maps(pid_t pid, ap_region_cb callback, void *user) {
  char path[64];
  char line[1024];
  FILE *fp;
  int result = AP_OK;

  if (pid < 0 || callback == NULL) {
    return AP_ERR_ARG;
  }
  snprintf(path, sizeof(path), "/proc/%ld/maps", (long)pid);
  fp = fopen(path, "re");
  if (fp == NULL) {
    return AP_ERR_IO;
  }
  while (fgets(line, sizeof(line), fp) != NULL) {
    unsigned long start = 0;
    unsigned long end = 0;
    unsigned long offset = 0;
    char perms[8] = {0};
    char *name;
    ap_event region;
    uint32_t bits = 0;

    if (sscanf(line, "%lx-%lx %7s %lx", &start, &end, perms, &offset) != 4) {
      continue;
    }
    if (perms[0] == 'r') bits |= 1u;
    if (perms[1] == 'w') bits |= 2u;
    if (perms[2] == 'x') bits |= 4u;
    if (perms[3] == 'p') bits |= 8u;
    name = strchr(line, '/');
    if (name == NULL) {
      name = strstr(line, "[");
    }
    ap_event_init(&region, AP_KIND_MEMREGION);
    region.pid = pid;
    region.arg[0] = (uint64_t)start;
    region.arg[1] = (uint64_t)end;
    region.arg[2] = bits;
    region.arg[3] = (uint64_t)offset;
    if (name != NULL) {
      snprintf(region.text, sizeof(region.text), "%s", name);
      size_t len = strlen(region.text);
      while (len > 0u && (region.text[len - 1u] == '\n' || region.text[len - 1u] == '\r')) {
        region.text[--len] = '\0';
      }
    }
    if (callback(&region, user) != 0) {
      result = AP_ERR_STATE;
      break;
    }
  }
  fclose(fp);
  return result;
}

int ap_sys_proc_uid(pid_t pid, uint32_t *uid, uint32_t *euid) {
  char path[64];
  char line[512];
  FILE *fp;
  int found = 0;

  if (pid < 0 || uid == NULL || euid == NULL) {
    return AP_ERR_ARG;
  }
  snprintf(path, sizeof(path), "/proc/%ld/status", (long)pid);
  fp = fopen(path, "re");
  if (fp == NULL) {
    return AP_ERR_IO;
  }
  while (fgets(line, sizeof(line), fp) != NULL) {
    unsigned int a = 0;
    unsigned int b = 0;
    if (strncmp(line, "Uid:", 4) == 0 &&
        sscanf(line + 4, "%u %u", &a, &b) == 2) {
      *uid = a;
      *euid = b;
      found = 1;
      break;
    }
  }
  fclose(fp);
  return found ? AP_OK : AP_ERR_IO;
}

int ap_sys_proc_comm(pid_t pid, char *out, size_t out_len) {
  char path[64];
  char line[256];
  FILE *fp;
  size_t len;

  if (pid < 0 || out == NULL || out_len == 0u) {
    return AP_ERR_ARG;
  }
  snprintf(path, sizeof(path), "/proc/%ld/comm", (long)pid);
  fp = fopen(path, "re");
  if (fp == NULL) {
    return AP_ERR_IO;
  }
  if (fgets(line, sizeof(line), fp) == NULL) {
    fclose(fp);
    return AP_ERR_IO;
  }
  fclose(fp);
  len = strlen(line);
  while (len > 0u && (line[len - 1u] == '\n' || line[len - 1u] == '\r')) {
    line[--len] = '\0';
  }
  snprintf(out, out_len, "%s", line);
  return AP_OK;
}

int ap_sys_proc_starttime(pid_t pid, uint64_t *out) {
  char path[64];
  char line[1024];
  FILE *fp;
  unsigned long long value = 0;
  int found = 0;

  if (pid < 0 || out == NULL) {
    return AP_ERR_ARG;
  }
  snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
  fp = fopen(path, "re");
  if (fp == NULL) {
    return AP_ERR_IO;
  }
  while (fgets(line, sizeof(line), fp) != NULL) {
    char *end = strrchr(line, ')');
    if (end != NULL &&
        sscanf(end + 1,
               " %*c %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %llu",
               &value) == 1) {
      found = 1;
      break;
    }
  }
  fclose(fp);
  if (!found) {
    return AP_ERR_IO;
  }
  *out = (uint64_t)value;
  return AP_OK;
}

int ap_sys_proc_io(pid_t pid, ap_proc_io *out) {
  char path[64];
  char line[256];
  FILE *fp;
  unsigned long long value = 0u;
  int found = 0;

  if (pid < 0 || out == NULL) {
    return AP_ERR_ARG;
  }
  memset(out, 0, sizeof(*out));
  snprintf(path, sizeof(path), "/proc/%ld/io", (long)pid);
  fp = fopen(path, "re");
  if (fp == NULL) {
    return AP_ERR_IO;
  }
  while (fgets(line, sizeof(line), fp) != NULL) {
    if (sscanf(line, "rchar: %llu", &value) == 1) {
      out->rchar = (uint64_t)value;
      found = 1;
    } else if (sscanf(line, "wchar: %llu", &value) == 1) {
      out->wchar = (uint64_t)value;
      found = 1;
    } else if (sscanf(line, "syscr: %llu", &value) == 1) {
      out->syscr = (uint64_t)value;
    } else if (sscanf(line, "syscw: %llu", &value) == 1) {
      out->syscw = (uint64_t)value;
    } else if (sscanf(line, "read_bytes: %llu", &value) == 1) {
      out->read_bytes = (uint64_t)value;
    } else if (sscanf(line, "write_bytes: %llu", &value) == 1) {
      out->write_bytes = (uint64_t)value;
    } else if (sscanf(line, "cancelled_write_bytes: %llu", &value) == 1) {
      out->cancelled_write_bytes = (uint64_t)value;
    }
  }
  fclose(fp);
  return found ? AP_OK : AP_ERR_IO;
}

int ap_sys_server_open(const char *path, int *fd) {
  char tmpdir[256];
  char tmpsock[320];
  const char *slash;
  size_t prefix;
  int sfd;
  struct sockaddr_un addr;
  struct stat st;

  if (path == NULL || fd == NULL || strlen(path) >= sizeof(addr.sun_path)) {
    return AP_ERR_ARG;
  }
  slash = strrchr(path, '/');
  prefix = slash == NULL ? 0u : (size_t)(slash - path);
  if (slash == path) {
    prefix = 1u;
  }
  if (prefix + sizeof("/.ap-ipc-XXXXXX") >= sizeof(tmpdir)) {
    return AP_ERR_ARG;
  }
  if (slash == NULL) {
    snprintf(tmpdir, sizeof(tmpdir), ".ap-ipc-XXXXXX");
  } else {
    snprintf(tmpdir, sizeof(tmpdir), "%.*s/.ap-ipc-XXXXXX", (int)prefix, path);
  }
  if (mkdtemp(tmpdir) == NULL) {
    return AP_ERR_IO;
  }
  snprintf(tmpsock, sizeof(tmpsock), "%s/s", tmpdir);
  if (strlen(tmpsock) >= sizeof(addr.sun_path)) {
    rmdir(tmpdir);
    return AP_ERR_ARG;
  }

  sfd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (sfd < 0) {
    rmdir(tmpdir);
    return AP_ERR_IO;
  }
  /* best effort: a larger receive queue reduces drops during bursts */
  {
    int rcvbuf = 4 * 1024 * 1024;
    (void)setsockopt(sfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
  }
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  {
    size_t socklen = strlen(tmpsock) + 1u;
    if (socklen > sizeof(addr.sun_path)) {
      close(sfd);
      unlink(tmpsock);
      rmdir(tmpdir);
      return AP_ERR_ARG;
    }
    memcpy(addr.sun_path, tmpsock, socklen);
  }
  if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(sfd);
    rmdir(tmpdir);
    return AP_ERR_IO;
  }
  if (chmod(tmpsock, 0600) != 0) {
    close(sfd);
    unlink(tmpsock);
    rmdir(tmpdir);
    return AP_ERR_IO;
  }
  {
    int enabled = 1;
    if (setsockopt(sfd, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)) != 0) {
      close(sfd);
      unlink(tmpsock);
      rmdir(tmpdir);
      return AP_ERR_IO;
    }
  }
  if (lstat(path, &st) == 0 && !S_ISSOCK(st.st_mode)) {
    close(sfd);
    unlink(tmpsock);
    rmdir(tmpdir);
    return AP_ERR_STATE;
  }
  if (rename(tmpsock, path) != 0) {
    close(sfd);
    unlink(tmpsock);
    rmdir(tmpdir);
    return AP_ERR_IO;
  }
  rmdir(tmpdir);
  *fd = sfd;
  return AP_OK;
}

int ap_sys_client_open(const char *path, int *fd) {
  int sfd;
  struct sockaddr_un addr;

  if (path == NULL || fd == NULL || strlen(path) >= sizeof(addr.sun_path)) {
    return AP_ERR_ARG;
  }
  sfd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (sfd < 0) {
    return AP_ERR_IO;
  }
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
  if (connect(sfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(sfd);
    return AP_ERR_IO;
  }
  *fd = sfd;
  return AP_OK;
}

static int ap_sys_recv_packet(int fd, void *data, size_t len, uint32_t *peer_pid) {
  struct msghdr msg;
  struct iovec iov;
  struct ucred cred;
  struct cmsghdr *cmsg;
  char control[CMSG_SPACE(sizeof(struct ucred))];
  ssize_t count;
  int have_cred = 0;

  if (peer_pid != NULL) *peer_pid = 0u;
  if (data == NULL || len == 0u) return AP_ERR_ARG;
  memset(&msg, 0, sizeof(msg));
  memset(&control, 0, sizeof(control));
  iov.iov_base = data;
  iov.iov_len = len;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);
  count = recvmsg(fd, &msg, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
  if (count <= 0) return AP_ERR_IO;
  for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS &&
        cmsg->cmsg_len >= CMSG_LEN(sizeof(cred))) {
      memcpy(&cred, CMSG_DATA(cmsg), sizeof(cred));
      have_cred = 1;
      break;
    }
  }
  if (!have_cred || cred.uid != geteuid()) return AP_ERR_STATE;
  if ((msg.msg_flags & MSG_TRUNC) != 0 || (size_t)count != len) return AP_ERR_RANGE;
  if (peer_pid != NULL) *peer_pid = (uint32_t)cred.pid;
  return AP_OK;
}

static int ap_sys_recv_sealed_common(int fd, const uint8_t key[AP_TRANSPORT_KEY_LEN],
                                     ap_client_keys *client_keys, void *data, size_t cap,
                                     size_t *received, ap_replay *replay, int strict) {
  ap_packet packet;
  const uint8_t *chosen = key;
  uint32_t peer_pid = 0u;
  uint32_t index;
  int status;

  if (data == NULL || received == NULL) return AP_ERR_ARG;
  if (client_keys == NULL && key == NULL) return AP_ERR_ARG;
  if (client_keys != NULL && client_keys->count == 0u) return AP_ERR_ARG;
  if (cap < sizeof(ap_event)) return AP_ERR_RANGE;
  status = ap_sys_recv_packet(fd, packet.data, sizeof(packet.data), &peer_pid);
  if (status != AP_OK) return status;
  if (client_keys != NULL) {
    for (index = 0u; index < client_keys->count; ++index) {
      if (client_keys->pids[index] == peer_pid) break;
    }
    if (index == client_keys->count) {
      client_keys->unmatched += 1u;
      return AP_ERR_AUTH;
    }
    chosen = client_keys->keys[index];
    client_keys->matched += 1u;
  }
  status = ap_transport_open(chosen, &packet, sizeof(packet.data), (ap_event *)data);
  if (status != AP_OK) return status;
  if (replay != NULL) {
    if (strict != 0) {
      status = ap_replay_accept_sequence(replay, &packet, ((const ap_event *)data)->seq, peer_pid);
    } else {
      status = ap_replay_accept(replay, &packet);
    }
    if (status != AP_OK) return status;
  }
  *received = sizeof(ap_event);
  return AP_OK;
}

int ap_sys_recv_sealed(int fd, const uint8_t key[AP_TRANSPORT_KEY_LEN], void *data, size_t cap,
                       size_t *received) {
  return ap_sys_recv_sealed_common(fd, key, NULL, data, cap, received, NULL, 0);
}

int ap_sys_recv_sealed_filtered(int fd, const uint8_t key[AP_TRANSPORT_KEY_LEN], void *data,
                                size_t cap, size_t *received, ap_replay *replay) {
  if (replay == NULL) return AP_ERR_ARG;
  return ap_sys_recv_sealed_common(fd, key, NULL, data, cap, received, replay, 0);
}

int ap_sys_recv_sealed_sequenced(int fd, const uint8_t key[AP_TRANSPORT_KEY_LEN], void *data,
                                 size_t cap, size_t *received, ap_replay *replay) {
  if (replay == NULL) return AP_ERR_ARG;
  return ap_sys_recv_sealed_common(fd, key, NULL, data, cap, received, replay, 1);
}

int ap_sys_recv_sealed_client(int fd, ap_client_keys *client_keys, void *data, size_t cap,
                              size_t *received, ap_replay *replay, int strict) {
  return ap_sys_recv_sealed_common(fd, NULL, client_keys, data, cap, received, replay, strict);
}

int ap_sys_send_sealed(int fd, const uint8_t key[AP_TRANSPORT_KEY_LEN], const ap_event *event) {
  ap_packet packet;
  int status;

  if (key == NULL || event == NULL) return AP_ERR_ARG;
  status = ap_transport_seal(key, event, &packet);
  if (status != AP_OK) return status;
  return ap_sys_write_all(fd, packet.data, sizeof(packet.data));
}

int ap_sys_write_all(int fd, const void *data, size_t len) {
  const char *bytes = (const char *)data;
  size_t done = 0;
  while (done < len) {
    ssize_t n = write(fd, bytes + done, len - done);
    if (n > 0) {
      done += (size_t)n;
      continue;
    }
    if (n < 0 && errno == EINTR) {
      continue;
    }
    return AP_ERR_IO;
  }
  return AP_OK;
}

static int ap_audit_read_exact(int fd, uint8_t *data, size_t len) {
  size_t done = 0u;
  while (done < len) {
    ssize_t count = read(fd, data + done, len - done);
    if (count > 0) {
      done += (size_t)count;
      continue;
    }
    if (count == 0) return done == 0u ? 1 : -1;
    if (errno == EINTR) continue;
    return -1;
  }
  return 0;
}

static uint32_t ap_audit_decode32(const uint8_t *data) {
  return (uint32_t)data[0] | ((uint32_t)data[1] << 8) |
         ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

static void ap_audit_encode32(uint8_t *data, uint32_t value) {
  data[0] = (uint8_t)(value & 0xffu);
  data[1] = (uint8_t)((value >> 8) & 0xffu);
  data[2] = (uint8_t)((value >> 16) & 0xffu);
  data[3] = (uint8_t)((value >> 24) & 0xffu);
}

int ap_audit_send(int fd, const uint8_t *data, size_t len) {
  uint8_t frame[AP_AUDIT_MAX_FRAME];
  ssize_t count;

  if (data == NULL || len == 0u) return AP_ERR_ARG;
  if (len > AP_AUDIT_MAX_PAYLOAD) return AP_ERR_RANGE;
  ap_audit_encode32(frame, (uint32_t)len);
  memcpy(frame + 4, data, len);
  do {
    count = write(fd, frame, len + 4u);
  } while (count < 0 && errno == EINTR);
  if (count == (ssize_t)(len + 4u)) return AP_OK;
  if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return AP_ERR_STATE;
  return AP_ERR_IO;
}

int ap_audit_recv(int fd, uint8_t *data, size_t cap, size_t *len) {
  uint8_t header[4];
  uint32_t frame_len;
  int status;

  if (data == NULL || len == NULL) return AP_ERR_ARG;
  *len = 0u;
  status = ap_audit_read_exact(fd, header, sizeof(header));
  if (status == 1) return AP_OK;
  if (status != 0) return AP_ERR_IO;
  frame_len = ap_audit_decode32(header);
  if (frame_len == 0u || frame_len > AP_AUDIT_MAX_PAYLOAD || frame_len > cap) {
    return AP_ERR_RANGE;
  }
  status = ap_audit_read_exact(fd, data, (size_t)frame_len);
  if (status != 0) return AP_ERR_IO;
  *len = (size_t)frame_len;
  return AP_OK;
}

int ap_audit_writer_spawn(const char *store, const char *key, int *write_fd, int *child_pid) {
  int fds[2];
  pid_t child;
  char *argv[5];

  if (store == NULL || key == NULL || write_fd == NULL || child_pid == NULL ||
      *store == '\0' || *key == '\0') {
    return AP_ERR_ARG;
  }
  if (pipe2(fds, O_CLOEXEC) != 0) return AP_ERR_IO;
  if (fcntl(fds[1], F_SETFL, O_NONBLOCK) < 0) {
    close(fds[0]);
    close(fds[1]);
    return AP_ERR_IO;
  }
  signal(SIGPIPE, SIG_IGN);
  child = fork();
  if (child < 0) {
    close(fds[0]);
    close(fds[1]);
    return AP_ERR_IO;
  }
  if (child == 0) {
    argv[0] = (char *)"ap";
    argv[1] = (char *)"--audit-writer";
    argv[2] = (char *)store;
    argv[3] = (char *)key;
    argv[4] = NULL;
    if (dup2(fds[0], STDIN_FILENO) < 0) _exit(4);
    close(fds[0]);
    close(fds[1]);
    execv("/proc/self/exe", argv);
    _exit(5);
  }
  close(fds[0]);
  *write_fd = fds[1];
  *child_pid = (int)child;
  return AP_OK;
}

void ap_sys_path_fingerprint(const char *path, uint64_t *out) {
  uint64_t hash = 1469598103934665603ull;
  const unsigned char *p = (const unsigned char *)path;
  if (out == NULL) {
    return;
  }
  if (p == NULL) p = (const unsigned char *)"";
  while (*p != 0) {
    hash ^= (uint64_t)*p++;
    hash *= 1099511628211ull;
  }
  *out = hash;
}
