#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

static void touch(const char *name, long result) {
  printf("kernel_probe: %s %ld errno=%d\n", name, result, errno);
}

int main(void) {
#ifdef SYS_bpf
  touch("bpf", syscall(SYS_bpf, 0, (void *)0, 0));
#endif
#ifdef SYS_ptrace
  touch("ptrace", syscall(SYS_ptrace, 0, 0, (void *)0, (void *)0));
#endif
#ifdef SYS_finit_module
  touch("finit_module", syscall(SYS_finit_module, -1, "", 0));
#else
#ifdef SYS_init_module
  touch("init_module", syscall(SYS_init_module, (void *)0, 0, ""));
#endif
#endif
#ifdef SYS_open_by_handle_at
  touch("open_by_handle_at", syscall(SYS_open_by_handle_at, -1, (void *)0, 0));
#endif
#ifdef SYS_process_vm_writev
  touch("process_vm_writev", syscall(SYS_process_vm_writev, -1, (void *)0, 0, (void *)0, 0, 0));
#endif
#ifdef SYS_process_vm_readv
  touch("process_vm_readv", syscall(SYS_process_vm_readv, -1, (void *)0, 0, (void *)0, 0, 0));
#endif
#ifdef SYS_userfaultfd
  {
    long fd = syscall(SYS_userfaultfd, 0);
    touch("userfaultfd", fd);
    if (fd >= 0) {
      close((int)fd);
    }
  }
#endif
#ifdef SYS_io_uring_setup
  touch("io_uring_setup", syscall(SYS_io_uring_setup, 0, (void *)0));
#endif
#ifdef SYS_mount
  touch("mount", syscall(SYS_mount, "", "", "", 0, ""));
#endif
#ifdef SYS_umount2
  touch("umount2", syscall(SYS_umount2, "", 0));
#endif
#ifdef SYS_setns
  touch("setns", syscall(SYS_setns, -1, 0));
#endif
#ifdef SYS_kexec_file_load
  touch("kexec_file_load", syscall(SYS_kexec_file_load, -1, -1, 0, (void *)0, 0));
#else
#ifdef SYS_kexec_load
  touch("kexec_load", syscall(SYS_kexec_load, -1, 0, 0, (void *)0));
#endif
#endif
  return 0;
}
