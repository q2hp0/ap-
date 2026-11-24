#define _GNU_SOURCE
#include "apcollector.h"
#include "apsys.h"

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define AP_TEST_WX_REGIONS 6u

typedef struct ap_capture {
  int64_t pid;
  int start;
  int exit_event;
  int exec_event;
  int priv_event;
  int wx;
  int io_event;
  uint32_t wx_events;
  uint64_t start_seq;
  uint64_t io_write_bytes;
  uint64_t io_write_calls;
} ap_capture;

static int capture_event(const ap_event *event, void *user) {
  ap_capture *capture = (ap_capture *)user;
  if (event == NULL || capture == NULL || event->pid != capture->pid) {
    return 0;
  }
  if (event->kind == AP_KIND_PROC && event->subkind == AP_PROC_START) {
    capture->start = 1;
    capture->start_seq = event->seq;
  }
  if (event->kind == AP_KIND_PROC && event->subkind == AP_PROC_EXIT) {
    capture->exit_event = 1;
  }
  if (event->kind == AP_KIND_EXEC) {
    capture->exec_event = 1;
  }
  if (event->kind == AP_KIND_PRIV && event->subkind == 2u) {
    capture->priv_event = 1;
  }
  if (event->kind == AP_KIND_MEMREGION && event->subkind == 2u &&
      (event->arg[2] & 6u) == 6u) {
    capture->wx = 1;
    ++capture->wx_events;
  }
  if (event->kind == AP_KIND_FILE && event->subkind == AP_FILE_IO) {
    capture->io_event = 1;
    if (event->arg[0] > capture->io_write_bytes) {
      capture->io_write_bytes = event->arg[0];
    }
    if (event->arg[1] > capture->io_write_calls) {
      capture->io_write_calls = event->arg[1];
    }
  }
  return 0;
}

static int scan_for_file_io(ap_collector *collector, ap_capture *capture);

static int map_limits_ok(void) {
  ap_collector *collector = ap_collector_new(AP_COLLECTOR_MAX_PIDS);
  uint32_t map_samples = 0u;
  uint32_t wx_per_scan = 0u;
  int ok = 1;

  if (collector == NULL) {
    return 0;
  }
  if (ap_collector_set_map_limits(collector, 0u, 4u) == AP_OK ||
      ap_collector_set_map_limits(collector, 33u, 4u) == AP_OK ||
      ap_collector_set_map_limits(collector, 8u, 0u) == AP_OK ||
      ap_collector_set_map_limits(collector, 8u, 17u) == AP_OK) {
    ok = 0;
  }
  if (ok && (ap_collector_set_map_limits(collector, 16u, 8u) != AP_OK ||
             ap_collector_map_limits(collector, &map_samples, &wx_per_scan) != AP_OK ||
             map_samples != 16u || wx_per_scan != 8u)) {
    ok = 0;
  }
  ap_collector_free(collector);
  return ok;
}

static int io_limits_ok(void) {
  ap_collector *collector = ap_collector_new(AP_COLLECTOR_MAX_PIDS);
  uint32_t io_per_scan = 0u;
  int ok = 1;

  if (collector == NULL) {
    return 0;
  }
  if (ap_collector_set_io_per_scan(collector, 0u) == AP_OK ||
      ap_collector_set_io_per_scan(collector, AP_COLLECTOR_MAX_IO_PER_SCAN + 1u) == AP_OK ||
      ap_collector_io_per_scan(collector, NULL) == AP_OK) {
    ok = 0;
  }
  if (ok && (ap_collector_set_io_per_scan(collector, 16u) != AP_OK ||
             ap_collector_io_per_scan(collector, &io_per_scan) != AP_OK ||
             io_per_scan != 16u)) {
    ok = 0;
  }
  ap_collector_free(collector);
  return ok;
}

static int proc_io_field(const char *name, uint64_t *out) {
  char line[256];
  char key[32];
  char *colon;
  unsigned long long value = 0u;
  FILE *fp = fopen("/proc/self/io", "re");
  if (fp == NULL) {
    return 0;
  }
  while (fgets(line, sizeof(line), fp) != NULL) {
    colon = strchr(line, ':');
    if (colon == NULL || (size_t)(colon - line) >= sizeof(key)) {
      continue;
    }
    *colon = '\0';
    memcpy(key, line, (size_t)(colon - line) + 1u);
    if (strcmp(key, name) == 0 && sscanf(colon + 1, " %llu", &value) == 1) {
      *out = (uint64_t)value;
      fclose(fp);
      return 1;
    }
  }
  fclose(fp);
  return 0;
}

static int proc_io_parser_matches(void) {
  ap_proc_io io;
  uint64_t wchar = 0u;
  uint64_t syscw = 0u;
  uint64_t read_bytes = 0u;
  int fd = open("/dev/null", O_WRONLY);
  const char payload[] = "ap io parser check\n";
  ssize_t written = -1;

  if (fd >= 0) {
    written = write(fd, payload, sizeof(payload) - 1u);
    close(fd);
  }
  if (written < 0 || ap_sys_proc_io(getpid(), &io) != AP_OK ||
      !proc_io_field("wchar", &wchar) || !proc_io_field("syscw", &syscw) ||
      !proc_io_field("read_bytes", &read_bytes)) {
    return 0;
  }
  return io.wchar == wchar && io.syscw == syscw && io.read_bytes == read_bytes &&
         io.wchar >= (uint64_t)(sizeof(payload) - 1u);
}

static int io_burst_child(const char *path, int ready_fd, int go_fd) {
  char block[16384];
  char ping = 'r';
  char go = 0u;
  uint32_t index;
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

  if (fd < 0) {
    return 1;
  }
  memset(block, 0x5a, sizeof(block));
  if (write(fd, "x", 1u) != 1u || write(ready_fd, &ping, 1u) != 1u ||
      read(go_fd, &go, 1u) != 1u) {
    close(fd);
    return 1;
  }
  for (index = 0u; index < 128u; ++index) {
    if (write(fd, block, sizeof(block)) != (ssize_t)sizeof(block)) {
      close(fd);
      return 1;
    }
  }
  sleep(2);
  close(fd);
  return 0;
}

static int write_burst_observed(ap_collector *collector) {
  char path[64];
  char ping = 0u;
  char go = 'g';
  int ready[2];
  int go_pipe[2];
  pid_t child;
  int status = 0;
  int ok = 0;
  ap_capture capture;

  memset(&capture, 0, sizeof(capture));
  snprintf(path, sizeof(path), "/tmp/ap-collector-io-%ld", (long)getpid());
  if (pipe(ready) != 0) {
    return 0;
  }
  if (pipe(go_pipe) != 0) {
    close(ready[0]);
    close(ready[1]);
    return 0;
  }
  child = fork();
  if (child < 0) {
    close(ready[0]);
    close(ready[1]);
    close(go_pipe[0]);
    close(go_pipe[1]);
    return 0;
  }
  if (child == 0) {
    close(ready[0]);
    close(go_pipe[1]);
    _exit(io_burst_child(path, ready[1], go_pipe[0]));
  }
  close(ready[1]);
  close(go_pipe[0]);
  if (read(ready[0], &ping, 1u) == 1u) {
    capture.pid = (int64_t)child;
    if (ap_collector_scan(collector, ap_clock_ns(), capture_event, &capture) == AP_OK &&
        ap_collector_scan_pid_io(collector, (int64_t)child, ap_clock_ns(),
                                 capture_event, &capture) == AP_OK &&
        write(go_pipe[1], &go, 1u) == 1u) {
      ok = scan_for_file_io(collector, &capture);
      if (ok && (capture.io_write_bytes < 65536u || capture.io_write_calls < 8u)) {
        ok = 0;
      }
    }
  }
  close(ready[0]);
  close(go_pipe[1]);
  if (!ok) {
    kill(child, SIGKILL);
  }
  waitpid(child, &status, 0);
  unlink(path);
  return ok;
}

static int scan_for(ap_collector *collector, ap_capture *capture, int flag) {
  int index;
  for (index = 0; index < 60; ++index) {
    if (ap_collector_scan(collector, ap_clock_ns(), capture_event, capture) != AP_OK) {
      return 0;
    }
    if (capture->start && (flag == 0 || flag == 1)) return 1;
    if (capture->wx && flag == 2) return 1;
    if (capture->exit_event && flag == 3) return 1;
    usleep(20000);
  }
  return 0;
}

static int scan_for_file_io(ap_collector *collector, ap_capture *capture) {
  int index;
  for (index = 0; index < 200; ++index) {
    if (ap_collector_scan_pid_io(collector, capture->pid, ap_clock_ns(),
                                 capture_event, capture) != AP_OK) {
      return 0;
    }
    if (capture->io_event && capture->io_write_bytes >= 65536u &&
        capture->io_write_calls >= 8u) {
      return 1;
    }
    usleep(10000);
  }
  return 0;
}

static int rwx_supported(void) {
  size_t len = 4096u;
  void *region = mmap(NULL, len, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  int ok;
  if (region == MAP_FAILED) {
    return 0;
  }
  ok = mprotect(region, len, PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
  munmap(region, len);
  return ok;
}

static int proc_starttime_matches(void) {
  char line[2048];
  char *cursor;
  char *tail;
  uint64_t expected = 0u;
  uint64_t observed = 0u;
  int index;
  FILE *fp = fopen("/proc/self/stat", "re");

  if (fp == NULL || fgets(line, sizeof(line), fp) == NULL) {
    if (fp != NULL) fclose(fp);
    return 0;
  }
  fclose(fp);
  cursor = strrchr(line, ')');
  if (cursor == NULL) return 0;
  ++cursor;
  for (index = 0; index < 19; ++index) {
    while (*cursor == ' ') ++cursor;
    while (*cursor != '\0' && *cursor != ' ') ++cursor;
  }
  while (*cursor == ' ') ++cursor;
  expected = (uint64_t)strtoull(cursor, &tail, 10);
  if (tail == cursor || ap_sys_proc_starttime(getpid(), &observed) != AP_OK) return 0;
  return expected != 0u && observed == expected;
}

int main(void) {
  ap_collector *collector;
  ap_collector_counters counters;
  ap_capture capture;
  pid_t child;
  int status = 0;
  int scan_status = 0;
  int rwx = rwx_supported();

  collector = ap_collector_new(AP_COLLECTOR_MAX_PIDS);
  if (collector == NULL) {
    fprintf(stderr, "collector allocation failed\n");
    return 1;
  }
  if (!proc_starttime_matches()) {
    fprintf(stderr, "proc starttime parser failed\n");
    ap_collector_free(collector);
    return 1;
  }
  if (!map_limits_ok() || !io_limits_ok()) {
    fprintf(stderr, "collector limits failed\n");
    ap_collector_free(collector);
    return 1;
  }
  if (!proc_io_parser_matches()) {
    fprintf(stderr, "proc io parser failed\n");
    ap_collector_free(collector);
    return 1;
  }
  memset(&capture, 0, sizeof(capture));
  if (ap_collector_scan(collector, ap_clock_ns(), capture_event, &capture) != AP_OK) {
    fprintf(stderr, "baseline scan failed\n");
    ap_collector_free(collector);
    return 1;
  }

  child = fork();
  if (child < 0) {
    ap_collector_free(collector);
    return 1;
  }
  if (child == 0) {
    if (rwx) {
      uint32_t index;
      for (index = 0u; index < AP_TEST_WX_REGIONS; ++index) {
        size_t len = 8192u;
        void *region = mmap(NULL, len, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (region != MAP_FAILED) {
          (void)mprotect(region, 4096u, PROT_READ | PROT_WRITE | PROT_EXEC);
        }
      }
    }
    sleep(1);
    _exit(0);
  }
  capture.pid = (int64_t)child;
  if (!scan_for(collector, &capture, 1)) {
    ap_collector_stats(collector, &counters);
    fprintf(stderr, "process start was not observed scans=%llu pids=%llu starts=%llu exits=%llu errors=%llu\n",
            (unsigned long long)counters.scans, (unsigned long long)counters.pids_seen,
            (unsigned long long)counters.starts, (unsigned long long)counters.exits,
            (unsigned long long)counters.errors);
    kill(child, SIGKILL);
    waitpid(child, &status, 0);
    ap_collector_free(collector);
    return 1;
  }
  if (rwx) {
    if (ap_collector_set_map_limits(collector, 8u, 2u) != AP_OK) {
      fprintf(stderr, "collector map limit update failed\n");
      kill(child, SIGKILL);
      waitpid(child, &status, 0);
      ap_collector_free(collector);
      return 1;
    }
    capture.wx_events = 0u;
    scan_status = ap_collector_scan_pid_maps(collector, (int64_t)child, ap_clock_ns(),
                                             capture_event, &capture);
    if ((scan_status != AP_OK && scan_status != AP_ERR_STATE) ||
        capture.wx_events != 2u) {
      fprintf(stderr, "writable executable emission cap failed status=%d events=%u\n",
              scan_status, capture.wx_events);
      kill(child, SIGKILL);
      waitpid(child, &status, 0);
      ap_collector_free(collector);
      return 1;
    }
    if (ap_collector_set_map_limits(collector, AP_COLLECTOR_DEFAULT_MAPS_PER_SCAN,
                                    AP_COLLECTOR_DEFAULT_WX_PER_SCAN) != AP_OK) {
      fprintf(stderr, "collector map limit restore failed\n");
      kill(child, SIGKILL);
      waitpid(child, &status, 0);
      ap_collector_free(collector);
      return 1;
    }
    capture.wx = 1;
  }
  waitpid(child, &status, 0);
  if (!scan_for(collector, &capture, 3)) {
    ap_collector_stats(collector, &counters);
    fprintf(stderr, "process exit was not observed scans=%llu starts=%llu exits=%llu evictions=%llu errors=%llu\n",
            (unsigned long long)counters.scans, (unsigned long long)counters.starts,
            (unsigned long long)counters.exits, (unsigned long long)counters.evictions,
            (unsigned long long)counters.errors);
    ap_collector_free(collector);
    return 1;
  }
  if (capture.start_seq == 0u || capture.exec_event || capture.priv_event) {
    fprintf(stderr, "collector emitted an unexpected process state change\n");
    ap_collector_free(collector);
    return 1;
  }
  if (ap_collector_stats(collector, &counters) != AP_OK ||
      counters.starts == 0u || counters.exits == 0u || counters.pids_seen == 0u) {
    fprintf(stderr, "collector counters are incomplete\n");
    ap_collector_free(collector);
    return 1;
  }
  if (rwx && counters.wx_regions == 0u) {
    fprintf(stderr, "collector wx counter stayed zero\n");
    ap_collector_free(collector);
    return 1;
  }
  if (!write_burst_observed(collector)) {
    fprintf(stderr, "collector file io observation failed\n");
    ap_collector_free(collector);
    return 1;
  }
  if (ap_collector_stats(collector, &counters) != AP_OK || counters.file_events == 0u ||
      counters.file_samples == 0u) {
    fprintf(stderr, "collector file counters are incomplete\n");
    ap_collector_free(collector);
    return 1;
  }
  ap_collector_free(collector);
  printf("collector tests: ok rwx=%d\n", rwx);
  return 0;
}
