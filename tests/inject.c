#define _POSIX_C_SOURCE 200809L
#include "apabi.h"
#include "apsys.h"
#include "aptransport.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void fill(ap_event *event, const char *name, int index) {
  ap_event_init(event, AP_KIND_PROC);
  event->seq = (uint64_t)index + 1;
  event->pid = 4000 + index;
  event->ts_ns = ap_clock_ns();
  event->confidence_x1000 = 940;
  if (strcmp(name, "wx") == 0) {
    event->kind = AP_KIND_MEMPROT;
    event->subkind = 1;
    event->severity = AP_SEV_CRITICAL;
    event->arg[2] = 7;
    snprintf(event->text, sizeof(event->text), "mprotect");
  } else if (strcmp(name, "wxregion") == 0) {
    event->kind = AP_KIND_MEMREGION;
    event->subkind = 2;
    event->severity = AP_SEV_CRITICAL;
    event->arg[0] = 0x1000;
    event->arg[1] = 0x2000;
    event->arg[2] = 6;
    snprintf(event->text, sizeof(event->text), "/tmp/wx");
  } else if (strcmp(name, "net") == 0) {
    event->kind = AP_KIND_NET;
    event->subkind = AP_NET_PACKET;
    event->severity = AP_SEV_HIGH;
    snprintf(event->text, sizeof(event->text),
             "45000028000000004006f77cc0a80101c0a80102050a008000000000000000005003ffff00000000");
  } else if (strcmp(name, "net6") == 0) {
    event->kind = AP_KIND_NET;
    event->subkind = AP_NET_PACKET;
    event->severity = AP_SEV_HIGH;
    snprintf(event->text, sizeof(event->text),
             "600000000014064020010db800000000000000000000000120010db8000000000000000000000002"
             "050a008000000000000000005003ffff00000000");
  } else if (strcmp(name, "raw") == 0) {
    event->kind = AP_KIND_NET;
    event->subkind = AP_NET_SOCKET;
    event->severity = AP_SEV_HIGH;
    event->arg[1] = 3;
    snprintf(event->text, sizeof(event->text), "socket");
  } else if (strcmp(name, "heap") == 0) {
    event->kind = AP_KIND_HEAP;
    event->subkind = AP_HEAP_DOUBLE_FREE;
    event->severity = AP_SEV_HIGH;
    snprintf(event->text, sizeof(event->text), "double_free");
  } else if (strcmp(name, "module") == 0) {
    event->kind = AP_KIND_KERNEL;
    event->subkind = 1;
    event->severity = AP_SEV_CRITICAL;
    snprintf(event->text, sizeof(event->text), "module_load");
  } else if (strcmp(name, "bpf") == 0) {
    event->kind = AP_KIND_KERNEL;
    event->subkind = 1;
    event->severity = AP_SEV_HIGH;
    snprintf(event->text, sizeof(event->text), "bpf");
  } else if (strcmp(name, "ptrace") == 0) {
    event->kind = AP_KIND_KERNEL;
    event->subkind = 1;
    event->severity = AP_SEV_HIGH;
    snprintf(event->text, sizeof(event->text), "ptrace");
  } else if (strcmp(name, "setid") == 0) {
    event->kind = AP_KIND_PRIV;
    event->subkind = 1;
    event->severity = AP_SEV_MEDIUM;
    event->confidence_x1000 = 450;
    snprintf(event->text, sizeof(event->text), "setid");
  } else if (strcmp(name, "execuid") == 0) {
    event->kind = AP_KIND_PRIV;
    event->subkind = 2;
    event->severity = AP_SEV_HIGH;
    event->confidence_x1000 = 800;
    snprintf(event->text, sizeof(event->text), "exec_uid_change");
  } else if (strcmp(name, "shadowcall") == 0) {
    event->kind = AP_KIND_FLOW;
    event->subkind = AP_FLOW_SHADOW;
    event->severity = AP_SEV_INFO;
    event->confidence_x1000 = 900;
    event->arg[1] = 0xabc;
    snprintf(event->text, sizeof(event->text), "call");
  } else if (strcmp(name, "shadowret") == 0) {
    event->kind = AP_KIND_FLOW;
    event->subkind = AP_FLOW_SHADOW;
    event->severity = AP_SEV_HIGH;
    event->confidence_x1000 = 900;
    event->arg[0] = 0xabd;
    snprintf(event->text, sizeof(event->text), "ret");
  } else if (strcmp(name, "exec") == 0) {
    event->kind = AP_KIND_EXEC;
    event->subkind = 1;
    event->severity = AP_SEV_HIGH;
    snprintf(event->text, sizeof(event->text), "/bin/app");
  } else if (strcmp(name, "flowstrong") == 0) {
    event->kind = AP_KIND_FLOW;
    event->subkind = AP_FLOW_RETURN_SITE;
    event->severity = AP_SEV_HIGH;
    event->confidence_x1000 = 900;
    event->arg[0] = 0xdead00;
    snprintf(event->text, sizeof(event->text), "strong");
  } else if (strcmp(name, "weak") == 0) {
    event->kind = AP_KIND_FLOW;
    event->subkind = AP_FLOW_RETURN_SITE;
    event->severity = AP_SEV_LOW;
    event->confidence_x1000 = 250;
    event->arg[0] = 0x5000 + (uint64_t)index;
    snprintf(event->text, sizeof(event->text), "return_site_unverified");
  } else if (strcmp(name, "clean") == 0) {
    event->kind = AP_KIND_PROC;
    event->severity = AP_SEV_INFO;
    event->confidence_x1000 = 1000;
    snprintf(event->text, sizeof(event->text), "benign");
  } else if (strcmp(name, "badabi") == 0) {
    event->abi_version = 99;
    snprintf(event->text, sizeof(event->text), "invalid");
  } else {
    fprintf(stderr, "unknown event type: %s\n", name);
    exit(2);
  }
}

static int send_event(int fd, const uint8_t *key, const ap_event *event) {
  if (ap_sys_send_sealed(fd, key, event) != AP_OK) {
    fprintf(stderr, "inject: write failed\n");
    return AP_ERR_IO;
  }
  return AP_OK;
}

static void stage_event(ap_event *event, uint64_t *seq, int64_t pid,
                        uint16_t kind, uint32_t subkind, uint32_t severity,
                        uint32_t confidence, uint64_t a, uint64_t b,
                        uint64_t c, const char *text) {
  ap_event_init(event, kind);
  event->seq = (*seq)++;
  event->pid = pid;
  event->tid = pid;
  event->ts_ns = ap_clock_ns();
  event->subkind = subkind;
  event->severity = severity;
  event->confidence_x1000 = confidence;
  event->arg[0] = a;
  event->arg[1] = b;
  event->arg[2] = c;
  snprintf(event->text, sizeof(event->text), "%s", text);
}

static void stage_timed(ap_event *event, uint64_t *seq, uint64_t *ts, int64_t pid,
                        uint16_t kind, uint32_t subkind, uint32_t severity,
                        uint32_t confidence, uint64_t a, uint64_t b,
                        uint64_t c, const char *text) {
  stage_event(event, seq, pid, kind, subkind, severity, confidence, a, b, c, text);
  event->ts_ns = *ts;
  *ts += 1000000000ull;
}

int main(int argc, char **argv) {
  uint8_t key[AP_TRANSPORT_KEY_LEN];
  int fd = -1;
  ap_event event;
  int index;

  if (argc < 3) {
    fprintf(stderr, "usage: inject <socket> <name> [count]\n");
    fprintf(stderr, "names: wx wxregion exec net net6 raw heap module bpf ptrace setid execuid kernelchain entitychain injectionchain exploitchain credchain fileburst destructive exfil filebenign jitstream containerstream shadowcall shadowret flowstrong weak clean duplicate staleseq badabi\n");
    return 2;
  }
  if (ap_sys_client_open(argv[1], &fd) != AP_OK) {
    fprintf(stderr, "inject: cannot connect to %s\n", argv[1]);
    return 1;
  }
  if (ap_transport_key_load(argv[1], key) != AP_OK) {
    fprintf(stderr, "inject: cannot load transport key for %s\n", argv[1]);
    close(fd);
    return 1;
  }
  if (strcmp(argv[2], "kernelchain") == 0) {
    static const char *labels[3] = {"module_load", "mount", "namespace_change"};
    int rounds = argc > 3 ? atoi(argv[3]) : 1;
    uint64_t seq = 1u;
    int round;
    int label;
    for (round = 0; round < rounds; ++round) {
      for (label = 0; label < 3; ++label) {
        ap_event_init(&event, AP_KIND_KERNEL);
        event.seq = seq++;
        event.pid = 7000;
        event.tid = 7000;
        event.ts_ns = ap_clock_ns();
        event.subkind = 1u;
        event.severity = AP_SEV_HIGH;
        event.confidence_x1000 = 900u;
        snprintf(event.text, sizeof(event.text), "%s", labels[label]);
        if (send_event(fd, key, &event) != AP_OK) {
          return 1;
        }
      }
    }
    return 0;
  }
  if (strcmp(argv[2], "entitychain") == 0) {
    uint64_t seq = 1u;
    stage_event(&event, &seq, 9100, AP_KIND_MEMREGION, 2u, AP_SEV_CRITICAL,
                940u, 0x1000u, 0x2000u, 6u, "/tmp/ap-entity-payload");
    if (send_event(fd, key, &event) != AP_OK) return 1;
    stage_event(&event, &seq, 9100, AP_KIND_EXEC, 1u, AP_SEV_HIGH, 900u,
                0u, 0u, 0u, "/tmp/ap-entity-payload");
    if (send_event(fd, key, &event) != AP_OK) return 1;
    stage_event(&event, &seq, 9100, AP_KIND_PRIV, 2u, AP_SEV_HIGH, 800u,
                0u, 1000u, 0u, "init");
    if (send_event(fd, key, &event) != AP_OK) return 1;
    stage_event(&event, &seq, 9100, AP_KIND_NET, AP_NET_CONNECT, AP_SEV_HIGH,
                900u, 0u, 0u, 0u, "peer:10.9.8.7:4444");
    return send_event(fd, key, &event) == AP_OK ? 0 : 1;
  }
  if (strcmp(argv[2], "jitstream") == 0) {
    uint64_t seq = 1u;
    stage_event(&event, &seq, 9200, AP_KIND_MEMREGION, 2u, AP_SEV_CRITICAL,
                940u, 0x3000u, 0x4000u, 6u, "/opt/jit/code");
    if (send_event(fd, key, &event) != AP_OK) return 1;
    stage_event(&event, &seq, 9200, AP_KIND_EXEC, 1u, AP_SEV_HIGH, 900u,
                0u, 0u, 0u, "/opt/jit/code");
    return send_event(fd, key, &event) == AP_OK ? 0 : 1;
  }
  if (strcmp(argv[2], "containerstream") == 0) {
    uint64_t seq = 1u;
    stage_event(&event, &seq, 9300, AP_KIND_EXEC, 1u, AP_SEV_HIGH, 900u,
                0u, 0u, 0u, "/usr/bin/init");
    if (send_event(fd, key, &event) != AP_OK) return 1;
    stage_event(&event, &seq, 9300, AP_KIND_PRIV, 2u, AP_SEV_HIGH, 800u,
                0u, 1000u, 0u, "init");
    if (send_event(fd, key, &event) != AP_OK) return 1;
    stage_event(&event, &seq, 9300, AP_KIND_NET, AP_NET_CONNECT, AP_SEV_HIGH,
                900u, 0u, 0u, 0u, "peer:10.9.8.8:443");
    return send_event(fd, key, &event) == AP_OK ? 0 : 1;
  }
  if (strcmp(argv[2], "injectionchain") == 0) {
    uint64_t seq = 1u;
    uint64_t ts = ap_clock_ns();
    stage_timed(&event, &seq, &ts, 9400, AP_KIND_KERNEL, 1u, AP_SEV_HIGH,
                900u, 0u, 0u, 0u, "process_vm_writev");
    event.arg[3] = 3u;
    if (send_event(fd, key, &event) != AP_OK) return 1;
    stage_timed(&event, &seq, &ts, 9400, AP_KIND_MEMPROT, 1u, AP_SEV_CRITICAL,
                940u, 0u, 0u, 7u, "mprotect");
    if (send_event(fd, key, &event) != AP_OK) return 1;
    stage_timed(&event, &seq, &ts, 9400, AP_KIND_EXEC, 1u, AP_SEV_HIGH,
                900u, 0u, 0u, 0u, "/bin/app");
    if (send_event(fd, key, &event) != AP_OK) return 1;
    stage_timed(&event, &seq, &ts, 9400, AP_KIND_FLOW, AP_FLOW_RETURN_SITE,
                AP_SEV_HIGH, 900u, 0xdead00u, 0u, 0u, "strong");
    return send_event(fd, key, &event) == AP_OK ? 0 : 1;
  }
  if (strcmp(argv[2], "exploitchain") == 0) {
    uint64_t seq = 1u;
    uint64_t ts = ap_clock_ns();
    stage_timed(&event, &seq, &ts, 9500, AP_KIND_MEMREGION, 2u, AP_SEV_CRITICAL,
                940u, 0x3000u, 0x4000u, 6u, "/tmp/wx");
    if (send_event(fd, key, &event) != AP_OK) return 1;
    stage_timed(&event, &seq, &ts, 9500, AP_KIND_FLOW, AP_FLOW_RETURN_SITE,
                AP_SEV_HIGH, 900u, 0xdead00u, 0u, 0u, "strong");
    if (send_event(fd, key, &event) != AP_OK) return 1;
    stage_timed(&event, &seq, &ts, 9500, AP_KIND_PRIV, 1u, AP_SEV_MEDIUM,
                450u, 0u, 0u, 0u, "setid");
    if (send_event(fd, key, &event) != AP_OK) return 1;
    stage_timed(&event, &seq, &ts, 9500, AP_KIND_NET, AP_NET_CONNECT,
                AP_SEV_HIGH, 900u, 0u, 0u, 0u, "peer:10.9.8.9:4444");
    return send_event(fd, key, &event) == AP_OK ? 0 : 1;
  }
  if (strcmp(argv[2], "credchain") == 0) {
    uint64_t seq = 1u;
    uint64_t ts = ap_clock_ns();
    stage_timed(&event, &seq, &ts, 9600, AP_KIND_KERNEL, 1u, AP_SEV_HIGH,
                900u, 0u, 0u, 0u, "process_vm_readv");
    event.arg[3] = 3u;
    if (send_event(fd, key, &event) != AP_OK) return 1;
    stage_timed(&event, &seq, &ts, 9600, AP_KIND_KERNEL, 1u, AP_SEV_HIGH,
                900u, 0u, 0u, 0u, "credential_theft");
    event.arg[3] = 3u;
    if (send_event(fd, key, &event) != AP_OK) return 1;
    stage_timed(&event, &seq, &ts, 9600, AP_KIND_PRIV, 1u, AP_SEV_MEDIUM,
                450u, 0u, 0u, 0u, "setid");
    return send_event(fd, key, &event) == AP_OK ? 0 : 1;
  }
  if (strcmp(argv[2], "fileburst") == 0) {
    uint64_t seq = 1u;
    uint64_t ts = ap_clock_ns();
    stage_timed(&event, &seq, &ts, 9700, AP_KIND_FILE, AP_FILE_IO,
                AP_SEV_LOW, 650u, 2000000u, 100u, 0u, "worker");
    return send_event(fd, key, &event) == AP_OK ? 0 : 1;
  }
  if (strcmp(argv[2], "destructive") == 0) {
    uint64_t seq = 1u;
    uint64_t ts = ap_clock_ns();
    stage_timed(&event, &seq, &ts, 9800, AP_KIND_FILE, AP_FILE_IO,
                AP_SEV_LOW, 650u, 2000000u, 100u, 0u, "worker");
    if (send_event(fd, key, &event) != AP_OK) return 1;
    stage_timed(&event, &seq, &ts, 9800, AP_KIND_FILE, AP_FILE_ACTION,
                AP_SEV_MEDIUM, 720u, 264u, 0u, 0u, "file_rename");
    if (send_event(fd, key, &event) != AP_OK) return 1;
    stage_timed(&event, &seq, &ts, 9800, AP_KIND_FILE, AP_FILE_ACTION,
                AP_SEV_MEDIUM, 720u, 263u, 0u, 0u, "file_unlink");
    return send_event(fd, key, &event) == AP_OK ? 0 : 1;
  }
  if (strcmp(argv[2], "exfil") == 0) {
    uint64_t seq = 1u;
    uint64_t ts = ap_clock_ns();
    stage_timed(&event, &seq, &ts, 9900, AP_KIND_FILE, AP_FILE_IO,
                AP_SEV_LOW, 650u, 0u, 0u, 9000000u, "worker");
    event.arg[3] = 6000000u;
    if (send_event(fd, key, &event) != AP_OK) return 1;
    stage_timed(&event, &seq, &ts, 9900, AP_KIND_NET, AP_NET_CONNECT,
                AP_SEV_HIGH, 900u, 0u, 0u, 0u, "peer:10.9.8.10:443");
    return send_event(fd, key, &event) == AP_OK ? 0 : 1;
  }
  if (strcmp(argv[2], "filebenign") == 0) {
    uint64_t seq = 1u;
    uint64_t ts = ap_clock_ns();
    stage_timed(&event, &seq, &ts, 9950, AP_KIND_FILE, AP_FILE_IO,
                AP_SEV_LOW, 650u, 512u, 1u, 256u, "worker");
    event.arg[3] = 128u;
    if (send_event(fd, key, &event) != AP_OK) return 1;
    stage_timed(&event, &seq, &ts, 9950, AP_KIND_FILE, AP_FILE_ACTION,
                AP_SEV_MEDIUM, 720u, 272u, 0u, 0u, "file_chmod");
    return send_event(fd, key, &event) == AP_OK ? 0 : 1;
  }
  if (strcmp(argv[2], "duplicate") == 0) {
    fill(&event, "clean", 0);
    for (index = 0; index < (argc > 3 ? atoi(argv[3]) : 2); ++index) {
      if (ap_sys_send_sealed(fd, key, &event) != AP_OK) {
        fprintf(stderr, "inject: write failed\n");
        return 1;
      }
    }
    return 0;
  }
  if (strcmp(argv[2], "staleseq") == 0) {
    fill(&event, "clean", 0);
    event.seq = 2u;
    snprintf(event.text, sizeof(event.text), "%s", "seq_first");
    if (send_event(fd, key, &event) != AP_OK) return 1;
    event.seq = 1u;
    snprintf(event.text, sizeof(event.text), "%s", "seq_stale");
    if (send_event(fd, key, &event) != AP_OK) return 1;
    event.seq = 3u;
    snprintf(event.text, sizeof(event.text), "%s", "seq_next");
    return send_event(fd, key, &event) == AP_OK ? 0 : 1;
  }
  fill(&event, argv[2], 0);
  for (index = 0; index < (argc > 3 ? atoi(argv[3]) : 1); ++index) {
    event.seq = (uint64_t)index + 1;
    if (ap_sys_send_sealed(fd, key, &event) != AP_OK) {
      fprintf(stderr, "inject: write failed\n");
      return 1;
    }
  }
  return 0;
}
