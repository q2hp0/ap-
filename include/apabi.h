#ifndef APABI_H
#define APABI_H

#include <stdint.h>
#include <stddef.h>

#define AP_ABI_VERSION 2u
#define AP_ENGINE_VERSION 2u

#define AP_TEXT_LEN 128u
#define AP_MAX_PACKET_BYTES 256u

enum ap_status {
  AP_OK = 0,
  AP_ERR_ARG = -1,
  AP_ERR_STATE = -2,
  AP_ERR_NOMEM = -3,
  AP_ERR_IO = -4,
  AP_ERR_UNSUPPORTED = -5,
  AP_ERR_RANGE = -6,
  AP_ERR_AUTH = -7,
  AP_ERR_REPLAY = -8,
  AP_ERR_SEQUENCE = -9
};

enum ap_kind {
  AP_KIND_NONE = 0,
  AP_KIND_PROC = 1,
  AP_KIND_MEMREGION = 2,
  AP_KIND_MEMPROT = 3,
  AP_KIND_EXEC = 4,
  AP_KIND_PRIV = 5,
  AP_KIND_KERNEL = 6,
  AP_KIND_NET = 7,
  AP_KIND_HEAP = 8,
  AP_KIND_FLOW = 9,
  AP_KIND_TRACE = 10,
  AP_KIND_HEARTBEAT = 11,
  AP_KIND_FILE = 12
};

enum ap_severity {
  AP_SEV_INFO = 0,
  AP_SEV_LOW = 1,
  AP_SEV_MEDIUM = 2,
  AP_SEV_HIGH = 3,
  AP_SEV_CRITICAL = 4
};

enum ap_decision {
  AP_DECISION_ALLOW = 0,
  AP_DECISION_DENY = 1,
  AP_DECISION_STOP = 2
};

enum ap_proc_sub {
  AP_PROC_INFO = 0,
  AP_PROC_EXEC_PATH = 1,
  AP_PROC_EXEC_COMM = 2,
  AP_PROC_START = 3,
  AP_PROC_EXIT = 4
};

enum ap_net_sub {
  AP_NET_SOCKET = 1,
  AP_NET_CONNECT = 2,
  AP_NET_PACKET = 3,
  AP_NET_FRAGMENT = 4
};

enum ap_flow_sub {
  AP_FLOW_RETURN_SITE = 1,
  AP_FLOW_INDIRECT = 2,
  AP_FLOW_STACK = 3,
  AP_FLOW_SHADOW = 4
};

enum ap_heap_sub {
  AP_HEAP_OVERFLOW = 1,
  AP_HEAP_DOUBLE_FREE = 2,
  AP_HEAP_INVALID_FREE = 3,
  AP_HEAP_QUARANTINE = 4
};

enum ap_file_sub {
  AP_FILE_IO = 1,
  AP_FILE_ACTION = 2
};

enum ap_rule {
  AP_RULE_NONE = 0,
  AP_RULE_WX_REGION = 1,
  AP_RULE_WX_TRANSITION = 2,
  AP_RULE_STACK_EXEC = 3,
  AP_RULE_RETURN_OUTSIDE_EXEC = 4,
  AP_RULE_SHADOW_MISMATCH = 5,
  AP_RULE_PRIV_CROSSING = 6,
  AP_RULE_MODULE_LOAD = 7,
  AP_RULE_KERNEL_IFACE = 8,
  AP_RULE_TCP_STATE = 9,
  AP_RULE_TCP_FLAGS = 10,
  AP_RULE_IP_MALFORMED = 11,
  AP_RULE_FRAG_OVERLAP = 12,
  AP_RULE_HEAP_CANARY = 13,
  AP_RULE_DOUBLE_FREE = 14,
  AP_RULE_INVALID_FREE = 15,
  AP_RULE_CORRELATED = 16,
  AP_RULE_RAW_SOCKET = 17,
  AP_RULE_EXEC_AFTER_WX = 18,
  AP_RULE_KERNEL_CHAIN = 19,
  AP_RULE_KERNEL_ROOTKIT = 20,
  AP_RULE_CREDENTIAL_THEFT = 21,
  AP_RULE_PERSISTENCE = 22,
  AP_RULE_CONTAINER_ESCAPE = 23,
  AP_RULE_FILELESS_EXEC = 24,
  AP_RULE_ANTI_ANALYSIS = 25,
  AP_RULE_BEACONING = 26,
  AP_RULE_PROCESS_INJECTION = 27,
  AP_RULE_EXPLOIT_CHAIN = 28,
  AP_RULE_CREDENTIAL_DUMP = 29,
  AP_RULE_FILE_WRITE_BURST = 30,
  AP_RULE_DESTRUCTIVE_CHAIN = 31,
  AP_RULE_DATA_EXFILTRATION = 32,
  AP_RULE_MAX = 32
};

typedef struct ap_event {
  uint32_t size;
  uint16_t abi_version;
  uint16_t kind;
  uint64_t seq;
  uint64_t ts_ns;
  int64_t pid;
  int64_t tid;
  uint32_t subkind;
  uint32_t severity;
  uint32_t confidence_x1000;
  uint64_t arg[4];
  char text[AP_TEXT_LEN];
} ap_event;

typedef struct ap_verdict {
  uint32_t size;
  uint16_t abi_version;
  uint16_t kind;
  uint64_t event_seq;
  uint32_t rule;
  uint32_t severity;
  uint32_t confidence_x1000;
  uint64_t evidence;
  char text[AP_TEXT_LEN];
} ap_verdict;

typedef int (*ap_event_cb)(const ap_event *event, ap_verdict *verdict, void *user);
typedef int (*ap_region_cb)(const ap_event *region, void *user);

#ifdef __cplusplus
extern "C" {
#endif

void ap_event_init(ap_event *event, uint16_t kind);
void ap_verdict_init(ap_verdict *verdict, uint64_t seq);
uint64_t ap_clock_ns(void);
int ap_hex_encode(const uint8_t *data, size_t len, char *out, size_t out_len);
int ap_hex_decode(const char *in, size_t in_len, uint8_t *out, size_t out_len);
const char *ap_kind_name(uint16_t kind);
const char *ap_status_name(int status);

#ifdef __cplusplus
}
#endif

#endif
