#define _POSIX_C_SOURCE 200809L
#include "apksensor.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

/* ap_ksample is 8+8+4+4+3*8 = 48 bytes in the header and eBPF sample. */
_Static_assert(sizeof(ap_ksample) == 48u, "ksensor sample size must match header");
_Static_assert(sizeof(ap_ksensor_status_t) >=
                   7u * sizeof(uint32_t) + AP_KSENSOR_REASON_LEN,
               "ksensor status must hold all fields and a reason");
_Static_assert(sizeof(ap_ksensor_status_t) <= 256u,
               "ksensor status must stay bounded");

static int failures = 0;

static void check(int condition, const char *name) {
  if (!condition) {
    fprintf(stderr, "ksensor test fail: %s\n", name);
    ++failures;
  }
}

static void test_probe(void) {
  uint32_t bpf_ok = 7u;
  uint32_t perf_ok = 7u;
  uint32_t lsm_ok = 7u;

  check(ap_ksensor_probe(&bpf_ok, &perf_ok, &lsm_ok) == AP_OK,
        "probe status");
  check(bpf_ok <= 1u && perf_ok <= 1u && lsm_ok <= 1u, "probe booleans");
  check(lsm_ok == 0u || bpf_ok == 1u, "lsm requires bpf");
  check(ap_ksensor_probe(NULL, NULL, NULL) == AP_OK, "probe null outputs");
}

static void test_sample_to_event(void) {
  ap_ksample sample;
  ap_event event;
  size_t i;

  memset(&sample, 0, sizeof(sample));
  sample.ts_ns = 1234567890ull;
  sample.pid_tgid = ((uint64_t)4242u << 32) | 0xdeadbeefu;
  sample.label_id = AP_KLABEL_EXEC;
  sample.subkind = 17u;
  sample.arg[0] = 11u;
  sample.arg[1] = 22u;
  sample.arg[2] = 33u;

  memset(&event, 0xa5, sizeof(event));
  check(ap_ksensor_sample_to_event(&sample, &event) == AP_OK,
        "sample conversion");
  check(event.size == sizeof(ap_event), "event size");
  check(event.abi_version == AP_ABI_VERSION, "event abi");
  check(event.kind == AP_KIND_KERNEL, "event kind");
  check(event.seq == 0u, "event seq");
  check(event.ts_ns == sample.ts_ns, "event timestamp");
  check(event.pid == 4242, "event pid split");
  check(event.tid == (int64_t)0xdeadbeefu, "event tid split");
  check(event.subkind == 17u, "event subkind");
  check(event.arg[0] == 11u && event.arg[1] == 22u && event.arg[2] == 33u,
        "event args");
  check(event.arg[3] == AP_KSENSOR_SOURCE_MARK, "event source mark");
  check(strcmp(event.text, "exec") == 0, "event text");
  check(strlen(event.text) < AP_TEXT_LEN, "event text bounded");
  check(event.severity == AP_SEV_HIGH || event.severity == AP_SEV_CRITICAL,
        "event severity");
  check(event.confidence_x1000 > 0u && event.confidence_x1000 <= 1000u,
        "event confidence");

  sample.label_id = 0u;
  check(ap_ksensor_sample_to_event(&sample, &event) == AP_OK, "label none");
  sample.label_id = AP_KLABEL_ANTI_ANALYSIS;
  check(ap_ksensor_sample_to_event(&sample, &event) == AP_OK, "label last");
  check(strcmp(event.text, "anti_analysis") == 0, "last label text");
  sample.label_id = AP_KLABEL_ANTI_ANALYSIS + 1u;
  check(ap_ksensor_sample_to_event(&sample, &event) == AP_ERR_RANGE,
        "invalid label rejected");
  sample.label_id = AP_KLABEL_EXEC;
  check(ap_ksensor_sample_to_event(NULL, &event) == AP_ERR_ARG,
        "null sample rejected");
  check(ap_ksensor_sample_to_event(&sample, NULL) == AP_ERR_ARG,
        "null event rejected");
  for (i = 0u; i < sizeof(event.text); ++i) {
    if (event.text[i] == '\0') break;
  }
  check(i < sizeof(event.text), "text nul terminated");
}

static void test_label_names(void) {
  const uint32_t count = AP_KLABEL_ANTI_ANALYSIS + 1u;
  uint32_t i;
  uint32_t j;

  for (i = 0u; i < count; ++i) {
    const char *name = ap_ksensor_label_name(i);
    check(name != NULL && name[0] != '\0', "label name non-empty");
    if (name == NULL) continue;
    check(strlen(name) < AP_TEXT_LEN, "label name bounded");
    for (j = 0u; j < i; ++j) {
      check(strcmp(name, ap_ksensor_label_name(j)) != 0,
            "label names unique");
    }
  }
  check(strcmp(ap_ksensor_label_name(count), "unknown") == 0,
        "unknown label name");

  check(strcmp(ap_ksensor_label_name(AP_KLABEL_PTRACE), "ptrace") == 0,
        "ptrace label contract");
  check(strcmp(ap_ksensor_label_name(AP_KLABEL_CRED), "cred_change") == 0,
        "credential change label contract");
  check(strcmp(ap_ksensor_label_name(AP_KLABEL_ROOTKIT), "kernel_rootkit") == 0,
        "rootkit label contract");
  check(strcmp(ap_ksensor_label_name(AP_KLABEL_CREDENTIAL_THEFT),
               "credential_theft") == 0,
        "credential theft label contract");
  check(strcmp(ap_ksensor_label_name(AP_KLABEL_FILELESS_EXEC),
               "fileless_exec") == 0,
        "fileless label contract");
  check(strcmp(ap_ksensor_label_name(AP_KLABEL_ANTI_ANALYSIS),
               "anti_analysis") == 0,
        "anti-analysis label contract");
}

static void test_open_unprivileged(void) {
  char reason[AP_KSENSOR_REASON_LEN];
  ap_ksensor *handle = (ap_ksensor *)(uintptr_t)1u;
  uint32_t i;
  int status;

  memset(reason, 0, sizeof(reason));
  status = ap_ksensor_open(AP_KSENSOR_FLAG_RAW_TRACEPOINTS, 0u, &handle,
                           reason, sizeof(reason));
  check(status == AP_ERR_UNSUPPORTED || status == AP_ERR_IO,
        "unprivileged open rejected");
  check(handle == NULL, "failed open leaves null handle");
  check(reason[0] != '\0', "failed open gives reason");
  for (i = 0u; i < sizeof(reason) && reason[i] != '\0'; ++i) {
    check(!isupper((unsigned char)reason[i]), "reason lowercase");
    if (reason[i] != ' ' && reason[i] != ';' && reason[i] != '_' &&
        reason[i] != '-') {
      check(islower((unsigned char)reason[i]) ||
                isdigit((unsigned char)reason[i]),
            "reason characters");
    }
  }
  if (status == AP_OK) ap_ksensor_close(handle);

  handle = (ap_ksensor *)(uintptr_t)1u;
  check(ap_ksensor_open(AP_KSENSOR_FLAG_RAW_TRACEPOINTS, 0u, NULL, reason,
                        sizeof(reason)) == AP_ERR_ARG,
        "null out rejected");
  check(ap_ksensor_open(0x80000000u, 0u, &handle, NULL, 0u) == AP_ERR_ARG,
        "unknown flags rejected");
  check(handle == NULL, "argument failure leaves null handle");
}

static void test_null_safety(void) {
  ap_ksensor_counters_t counters;
  ap_ksensor_status_t status;

  check(ap_ksensor_lsm_set_mask(NULL, 1u) == AP_ERR_ARG, "null lsm mask");
  ap_ksensor_close(NULL);
  ap_ksensor_counters(NULL, &counters);
  check(counters.probes == 0u && counters.events == 0u, "null counters");
  ap_ksensor_status(NULL, &status);
  check(status.reason[0] == '\0' && status.sensor_active == 0u,
        "null status");
  ap_ksensor_counters(NULL, NULL);
  ap_ksensor_status(NULL, NULL);
  check(ap_ksensor_poll(NULL, 1u, NULL, NULL) == AP_ERR_ARG,
        "null poll handle");
}

int main(void) {
  test_probe();
  test_sample_to_event();
  test_label_names();
  test_open_unprivileged();
  test_null_safety();
  if (failures != 0) {
    fprintf(stderr, "ksensor tests: failed\n");
    return 1;
  }
  printf("ksensor tests: ok\n");
  return 0;
}
