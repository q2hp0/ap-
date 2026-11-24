#include "apabi.h"
#include "apsys.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

static void check(int condition, const char *name) {
  if (!condition) {
    fprintf(stderr, "fail: %s\n", name);
    ++failures;
  }
}

int main(void) {
  ap_event event;
  uint8_t bytes[8];
  char hex[17];

  check(sizeof(ap_event) == 216u, "event size");
  check(sizeof(ap_verdict) == 168u, "verdict size");
  check(AP_ABI_VERSION == 2u, "abi version");
  check(AP_PROC_START == 3u && AP_PROC_EXIT == 4u, "process subkinds");
  check(AP_RULE_NONE == 0u && AP_RULE_CORRELATED == 16u &&
        AP_RULE_RAW_SOCKET == 17u && AP_RULE_EXEC_AFTER_WX == 18u &&
        AP_RULE_KERNEL_CHAIN == 19u && AP_RULE_KERNEL_ROOTKIT == 20u &&
        AP_RULE_CREDENTIAL_THEFT == 21u && AP_RULE_PERSISTENCE == 22u &&
        AP_RULE_CONTAINER_ESCAPE == 23u && AP_RULE_FILELESS_EXEC == 24u &&
        AP_RULE_ANTI_ANALYSIS == 25u && AP_RULE_BEACONING == 26u &&
        AP_RULE_PROCESS_INJECTION == 27u && AP_RULE_EXPLOIT_CHAIN == 28u &&
        AP_RULE_CREDENTIAL_DUMP == 29u && AP_RULE_FILE_WRITE_BURST == 30u &&
        AP_RULE_DESTRUCTIVE_CHAIN == 31u && AP_RULE_DATA_EXFILTRATION == 32u &&
        AP_RULE_MAX == 32u, "rule values");
  check(AP_KIND_FILE == 12u && AP_FILE_IO == 1u && AP_FILE_ACTION == 2u,
        "file kinds and subkinds");

  ap_event_init(&event, AP_KIND_MEMPROT);
  check(event.size == sizeof(event), "event init size");
  check(event.abi_version == AP_ABI_VERSION, "event init version");
  check(event.ts_ns > 0u, "event clock");

  check(ap_hex_encode((const uint8_t *)"\x00\x0f\xff\x10", 4, hex, sizeof(hex)) == AP_OK,
        "hex encode");
  check(strcmp(hex, "000fff10") == 0, "hex value");
  check(ap_hex_decode(hex, 8, bytes, sizeof(bytes)) == AP_OK, "hex decode");
  check(bytes[0] == 0u && bytes[1] == 15u && bytes[2] == 255u && bytes[3] == 16u,
        "hex roundtrip");
  check(ap_hex_decode("xyz", 3, bytes, sizeof(bytes)) == AP_ERR_ARG, "hex rejects odd input");
  check(ap_hex_decode("zz", 2, bytes, sizeof(bytes)) == AP_ERR_ARG, "hex rejects bad digit");
  check(strcmp(ap_kind_name(AP_KIND_HEAP), "heap") == 0, "kind name");
  check(strcmp(ap_kind_name(AP_KIND_FILE), "file") == 0, "file kind name");
  check(strcmp(ap_status_name(AP_ERR_UNSUPPORTED), "unsupported") == 0, "status name");
  check(ap_sys_init() == AP_OK, "sys init");
  check(ap_sys_capability_state() >= 0, "capability probe");

  printf("abi tests: %s\n", failures == 0 ? "ok" : "failed");
  return failures == 0 ? 0 : 1;
}
