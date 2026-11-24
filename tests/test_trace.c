#include "aptrace.h"
#include "apsys.h"

#include <stdio.h>

static int events = 0;
static int kernel_events = 0;

static int on_event(const ap_event *event, ap_verdict *verdict, void *user) {
  (void)verdict;
  (void)user;
  if (event->size == sizeof(ap_event) && event->abi_version == AP_ABI_VERSION) {
    ++events;
    if (event->kind == AP_KIND_KERNEL) {
      ++kernel_events;
    }
  }
  return AP_DECISION_ALLOW;
}

int main(int argc, char **argv) {
  const char *fallback[] = {"/bin/true", NULL};
  ap_trace_config config;
  int status;
  int capabilities = ap_sys_capability_state();
  int expect_kernel = argc > 1;

  config.argv = expect_kernel ? (const char **)(argv + 1) : fallback;
  config.argc = expect_kernel ? argc - 1 : 1;
  config.flags = AP_TRACE_FOLLOW_FORK;
  config.mask = AP_TRACE_MASK_ALL;
  config.max_events = 512;
  status = ap_trace_run(&config, on_event, NULL);

  printf("trace: caps=%d status=%d events=%d kernel=%d\n", capabilities, status,
         events, kernel_events);
  if (status == AP_OK) {
    if (events == 0) {
      return 1;
    }
    return expect_kernel && kernel_events == 0 ? 1 : 0;
  }
  return status == AP_ERR_UNSUPPORTED ? 0 : 1;
}
