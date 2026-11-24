#ifndef APHEAP_H
#define APHEAP_H

#include "apabi.h"

#define AP_HEAP_ENV_SOCKET "AP_SOCKET"
#define AP_HEAP_QUARANTINE 256u

#ifdef __cplusplus
extern "C" {
#endif

int ap_heap_event_validate(const ap_event *event);
const char *ap_heap_sub_name(uint32_t subkind);

#ifdef __cplusplus
}
#endif

#endif
