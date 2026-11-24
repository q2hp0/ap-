#ifndef APTRANSPORT_H
#define APTRANSPORT_H

#include "apabi.h"
#include "apcrypto.h"

#define AP_TRANSPORT_VERSION 1u
#define AP_TRANSPORT_TYPE_EVENT 1u
#define AP_TRANSPORT_MAGIC 0x41505452u
#define AP_TRANSPORT_PACKET_LEN 256u
#define AP_TRANSPORT_HEADER_LEN 8u
#define AP_TRANSPORT_EVENT_LEN 216u
#define AP_TRANSPORT_KEY_LEN 32u
#define AP_TRANSPORT_TAG_LEN 32u
#define AP_TRANSPORT_MAX_PATH 4096u

typedef struct ap_packet {
  uint8_t data[AP_TRANSPORT_PACKET_LEN];
} ap_packet;

#ifdef __cplusplus
extern "C" {
#endif

int ap_transport_key_path(const char *socket_path, char *out, size_t cap);
int ap_transport_key_create(const char *socket_path, uint8_t key[AP_TRANSPORT_KEY_LEN]);
int ap_transport_key_create_path(const char *path, uint8_t key[AP_TRANSPORT_KEY_LEN]);
int ap_transport_key_load(const char *socket_path, uint8_t key[AP_TRANSPORT_KEY_LEN]);
int ap_transport_key_load_path(const char *path, uint8_t key[AP_TRANSPORT_KEY_LEN]);
int ap_transport_seal(const uint8_t key[AP_TRANSPORT_KEY_LEN], const ap_event *event,
                      ap_packet *packet);
int ap_transport_open(const uint8_t key[AP_TRANSPORT_KEY_LEN], const ap_packet *packet,
                      size_t len, ap_event *event);

#ifdef __cplusplus
}
#endif

#endif
