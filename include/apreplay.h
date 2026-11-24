#ifndef APREPLAY_H
#define APREPLAY_H

#include "aptransport.h"

#define AP_REPLAY_SLOTS 256u
#define AP_SEQUENCE_SLOTS 64u

typedef struct ap_replay {
  uint8_t tags[AP_REPLAY_SLOTS][AP_TRANSPORT_TAG_LEN];
  uint8_t used[AP_REPLAY_SLOTS];
  uint32_t next;
  uint32_t count;
  uint64_t accepted;
  uint64_t duplicates;
  uint32_t peer_pid[AP_SEQUENCE_SLOTS];
  uint64_t peer_epoch[AP_SEQUENCE_SLOTS];
  uint32_t peer_next;
  uint32_t peer_count;
  uint64_t peer_seq[AP_SEQUENCE_SLOTS];
  uint8_t peer_used[AP_SEQUENCE_SLOTS];
  uint64_t sequences;
  uint64_t sequence_drops;
  uint64_t peer_evictions;
} ap_replay;

#ifdef __cplusplus
extern "C" {
#endif

void ap_replay_init(ap_replay *filter);
int ap_replay_accept(ap_replay *filter, const ap_packet *packet);
int ap_replay_accept_sequence(ap_replay *filter, const ap_packet *packet, uint64_t seq,
                              uint32_t peer_pid);

#ifdef __cplusplus
}
#endif

#endif
