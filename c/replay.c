#include "apreplay.h"

#include "apsys.h"

#include <string.h>

#define AP_REPLAY_STRUCT_SIZE \
  (AP_REPLAY_SLOTS * AP_TRANSPORT_TAG_LEN + AP_REPLAY_SLOTS + 8u + 16u)
#define AP_SEQUENCE_STRUCT_SIZE \
  (AP_SEQUENCE_SLOTS * 4u + AP_SEQUENCE_SLOTS * 8u + 8u + AP_SEQUENCE_SLOTS * 8u + \
   AP_SEQUENCE_SLOTS + 24u)

_Static_assert(sizeof(ap_replay) == AP_REPLAY_STRUCT_SIZE + AP_SEQUENCE_STRUCT_SIZE,
               "replay layout changed");

static uint64_t ap_replay_peer_epoch(uint32_t peer_pid) {
  uint64_t epoch = 0u;
  if (peer_pid == 0u) return 0u;
  if (ap_sys_proc_starttime((pid_t)peer_pid, &epoch) != AP_OK) return 0u;
  return epoch;
}

static int ap_replay_tag_present(const ap_replay *filter, const ap_packet *packet) {
  const uint8_t *tag = packet->data + AP_TRANSPORT_PACKET_LEN - AP_TRANSPORT_TAG_LEN;
  uint32_t index;

  for (index = 0u; index < filter->count; ++index) {
    if (filter->used[index] != 0u &&
        ap_constant_time_eq(filter->tags[index], tag, AP_TRANSPORT_TAG_LEN) != 0) {
      return 1;
    }
  }
  return 0;
}

static void ap_replay_store_tag(ap_replay *filter, const ap_packet *packet) {
  const uint8_t *tag = packet->data + AP_TRANSPORT_PACKET_LEN - AP_TRANSPORT_TAG_LEN;

  memcpy(filter->tags[filter->next], tag, AP_TRANSPORT_TAG_LEN);
  filter->used[filter->next] = 1u;
  filter->next = (filter->next + 1u) % AP_REPLAY_SLOTS;
  if (filter->count < AP_REPLAY_SLOTS) ++filter->count;
}

void ap_replay_init(ap_replay *filter) {
  if (filter != NULL) memset(filter, 0, sizeof(*filter));
}

int ap_replay_accept(ap_replay *filter, const ap_packet *packet) {
  if (filter == NULL || packet == NULL) return AP_ERR_ARG;
  if (ap_replay_tag_present(filter, packet) != 0) {
    ++filter->duplicates;
    return AP_ERR_REPLAY;
  }
  ap_replay_store_tag(filter, packet);
  ++filter->accepted;
  return AP_OK;
}

int ap_replay_accept_sequence(ap_replay *filter, const ap_packet *packet, uint64_t seq,
                              uint32_t peer_pid) {
  uint32_t index = 0u;
  uint64_t current_epoch = 0u;
  int found = 0;

  if (filter == NULL || packet == NULL) return AP_ERR_ARG;
  if (ap_replay_tag_present(filter, packet) != 0) {
    ++filter->duplicates;
    return AP_ERR_REPLAY;
  }
  if (seq != 0u) {
    for (index = 0u; index < filter->peer_count; ++index) {
      if (filter->peer_used[index] == 0u || filter->peer_pid[index] != peer_pid) continue;
      found = 1;
      break;
    }
    if (found != 0) {
      if (seq <= filter->peer_seq[index]) {
        current_epoch = ap_replay_peer_epoch(peer_pid);
        if (filter->peer_epoch[index] != 0u && current_epoch != 0u &&
            current_epoch != filter->peer_epoch[index]) {
          filter->peer_epoch[index] = current_epoch;
        } else {
          if (filter->peer_epoch[index] == 0u && current_epoch != 0u) {
            filter->peer_epoch[index] = current_epoch;
          }
          ++filter->sequence_drops;
          return AP_ERR_SEQUENCE;
        }
      } else if (filter->peer_epoch[index] == 0u) {
        current_epoch = ap_replay_peer_epoch(peer_pid);
        if (current_epoch != 0u) filter->peer_epoch[index] = current_epoch;
      }
      filter->peer_seq[index] = seq;
      ap_replay_store_tag(filter, packet);
      ++filter->accepted;
      ++filter->sequences;
      return AP_OK;
    }
  }
  ap_replay_store_tag(filter, packet);
  ++filter->accepted;
  if (seq == 0u) return AP_OK;

  ++filter->sequences;
  index = filter->peer_next;
  if (filter->peer_count < AP_SEQUENCE_SLOTS) {
    ++filter->peer_count;
  } else {
    ++filter->peer_evictions;
  }
  filter->peer_next = (filter->peer_next + 1u) % AP_SEQUENCE_SLOTS;
  filter->peer_pid[index] = peer_pid;
  filter->peer_seq[index] = seq;
  filter->peer_epoch[index] = ap_replay_peer_epoch(peer_pid);
  filter->peer_used[index] = 1u;
  return AP_OK;
}
