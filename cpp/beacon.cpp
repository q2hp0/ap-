#include "apbeacon.h"

#include <cstring>

namespace {

struct PeerState {
  bool used;
  char peer[AP_BEACON_KEY_LEN];
  uint64_t ts[AP_BEACON_SAMPLES];
  uint32_t bytes[AP_BEACON_SAMPLES];
  uint32_t cursor;
  uint32_t count;
  uint64_t last_finding;
};

struct BeaconState {
  PeerState peers[AP_BEACON_PEERS];
  uint64_t peer_cursor;
  uint64_t added;
  uint64_t evicted;
  uint64_t findings;
  uint64_t suppressed;
};

void copy_key(char out[AP_BEACON_KEY_LEN], const char *key) {
  if (key == nullptr || key[0] == '\0') {
    out[0] = '\0';
    return;
  }
  std::size_t i = 0;
  for (; i + 1 < AP_BEACON_KEY_LEN && key[i] != '\0'; ++i) out[i] = key[i];
  out[i] = '\0';
}

void sort_samples(uint64_t *ts, uint32_t *bytes, uint32_t count) {
  for (uint32_t i = 1; i < count; ++i) {
    uint64_t key_ts = ts[i];
    uint32_t key_bytes = bytes[i];
    uint32_t j = i;
    while (j > 0u && ts[j - 1u] > key_ts) {
      ts[j] = ts[j - 1u];
      bytes[j] = bytes[j - 1u];
      --j;
    }
    ts[j] = key_ts;
    bytes[j] = key_bytes;
  }
}

}  // namespace

struct ap_beacon {
  BeaconState state;
};

extern "C" ap_beacon *ap_beacon_new(void) {
  ap_beacon *beacon = new ap_beacon;
  std::memset(&beacon->state, 0, sizeof(beacon->state));
  return beacon;
}

extern "C" void ap_beacon_free(ap_beacon *beacon) { delete beacon; }

extern "C" void ap_beacon_reset(ap_beacon *beacon) {
  if (beacon == nullptr) return;
  std::memset(&beacon->state, 0, sizeof(beacon->state));
}

extern "C" int ap_beacon_add(ap_beacon *beacon,
                             const ap_beacon_observation *observation) {
  if (beacon == nullptr || observation == nullptr) return AP_ERR_ARG;
  if (observation->ts_ns == 0u) return AP_ERR_ARG;
  if (observation->peer[0] == '\0') return AP_ERR_ARG;

  PeerState *target = nullptr;
  for (uint32_t i = 0; i < AP_BEACON_PEERS; ++i) {
    if (beacon->state.peers[i].used != 0 &&
        std::strcmp(beacon->state.peers[i].peer, observation->peer) == 0) {
      target = &beacon->state.peers[i];
      break;
    }
  }
  if (target == nullptr) {
    uint32_t at = static_cast<uint32_t>(beacon->state.peer_cursor % AP_BEACON_PEERS);
    target = &beacon->state.peers[at];
    if (target->used) ++beacon->state.evicted;
    std::memset(target, 0, sizeof(*target));
    target->used = true;
    copy_key(target->peer, observation->peer);
    ++beacon->state.peer_cursor;
  }

  target->ts[target->cursor] = observation->ts_ns;
  target->bytes[target->cursor] = observation->bytes_out;
  target->cursor = (target->cursor + 1u) % AP_BEACON_SAMPLES;
  if (target->count < AP_BEACON_SAMPLES) ++target->count;
  ++beacon->state.added;
  return AP_OK;
}

extern "C" int ap_beacon_evaluate(ap_beacon *beacon, uint64_t now_ns,
                                  ap_beacon_cb callback, void *user) {
  if (beacon == nullptr || callback == nullptr) return AP_ERR_ARG;
  if (now_ns == 0u) return AP_ERR_ARG;

  for (uint32_t i = 0; i < AP_BEACON_PEERS; ++i) {
    PeerState &peer = beacon->state.peers[i];
    if (!peer.used || peer.count < AP_BEACON_MIN_SAMPLES) continue;
    if (peer.last_finding != 0u && now_ns >= peer.last_finding &&
        now_ns - peer.last_finding < AP_BEACON_WINDOW_NS) {
      ++beacon->state.suppressed;
      continue;
    }

    uint64_t ts[AP_BEACON_SAMPLES];
    uint32_t bytes[AP_BEACON_SAMPLES];
    uint32_t count = 0u;
    for (uint32_t j = 0; j < peer.count; ++j) {
      uint32_t at = (peer.cursor + AP_BEACON_SAMPLES - 1u - j) % AP_BEACON_SAMPLES;
      if (peer.ts[at] == 0u || now_ns < peer.ts[at]) continue;
      if (now_ns - peer.ts[at] > AP_BEACON_WINDOW_NS) continue;
      ts[count] = peer.ts[at];
      bytes[count] = peer.bytes[at];
      ++count;
    }
    if (count < AP_BEACON_MIN_SAMPLES) continue;
    sort_samples(ts, bytes, count);

    uint64_t span = ts[count - 1u] - ts[0];
    if (span == 0u) continue;
    uint64_t mean = span / static_cast<uint64_t>(count - 1u);
    if (mean == 0u || mean > 60000000000ULL) continue;
    uint64_t jitter = 0u;
    for (uint32_t j = 1; j < count; ++j) {
      uint64_t interval = ts[j] - ts[j - 1u];
      uint64_t delta = interval > mean ? interval - mean : mean - interval;
      if (delta > 60000000000ULL) delta = 60000000000ULL;
      jitter += delta;
    }
    jitter /= static_cast<uint64_t>(count - 1u);
    uint64_t tolerance = mean / 5u + 500000000ULL;
    if (jitter > tolerance) continue;

    uint32_t total = 0u;
    uint32_t nonzero = 0u;
    for (uint32_t j = 0; j < count; ++j) {
      total += bytes[j];
      if (bytes[j] != 0u) ++nonzero;
    }
    if (nonzero < 2u || total == 0u) continue;

    ap_beacon_finding finding;
    std::memset(&finding, 0, sizeof(finding));
    finding.ts_ns = ts[count - 1u];
    finding.span_ns = span;
    finding.jitter_ns = jitter;
    finding.connections = count;
    finding.bytes_out = total;
    finding.score_x1000 = 700u + (count - AP_BEACON_MIN_SAMPLES) * 100u;
    copy_key(finding.peer, peer.peer);
    if (callback(&finding, user) == AP_OK) ++beacon->state.findings;
    peer.last_finding = finding.ts_ns;
  }
  return AP_OK;
}
