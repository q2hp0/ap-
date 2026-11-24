#include "apnet.h"

#include <cstdio>
#include <cstring>

namespace {

constexpr uint8_t flag_fin = 0x01u;
constexpr uint8_t flag_syn = 0x02u;
constexpr uint8_t flag_rst = 0x04u;
constexpr uint8_t flag_ack = 0x10u;

enum tcp_phase {
  phase_closed = 0,
  phase_syn_sent = 1,
  phase_established = 2,
  phase_fin_wait = 3,
  phase_reset = 4
};

struct flow_key {
  uint8_t family;
  uint8_t src[16];
  uint8_t dst[16];
  uint16_t sport;
  uint16_t dport;
  uint8_t proto;
  uint8_t pad[1];
};

struct tcp_state {
  flow_key key;
  uint32_t last_seq;
  uint32_t last_ack;
  uint64_t last_seen;
  uint8_t phase;
  uint8_t have_seq;
  uint16_t flags_seen;
};

struct frag_state {
  uint8_t family;
  uint8_t src[16];
  uint8_t dst[16];
  uint32_t id;
  uint8_t proto;
  uint8_t used;
  uint64_t last_seen;
  uint8_t bits[64];
};

uint16_t read_be16(const uint8_t *p) {
  return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

uint32_t read_be32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

void set_v4_addr(uint8_t out[16], uint32_t addr) {
  memset(out, 0, 16);
  out[0] = (uint8_t)(addr >> 24);
  out[1] = (uint8_t)(addr >> 16);
  out[2] = (uint8_t)(addr >> 8);
  out[3] = (uint8_t)addr;
}

void swap_addr(uint8_t a[16], uint8_t b[16]) {
  uint8_t tmp[16];
  memcpy(tmp, a, 16);
  memcpy(a, b, 16);
  memcpy(b, tmp, 16);
}

uint64_t key_hash(const flow_key &key) {
  const uint8_t *p = reinterpret_cast<const uint8_t *>(&key);
  uint64_t hash = 1469598103934665603ull;
  for (size_t i = 0; i < sizeof(flow_key); ++i) {
    hash = (hash ^ p[i]) * 1099511628211ull;
  }
  return hash;
}

bool key_equal(const flow_key &a, const flow_key &b) {
  return memcmp(&a, &b, sizeof(flow_key)) == 0;
}

uint64_t peer_hash(uint8_t family, const uint8_t addr[16], uint16_t port) {
  uint64_t hash = 1469598103934665603ull;
  hash = (hash ^ family) * 1099511628211ull;
  for (size_t i = 0; i < 16; ++i) {
    hash = (hash ^ addr[i]) * 1099511628211ull;
  }
  hash = (hash ^ (uint8_t)(port & 0xffu)) * 1099511628211ull;
  hash = (hash ^ (uint8_t)(port >> 8)) * 1099511628211ull;
  return hash;
}

void set_verdict(ap_verdict *verdict, const ap_event *event, uint32_t rule,
                 uint32_t severity, uint32_t confidence, uint64_t evidence,
                 const char *text) {
  if (verdict == nullptr) {
    return;
  }
  ap_verdict_init(verdict, event->seq);
  verdict->kind = AP_KIND_NET;
  verdict->rule = rule;
  verdict->severity = severity;
  verdict->confidence_x1000 = confidence;
  verdict->evidence = evidence;
  std::snprintf(verdict->text, sizeof(verdict->text), "%s", text);
}

uint16_t ip_checksum(const uint8_t *data, size_t len) {
  uint32_t sum = 0;
  size_t i;
  for (i = 0; i + 1 < len; i += 2) {
    sum += read_be16(data + i);
  }
  if (i < len) {
    sum += (uint32_t)data[i] << 8;
  }
  while ((sum >> 16) != 0u) {
    sum = (sum & 0xffffu) + (sum >> 16);
  }
  return (uint16_t)~sum;
}

}  // namespace

struct peer_state {
  uint8_t addr[16];
  uint16_t port;
  uint8_t family;
  uint8_t used;
  uint64_t window_start;
  uint64_t last_seen;
  uint32_t events;
};

struct ap_net_handle {
  tcp_state flows[AP_NET_FLOW_SLOTS];
  frag_state frags[AP_NET_FRAG_SLOTS];
  peer_state peers[AP_NET_PEER_SLOTS];
  uint32_t flow_count;
  uint32_t frag_count;
  uint32_t peer_count;
  ap_net_counters stats;
};

ap_net_handle *ap_net_new(void) {
  ap_net_handle *handle = new ap_net_handle;
  memset(handle, 0, sizeof(*handle));
  return handle;
}

void ap_net_free(ap_net_handle *handle) {
  delete handle;
}

int ap_net_reset(ap_net_handle *handle) {
  if (handle == nullptr) {
    return AP_ERR_ARG;
  }
  memset(handle->flows, 0, sizeof(handle->flows));
  memset(handle->frags, 0, sizeof(handle->frags));
  memset(handle->peers, 0, sizeof(handle->peers));
  handle->flow_count = 0;
  handle->frag_count = 0;
  handle->peer_count = 0;
  return AP_OK;
}

int ap_net_stats(const ap_net_handle *handle, ap_net_counters *stats) {
  if (handle == nullptr || stats == nullptr) {
    return AP_ERR_ARG;
  }
  *stats = handle->stats;
  stats->peers = handle->peer_count;
  return AP_OK;
}

namespace {

void observe_peer(ap_net_handle *handle, uint8_t family,
                  const uint8_t addr[16], uint16_t port, uint64_t now) {
  uint64_t hash = peer_hash(family, addr, port);
  uint32_t oldest = 0u;
  uint64_t oldest_time = ~0ull;
  peer_state *slot = nullptr;

  if (now == 0u) now = 1u;
  for (uint32_t probe = 0u; probe < AP_NET_PEER_SLOTS; ++probe) {
    uint32_t index = (uint32_t)((hash + probe) % AP_NET_PEER_SLOTS);
    peer_state *candidate = &handle->peers[index];
    if (candidate->used != 0u && candidate->family == family &&
        candidate->port == port && memcmp(candidate->addr, addr, 16) == 0) {
      slot = candidate;
      break;
    }
    if (candidate->last_seen < oldest_time) {
      oldest_time = candidate->last_seen;
      oldest = index;
    }
  }
  ++handle->stats.peer_events;
  if (slot == nullptr) {
    if (handle->peer_count < AP_NET_PEER_SLOTS) {
      slot = &handle->peers[oldest];
      if (slot->used == 0u) ++handle->peer_count;
    } else {
      slot = &handle->peers[oldest];
      ++handle->stats.peer_evictions;
      ++handle->stats.peer_exhaustion;
    }
    memset(slot, 0, sizeof(*slot));
    slot->family = family;
    memcpy(slot->addr, addr, 16);
    slot->port = port;
    slot->used = 1u;
    slot->window_start = now;
    slot->events = 1u;
  } else {
    if (now < slot->window_start ||
        now - slot->window_start >= AP_NET_PEER_WINDOW_NS) {
      slot->window_start = now;
      slot->events = 1u;
    } else {
      ++slot->events;
    }
    if (slot->events >= AP_NET_PEER_BURST) {
      ++handle->stats.peer_bursts;
      slot->events = 0u;
      slot->window_start = now;
    }
  }
  slot->last_seen = now;
}

tcp_state *flow_slot(ap_net_handle *handle, const flow_key &original, bool create) {
  flow_key key = original;
  int order = memcmp(key.src, key.dst, sizeof(key.src));
  if (order > 0 || (order == 0 && key.sport > key.dport)) {
    swap_addr(key.src, key.dst);
    uint16_t temp_port = key.sport;
    key.sport = key.dport;
    key.dport = temp_port;
  }
  uint64_t hash = key_hash(key);
  uint32_t index;
  uint32_t probe;
  uint32_t oldest = 0;
  uint64_t oldest_time = ~0ull;

  for (probe = 0; probe < AP_NET_FLOW_SLOTS; ++probe) {
    index = (uint32_t)((hash + probe) % AP_NET_FLOW_SLOTS);
    tcp_state *slot = &handle->flows[index];
    if (slot->last_seen != 0u && key_equal(slot->key, key)) {
      return slot;
    }
    if (slot->last_seen < oldest_time) {
      oldest_time = slot->last_seen;
      oldest = index;
    }
    if (slot->last_seen == 0u && create) {
      memset(slot, 0, sizeof(*slot));
      slot->key = key;
      slot->phase = phase_closed;
      ++handle->flow_count;
      return slot;
    }
  }
  if (!create) {
    return nullptr;
  }
  tcp_state *slot = &handle->flows[oldest];
  if (slot->last_seen != 0u) {
    ++handle->stats.evictions;
  } else {
    ++handle->flow_count;
  }
  memset(slot, 0, sizeof(*slot));
  slot->key = key;
  slot->phase = phase_closed;
  return slot;
}

frag_state *frag_slot(ap_net_handle *handle, uint8_t family,
                      const uint8_t src[16], const uint8_t dst[16],
                      uint32_t id, uint8_t proto, bool create) {
  uint8_t seed_bytes[38];
  uint64_t seed = 1469598103934665603ull;
  uint32_t oldest = 0;
  uint64_t oldest_time = ~0ull;

  memset(seed_bytes, 0, sizeof(seed_bytes));
  seed_bytes[0] = family;
  memcpy(seed_bytes + 1, src, 16);
  memcpy(seed_bytes + 17, dst, 16);
  seed_bytes[33] = (uint8_t)(id >> 24);
  seed_bytes[34] = (uint8_t)(id >> 16);
  seed_bytes[35] = (uint8_t)(id >> 8);
  seed_bytes[36] = (uint8_t)id;
  seed_bytes[37] = proto;
  for (size_t i = 0; i < sizeof(seed_bytes); ++i) {
    seed = (seed ^ seed_bytes[i]) * 1099511628211ull;
  }

  for (uint32_t probe = 0; probe < AP_NET_FRAG_SLOTS; ++probe) {
    uint32_t index = (uint32_t)((seed + probe) % AP_NET_FRAG_SLOTS);
    frag_state *slot = &handle->frags[index];
    if (slot->used != 0u && slot->family == family && slot->id == id &&
        slot->proto == proto && memcmp(slot->src, src, 16) == 0 &&
        memcmp(slot->dst, dst, 16) == 0) {
      return slot;
    }
    if (slot->last_seen < oldest_time) {
      oldest_time = slot->last_seen;
      oldest = index;
    }
    if (slot->used == 0u && create) {
      memset(slot, 0, sizeof(*slot));
      slot->family = family;
      memcpy(slot->src, src, 16);
      memcpy(slot->dst, dst, 16);
      slot->id = id;
      slot->proto = proto;
      slot->used = 1;
      ++handle->frag_count;
      return slot;
    }
  }
  if (!create) {
    return nullptr;
  }
  frag_state *slot = &handle->frags[oldest];
  if (slot->used != 0u) {
    ++handle->stats.evictions;
  } else {
    ++handle->frag_count;
  }
  memset(slot, 0, sizeof(*slot));
  slot->family = family;
  memcpy(slot->src, src, 16);
  memcpy(slot->dst, dst, 16);
  slot->id = id;
  slot->proto = proto;
  slot->used = 1;
  return slot;
}

void check_tcp(ap_net_handle *handle, const ap_event *event, ap_verdict *verdict,
               const uint8_t *packet, size_t ip_header, size_t captured,
               uint8_t family, const uint8_t src[16], const uint8_t dst[16],
               uint16_t sport, uint16_t dport) {
  size_t offset = ip_header;
  uint32_t seq;
  uint32_t ack;
  uint8_t flags;
  uint32_t data_offset;
  flow_key key;
  tcp_state *state;
  size_t payload;
  uint64_t now;

  if (captured < offset + 20u) {
    set_verdict(verdict, event, AP_RULE_TCP_FLAGS, AP_SEV_MEDIUM, 780u,
                (uint64_t)captured, "tcp_header_truncated");
    ++handle->stats.findings;
    return;
  }
  now = event->ts_ns != 0u ? event->ts_ns : 1u;
  observe_peer(handle, family, src, sport, now);
  observe_peer(handle, family, dst, dport, now);
  data_offset = (uint32_t)(packet[offset + 12] >> 4) * 4u;
  flags = packet[offset + 13];
  seq = read_be32(packet + offset + 4);
  ack = read_be32(packet + offset + 8);
  if (data_offset < 20u || offset + data_offset > captured) {
    set_verdict(verdict, event, AP_RULE_TCP_FLAGS, AP_SEV_HIGH, 880u,
                (uint64_t)data_offset, "tcp_data_offset");
    ++handle->stats.findings;
    return;
  }
  payload = captured - offset - data_offset;
  if ((packet[offset + 12] & 0x0fu) != 0u) {
    set_verdict(verdict, event, AP_RULE_TCP_FLAGS, AP_SEV_MEDIUM, 700u,
                (uint64_t)packet[offset + 12], "tcp_reserved_bits");
    ++handle->stats.findings;
    return;
  }
  if ((flags & flag_syn) != 0u && (flags & flag_fin) != 0u) {
    set_verdict(verdict, event, AP_RULE_TCP_FLAGS, AP_SEV_HIGH, 940u,
                (uint64_t)flags, "syn_fin");
    ++handle->stats.findings;
    return;
  }
  if ((flags & flag_syn) != 0u && (flags & flag_rst) != 0u) {
    set_verdict(verdict, event, AP_RULE_TCP_FLAGS, AP_SEV_HIGH, 920u,
                (uint64_t)flags, "syn_rst");
    ++handle->stats.findings;
    return;
  }
  if ((flags & flag_fin) != 0u && (flags & flag_rst) != 0u) {
    set_verdict(verdict, event, AP_RULE_TCP_FLAGS, AP_SEV_MEDIUM, 800u,
                (uint64_t)flags, "fin_rst");
    ++handle->stats.findings;
    return;
  }
  if (flags == 0u) {
    set_verdict(verdict, event, AP_RULE_TCP_FLAGS, AP_SEV_MEDIUM, 720u,
                (uint64_t)seq, "tcp_null_flags");
    ++handle->stats.findings;
    return;
  }

  memset(&key, 0, sizeof(key));
  key.family = family;
  memcpy(key.src, src, 16);
  memcpy(key.dst, dst, 16);
  key.sport = sport;
  key.dport = dport;
  key.proto = 6;
  state = flow_slot(handle, key, true);
  if (state == nullptr) {
    return;
  }
  state->last_seen = event->ts_ns != 0u ? event->ts_ns : 1u;
  state->flags_seen |= flags;

  if (state->have_seq != 0u) {
    int32_t delta = (int32_t)(seq - state->last_seq);
    if (delta < -65536) {
      set_verdict(verdict, event, AP_RULE_TCP_STATE, AP_SEV_MEDIUM, 760u,
                  (uint64_t)(uint32_t)delta, "seq_regression");
      ++handle->stats.findings;
    }
  }
  if (state->have_seq != 0u && (flags & flag_ack) != 0u) {
    int32_t delta = (int32_t)(ack - state->last_ack);
    if (delta < -65536) {
      set_verdict(verdict, event, AP_RULE_TCP_STATE, AP_SEV_MEDIUM, 700u,
                  (uint64_t)(uint32_t)delta, "ack_regression");
      ++handle->stats.findings;
    }
  }
  state->last_seq = seq;
  state->last_ack = ack;
  state->have_seq = 1;

  if (payload > 0u && state->phase == phase_closed && (flags & flag_syn) == 0u) {
    set_verdict(verdict, event, AP_RULE_TCP_STATE, AP_SEV_MEDIUM, 680u,
                (uint64_t)payload, "data_before_handshake");
    ++handle->stats.findings;
    return;
  }
  if ((flags & flag_rst) != 0u) {
    state->phase = phase_reset;
    return;
  }
  switch (state->phase) {
    case phase_closed:
      if ((flags & flag_syn) != 0u && (flags & flag_ack) == 0u) {
        state->phase = phase_syn_sent;
      } else if ((flags & flag_ack) != 0u) {
        set_verdict(verdict, event, AP_RULE_TCP_STATE, AP_SEV_LOW, 560u,
                    (uint64_t)flags, "ack_without_handshake");
        ++handle->stats.findings;
      }
      break;
    case phase_syn_sent:
      if ((flags & flag_syn) != 0u && (flags & flag_ack) != 0u) {
        state->phase = phase_established;
      }
      break;
    case phase_established:
      if ((flags & flag_syn) != 0u) {
        set_verdict(verdict, event, AP_RULE_TCP_STATE, AP_SEV_MEDIUM, 740u,
                    (uint64_t)flags, "syn_in_established");
        ++handle->stats.findings;
      } else if ((flags & flag_fin) != 0u) {
        state->phase = phase_fin_wait;
      }
      break;
    case phase_fin_wait:
      if ((flags & flag_syn) != 0u) {
        set_verdict(verdict, event, AP_RULE_TCP_STATE, AP_SEV_HIGH, 840u,
                    (uint64_t)flags, "syn_after_fin");
        ++handle->stats.findings;
      } else if ((flags & flag_ack) != 0u) {
        state->phase = phase_closed;
      }
      break;
    case phase_reset:
      if ((flags & flag_syn) != 0u && (flags & flag_ack) == 0u) {
        state->phase = phase_syn_sent;
      }
      break;
    default:
      break;
  }
}

void fragment_bits(ap_net_handle *handle, const ap_event *event, ap_verdict *verdict,
                   uint8_t family, const uint8_t src[16], const uint8_t dst[16],
                   uint8_t proto, uint32_t id, uint32_t offset, bool more,
                   size_t payload_len) {
  frag_state *frag;
  bool overlap = false;
  size_t i;

  if (!more && offset == 0u) {
    return;
  }
  if (payload_len == 0u) {
    return;
  }
  if ((uint64_t)offset + (uint64_t)payload_len > 65535u) {
    set_verdict(verdict, event, AP_RULE_IP_MALFORMED, AP_SEV_HIGH, 860u,
                (uint64_t)offset, "fragment_range");
    ++handle->stats.findings;
    return;
  }
  frag = frag_slot(handle, family, src, dst, id, proto, true);
  if (frag == nullptr) {
    return;
  }
  frag->last_seen = event->ts_ns != 0u ? event->ts_ns : 1u;
  for (i = 0; i < payload_len; i += 8u) {
    uint32_t chunk = (offset + (uint32_t)i) / 8u;
    uint32_t byte = chunk / 8u;
    uint8_t mask = (uint8_t)(1u << (chunk % 8u));
    if (byte >= sizeof(frag->bits)) {
      set_verdict(verdict, event, AP_RULE_IP_MALFORMED, AP_SEV_MEDIUM, 700u,
                  (uint64_t)chunk, "fragment_range");
      ++handle->stats.findings;
      return;
    }
    if ((frag->bits[byte] & mask) != 0u) {
      overlap = true;
    }
    frag->bits[byte] |= mask;
  }
  if (overlap) {
    set_verdict(verdict, event, AP_RULE_FRAG_OVERLAP, AP_SEV_HIGH, 860u,
                (uint64_t)id, "fragment_overlap");
    ++handle->stats.findings;
  }
}

void check_ipv6(ap_net_handle *handle, const ap_event *event, ap_verdict *verdict,
                const uint8_t *bytes, size_t captured) {
  size_t payload = read_be16(bytes + 4);
  size_t total = 40u + payload;
  uint8_t next = bytes[6];
  size_t offset = 40u;
  uint8_t src[16];
  uint8_t dst[16];
  int hops = 0;

  memcpy(src, bytes + 8, 16);
  memcpy(dst, bytes + 24, 16);
  if (payload == 0u || total < 40u || total > captured) {
    set_verdict(verdict, event, AP_RULE_IP_MALFORMED, AP_SEV_HIGH, 900u,
                (uint64_t)((payload << 16) | (uint32_t)captured), "ipv6_length");
    ++handle->stats.findings;
    return;
  }

  while (hops < 8 && offset < total) {
    size_t ext = 0u;
    if (next == 6u || next == 17u) {
      break;
    }
    if (next == 59u) {
      return;
    }
    if (offset + 2u > total) {
      set_verdict(verdict, event, AP_RULE_IP_MALFORMED, AP_SEV_MEDIUM, 780u,
                  (uint64_t)next, "ipv6_extension_truncated");
      ++handle->stats.findings;
      return;
    }
    if (next == 44u) {
      uint8_t upper = bytes[offset];
      uint16_t field;
      uint32_t frag_offset;
      bool more;
      uint32_t id;

      if (offset + 8u > total) {
        set_verdict(verdict, event, AP_RULE_IP_MALFORMED, AP_SEV_MEDIUM, 780u,
                    (uint64_t)offset, "ipv6_fragment_truncated");
        ++handle->stats.findings;
        return;
      }
      field = read_be16(bytes + offset + 2u);
      frag_offset = (uint32_t)(field >> 3) * 8u;
      more = (field & 1u) != 0u;
      id = read_be32(bytes + offset + 4u);
      if (offset + 8u < total) {
        fragment_bits(handle, event, verdict, 6u, src, dst, upper, id,
                      frag_offset, more, total - offset - 8u);
      }
      if (frag_offset != 0u) {
        return;
      }
      next = upper;
      offset += 8u;
      ++hops;
      continue;
    }
    if (next == 0u || next == 43u || next == 60u) {
      ext = ((size_t)bytes[offset + 1u] + 1u) * 8u;
    } else if (next == 51u) {
      ext = ((size_t)bytes[offset + 1u] + 2u) * 4u;
    } else {
      return;
    }
    if (ext == 0u || offset + ext > total) {
      set_verdict(verdict, event, AP_RULE_IP_MALFORMED, AP_SEV_MEDIUM, 780u,
                  (uint64_t)next, "ipv6_extension_length");
      ++handle->stats.findings;
      return;
    }
    next = bytes[offset];
    offset += ext;
    ++hops;
  }
  if (hops >= 8) {
    set_verdict(verdict, event, AP_RULE_IP_MALFORMED, AP_SEV_MEDIUM, 740u,
                (uint64_t)next, "ipv6_extension_chain");
    ++handle->stats.findings;
    return;
  }
  if (next == 6u && offset + 20u <= total) {
    check_tcp(handle, event, verdict, bytes, offset, total, 6u, src, dst,
              read_be16(bytes + offset), read_be16(bytes + offset + 2u));
  } else if (next == 17u && offset + 8u <= total) {
    uint16_t udp_len = read_be16(bytes + offset + 4u);
    uint64_t now = event->ts_ns != 0u ? event->ts_ns : 1u;
    observe_peer(handle, 6u, src, read_be16(bytes + offset), now);
    observe_peer(handle, 6u, dst, read_be16(bytes + offset + 2u), now);
    if (udp_len < 8u || (size_t)udp_len > total - offset) {
      set_verdict(verdict, event, AP_RULE_IP_MALFORMED, AP_SEV_MEDIUM, 740u,
                  (uint64_t)udp_len, "udp_length");
      ++handle->stats.findings;
    }
  }
}

}  // namespace

int ap_net_feed(ap_net_handle *handle, const ap_event *event, ap_verdict *verdict) {
  uint8_t bytes[AP_MAX_PACKET_BYTES];
  size_t len;
  size_t ihl;
  size_t total;
  uint16_t checksum;
  uint32_t src;
  uint32_t dst;
  uint8_t proto;
  uint8_t v4_src[16];
  uint8_t v4_dst[16];

  if (handle == nullptr || event == nullptr || verdict == nullptr) {
    return AP_ERR_ARG;
  }
  ap_verdict_init(verdict, event->seq);
  if (event->kind != AP_KIND_NET || event->subkind != AP_NET_PACKET) {
    return AP_OK;
  }
  len = std::strlen(event->text);
  ++handle->stats.packets;
  if ((len & 1u) != 0u || len / 2u > sizeof(bytes) ||
      ap_hex_decode(event->text, len, bytes, sizeof(bytes)) != AP_OK) {
    ++handle->stats.invalid;
    return AP_OK;
  }
  if (len / 2u < 20u || (bytes[0] >> 4) == 0u ||
      (bytes[0] >> 4) > 6u || ((bytes[0] >> 4) != 4u && (bytes[0] >> 4) != 6u)) {
    set_verdict(verdict, event, AP_RULE_IP_MALFORMED, AP_SEV_MEDIUM, 760u,
                (uint64_t)bytes[0], "ip_version");
    ++handle->stats.findings;
    return AP_OK;
  }
  if ((bytes[0] >> 4) == 6u) {
    if (len / 2u < 40u) {
      set_verdict(verdict, event, AP_RULE_IP_MALFORMED, AP_SEV_HIGH, 900u,
                  (uint64_t)(len / 2u), "ipv6_truncated");
      ++handle->stats.findings;
      return AP_OK;
    }
    check_ipv6(handle, event, verdict, bytes, len / 2u);
    return AP_OK;
  }
  ihl = (size_t)(bytes[0] & 0x0fu) * 4u;
  total = read_be16(bytes + 2);
  if (ihl < 20u || ihl > len / 2u || total < ihl || total > len / 2u) {
    set_verdict(verdict, event, AP_RULE_IP_MALFORMED, AP_SEV_HIGH, 900u,
                (uint64_t)((total << 16) | ihl), "ip_length");
    ++handle->stats.findings;
    return AP_OK;
  }
  checksum = ip_checksum(bytes, ihl);
  if (checksum != 0u) {
    set_verdict(verdict, event, AP_RULE_IP_MALFORMED, AP_SEV_MEDIUM, 620u,
                (uint64_t)checksum, "ip_checksum");
    ++handle->stats.findings;
  }
  src = read_be32(bytes + 12);
  dst = read_be32(bytes + 16);
  proto = bytes[9];
  set_v4_addr(v4_src, src);
  set_v4_addr(v4_dst, dst);
  {
    uint16_t field = read_be16(bytes + 6);
    uint32_t frag_offset = (uint32_t)(field & 0x1fffu) * 8u;
    bool more = (field & 0x2000u) != 0u;
    fragment_bits(handle, event, verdict, 4u, v4_src, v4_dst, proto,
                  read_be16(bytes + 4), frag_offset, more, len / 2u - ihl);
  }

  if (proto == 6u && len / 2u >= ihl + 4u) {
    ap_verdict tcp_verdict;
    ap_verdict_init(&tcp_verdict, event->seq);
    check_tcp(handle, event, &tcp_verdict, bytes, ihl, len / 2u, 4u, v4_src,
              v4_dst, read_be16(bytes + ihl), read_be16(bytes + ihl + 2));
    if (tcp_verdict.rule != AP_RULE_NONE) {
      *verdict = tcp_verdict;
    }
  } else if (proto == 17u && len / 2u >= ihl + 8u &&
             (read_be16(bytes + 6) & 0x3fffu) == 0u) {
    uint16_t udp_len = read_be16(bytes + ihl + 4);
    uint64_t now = event->ts_ns != 0u ? event->ts_ns : 1u;
    observe_peer(handle, 4u, v4_src, read_be16(bytes + ihl), now);
    observe_peer(handle, 4u, v4_dst, read_be16(bytes + ihl + 2), now);
    if (udp_len < 8u || (size_t)udp_len > len / 2u - ihl) {
      set_verdict(verdict, event, AP_RULE_IP_MALFORMED, AP_SEV_MEDIUM, 740u,
                  (uint64_t)udp_len, "udp_length");
      ++handle->stats.findings;
    }
  }
  return AP_OK;
}
