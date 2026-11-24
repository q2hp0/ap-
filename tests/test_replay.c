#define _GNU_SOURCE
#include "apabi.h"
#include "apreplay.h"
#include "apsys.h"
#include "aptransport.h"

#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures = 0;

static void check(bool condition, const char *name) {
  if (!condition) {
    fprintf(stderr, "replay test fail: %s\n", name);
    ++failures;
  }
}

static int wait_input(int fd) {
  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = POLLIN;
  pfd.revents = 0;
  return poll(&pfd, 1, 2000);
}

static ap_event make_event(uint64_t seq) {
  ap_event event;
  ap_event_init(&event, AP_KIND_HEARTBEAT);
  event.seq = seq;
  event.pid = 55;
  event.tid = 55;
  event.ts_ns = 1000u + seq;
  snprintf(event.text, sizeof(event.text), "%s", "replay_probe");
  return event;
}

static void test_ring(void) {
  uint8_t key[AP_TRANSPORT_KEY_LEN];
  ap_replay filter;
  ap_packet packet;
  ap_event event;
  uint64_t index;

  memset(key, 0x5a, sizeof(key));
  ap_replay_init(&filter);
  check(filter.count == 0u && filter.next == 0u, "fresh filter state");

  event = make_event(1u);
  check(ap_transport_seal(key, &event, &packet) == AP_OK, "seal initial event");
  check(ap_replay_accept(&filter, &packet) == AP_OK, "initial event accepted");
  check(ap_replay_accept(&filter, &packet) == AP_ERR_REPLAY, "identical packet rejected");
  check(filter.duplicates == 1u && filter.accepted == 1u, "duplicate counters");

  event = make_event(2u);
  check(ap_transport_seal(key, &event, &packet) == AP_OK, "seal new event");
  check(ap_replay_accept(&filter, &packet) == AP_OK, "new event accepted");

  for (index = 3u; index <= AP_REPLAY_SLOTS + 1u; ++index) {
    event = make_event(index);
    check(ap_transport_seal(key, &event, &packet) == AP_OK, "seal ring event");
    check(ap_replay_accept(&filter, &packet) == AP_OK, "ring event accepted");
  }
  check(filter.count == AP_REPLAY_SLOTS, "ring is bounded");

  event = make_event(1u);
  check(ap_transport_seal(key, &event, &packet) == AP_OK, "seal evicted event");
  check(ap_replay_accept(&filter, &packet) == AP_OK, "oldest tag is evicted");
  event = make_event(3u);
  check(ap_transport_seal(key, &event, &packet) == AP_OK, "seal retained event");
  check(ap_replay_accept(&filter, &packet) == AP_ERR_REPLAY, "retained tag rejected");
}

static void test_sequence(void) {
  uint8_t key[AP_TRANSPORT_KEY_LEN];
  ap_replay filter;
  ap_packet packet;
  ap_event event;
  uint32_t pid;
  uint32_t self_pid = (uint32_t)getpid();
  uint64_t epoch = 0u;

  memset(key, 0x63, sizeof(key));
  ap_replay_init(&filter);

  check(ap_sys_proc_starttime((pid_t)self_pid, &epoch) == AP_OK && epoch != 0u,
        "self starttime");
  event = make_event(10u);
  check(ap_transport_seal(key, &event, &packet) == AP_OK, "seal sequenced event");
  check(ap_replay_accept_sequence(&filter, &packet, 10u, self_pid) == AP_OK,
        "first sequence accepted");
  check(filter.sequences == 1u && filter.accepted == 1u, "sequence counters");
  check(filter.peer_epoch[0] == epoch, "peer epoch stored");
  check(ap_replay_accept_sequence(&filter, &packet, 10u, self_pid) == AP_ERR_REPLAY,
        "identical sequenced packet is a duplicate");
  check(filter.duplicates == 1u && filter.sequence_drops == 0u,
        "duplicate and sequence counters stay separate");

  event = make_event(5u);
  snprintf(event.text, sizeof(event.text), "%s", "stale");
  check(ap_transport_seal(key, &event, &packet) == AP_OK, "seal stale event");
  check(ap_replay_accept_sequence(&filter, &packet, 5u, self_pid) == AP_ERR_SEQUENCE,
        "stale sequence rejected");
  check(filter.sequence_drops == 1u && filter.accepted == 1u, "stale drop counted");
  check(filter.peer_seq[0] == 10u, "stale sequence does not advance peer");

  filter.peer_epoch[0] = epoch + 1u;
  event = make_event(4u);
  snprintf(event.text, sizeof(event.text), "%s", "reuse");
  check(ap_transport_seal(key, &event, &packet) == AP_OK, "seal reused pid event");
  check(ap_replay_accept_sequence(&filter, &packet, 4u, self_pid) == AP_OK,
        "changed epoch resets peer sequence");
  check(filter.peer_epoch[0] == epoch && filter.peer_seq[0] == 4u, "peer epoch and sequence reset");
  check(filter.sequence_drops == 1u, "reset is not a stale drop");

  event = make_event(0u);
  snprintf(event.text, sizeof(event.text), "%s", "unsequenced");
  check(ap_transport_seal(key, &event, &packet) == AP_OK, "seal unsequenced event");
  check(ap_replay_accept_sequence(&filter, &packet, 0u, self_pid) == AP_OK,
        "zero sequence is unsequenced");
  check(filter.sequences == 2u, "zero sequence is not counted");

  event = make_event(11u);
  check(ap_transport_seal(key, &event, &packet) == AP_OK, "seal next event");
  check(ap_replay_accept_sequence(&filter, &packet, 11u, self_pid) == AP_OK,
        "higher sequence accepted");

  event = make_event(1u);
  snprintf(event.text, sizeof(event.text), "%s", "peer_101");
  check(ap_transport_seal(key, &event, &packet) == AP_OK, "seal second peer event");
  check(ap_replay_accept_sequence(&filter, &packet, 1u, 101u) == AP_OK,
        "new peer sequence accepted");

  for (pid = 102u; pid < AP_SEQUENCE_SLOTS + 100u; ++pid) {
    event = make_event(1u);
    snprintf(event.text, sizeof(event.text), "peer_%u", pid);
    check(ap_transport_seal(key, &event, &packet) == AP_OK, "seal peer table event");
    check(ap_replay_accept_sequence(&filter, &packet, 1u, pid) == AP_OK,
          "peer table event accepted");
  }
  check(filter.peer_count == AP_SEQUENCE_SLOTS, "peer table is bounded");
  check(filter.peer_evictions == 0u, "no eviction before full table");

  event = make_event(1u);
  snprintf(event.text, sizeof(event.text), "%s", "peer_200");
  check(ap_transport_seal(key, &event, &packet) == AP_OK, "seal eviction event");
  check(ap_replay_accept_sequence(&filter, &packet, 1u, 200u) == AP_OK,
        "peer table evicts oldest slot");
  check(filter.peer_evictions == 1u, "peer eviction counted");
}

static void test_filtered_receive(const char *dir) {
  char path[256];
  char keypath[256];
  uint8_t key[AP_TRANSPORT_KEY_LEN];
  ap_replay filter;
  ap_event event;
  ap_event out;
  ap_packet packet;
  size_t received = 0u;
  int sfd = -1;
  int cfd = -1;

  snprintf(path, sizeof(path), "%s/replay.sock", dir);
  check(ap_sys_server_open(path, &sfd) == AP_OK, "server open");
  check(ap_sys_client_open(path, &cfd) == AP_OK, "client open");
  check(ap_transport_key_create(path, key) == AP_OK, "key create");
  check(ap_transport_key_path(path, keypath, sizeof(keypath)) == AP_OK, "key path");
  if (sfd < 0 || cfd < 0) {
    if (sfd >= 0) close(sfd);
    if (cfd >= 0) close(cfd);
    unlink(path);
    unlink(keypath);
    return;
  }

  ap_replay_init(&filter);
  event = make_event(9u);
  check(ap_sys_send_sealed(cfd, key, &event) == AP_OK, "send valid event");
  check(wait_input(sfd) == 1, "valid event ready");
  check(ap_sys_recv_sealed_filtered(sfd, key, &out, sizeof(out), &received, &filter) == AP_OK,
        "valid event accepted");
  check(received == sizeof(ap_event) && out.seq == 9u, "valid event contents");

  check(ap_transport_seal(key, &event, &packet) == AP_OK, "seal replay packet");
  check(ap_sys_write_all(cfd, packet.data, sizeof(packet.data)) == AP_OK, "send replay packet");
  check(wait_input(sfd) == 1, "replay packet ready");
  check(ap_sys_recv_sealed_filtered(sfd, key, &out, sizeof(out), &received, &filter) == AP_ERR_REPLAY,
        "replay packet rejected");
  check(filter.duplicates == 1u, "filtered duplicate counted");

  event = make_event(10u);
  check(ap_sys_send_sealed(cfd, key, &event) == AP_OK, "send next event");
  check(wait_input(sfd) == 1, "next event ready");
  check(ap_sys_recv_sealed_filtered(sfd, key, &out, sizeof(out), &received, &filter) == AP_OK,
        "next event accepted");
  check(out.seq == 10u, "next event contents");

  close(cfd);
  close(sfd);
  unlink(path);
  unlink(keypath);
}

static void test_sequenced_receive(const char *dir) {
  char path[256];
  char keypath[256];
  uint8_t key[AP_TRANSPORT_KEY_LEN];
  ap_replay filter;
  ap_event event;
  ap_event out;
  size_t received = 0u;
  int sfd = -1;
  int cfd = -1;

  snprintf(path, sizeof(path), "%s/seq.sock", dir);
  check(ap_sys_server_open(path, &sfd) == AP_OK, "sequence server open");
  check(ap_sys_client_open(path, &cfd) == AP_OK, "sequence client open");
  check(ap_transport_key_create(path, key) == AP_OK, "sequence key create");
  check(ap_transport_key_path(path, keypath, sizeof(keypath)) == AP_OK, "sequence key path");
  if (sfd < 0 || cfd < 0) {
    if (sfd >= 0) close(sfd);
    if (cfd >= 0) close(cfd);
    unlink(path);
    unlink(keypath);
    return;
  }

  ap_replay_init(&filter);
  event = make_event(41u);
  check(ap_sys_send_sealed(cfd, key, &event) == AP_OK, "send sequenced event");
  check(wait_input(sfd) == 1, "sequenced event ready");
  check(ap_sys_recv_sealed_sequenced(sfd, key, &out, sizeof(out), &received, &filter) == AP_OK,
        "sequenced event accepted");
  check(received == sizeof(ap_event) && out.seq == 41u, "sequenced event contents");

  event = make_event(40u);
  snprintf(event.text, sizeof(event.text), "%s", "stale_socket");
  check(ap_sys_send_sealed(cfd, key, &event) == AP_OK, "send stale event");
  check(wait_input(sfd) == 1, "stale event ready");
  check(ap_sys_recv_sealed_sequenced(sfd, key, &out, sizeof(out), &received, &filter) ==
            AP_ERR_SEQUENCE,
        "stale socket event rejected");
  check(filter.sequence_drops == 1u, "socket sequence drop counted");

  event = make_event(42u);
  snprintf(event.text, sizeof(event.text), "%s", "next_socket");
  check(ap_sys_send_sealed(cfd, key, &event) == AP_OK, "send next sequenced event");
  check(wait_input(sfd) == 1, "next sequenced event ready");
  check(ap_sys_recv_sealed_sequenced(sfd, key, &out, sizeof(out), &received, &filter) == AP_OK,
        "next sequenced event accepted");
  check(out.seq == 42u, "next sequenced event contents");

  close(cfd);
  close(sfd);
  unlink(path);
  unlink(keypath);
}

int main(void) {
  char dir[] = "/tmp/ap-replay-test-XXXXXX";
  if (mkdtemp(dir) == NULL) {
    fprintf(stderr, "replay test: cannot create temp dir\n");
    return 1;
  }
  test_ring();
  test_sequence();
  test_filtered_receive(dir);
  test_sequenced_receive(dir);
  rmdir(dir);
  printf("replay tests: %s\n", failures == 0 ? "ok" : "failed");
  return failures == 0 ? 0 : 1;
}
