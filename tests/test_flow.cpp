#include "apflow.h"
#include "apksensor.h"

#include <cstdio>
#include <cstring>

static int failures = 0;

static void check(bool condition, const char *name) {
  if (!condition) {
    std::fprintf(stderr, "fail: %s\n", name);
    ++failures;
  }
}

static ap_verdict feed(ap_flow_handle *handle, uint64_t seq, uint16_t kind,
                       uint32_t subkind, uint64_t ts, uint64_t a, uint64_t b,
                       uint64_t c, uint32_t confidence, const char *text) {
  ap_event event;
  ap_event_init(&event, kind);
  event.seq = seq;
  event.ts_ns = ts;
  event.pid = 42;
  event.subkind = subkind;
  event.confidence_x1000 = confidence;
  event.arg[0] = a;
  event.arg[1] = b;
  event.arg[2] = c;
  std::snprintf(event.text, sizeof(event.text), "%s", text);
  ap_verdict verdict;
  ap_flow_feed(handle, &event, &verdict);
  return verdict;
}

static ap_verdict feed_kernel(ap_flow_handle *handle, uint64_t seq, int64_t pid,
                              uint64_t ts, const char *label) {
  ap_event event;
  ap_event_init(&event, AP_KIND_KERNEL);
  event.seq = seq;
  event.ts_ns = ts;
  event.pid = pid;
  event.subkind = 1u;
  event.severity = AP_SEV_HIGH;
  event.confidence_x1000 = 780u;
  std::snprintf(event.text, sizeof(event.text), "%s", label);
  ap_verdict verdict;
  ap_flow_feed(handle, &event, &verdict);
  return verdict;
}

static ap_verdict feed_marked_kernel(ap_flow_handle *handle, uint64_t seq, int64_t pid,
                                     uint64_t ts, uint64_t mark, const char *label) {
  ap_event event;
  ap_event_init(&event, AP_KIND_KERNEL);
  event.seq = seq;
  event.ts_ns = ts;
  event.pid = pid;
  event.tid = pid;
  event.subkind = 1u;
  event.severity = AP_SEV_HIGH;
  event.confidence_x1000 = 780u;
  event.arg[3] = mark;
  std::snprintf(event.text, sizeof(event.text), "%s", label);
  ap_verdict verdict;
  ap_flow_feed(handle, &event, &verdict);
  return verdict;
}

static ap_verdict feed_ksensor(ap_flow_handle *handle, uint64_t seq, int64_t pid,
                               uint64_t ts, const char *label) {
  return feed_marked_kernel(handle, seq, pid, ts, AP_KSENSOR_SOURCE_MARK, label);
}

static ap_verdict feed_priv(ap_flow_handle *handle, uint64_t seq, uint64_t ts,
                            uint32_t subkind, uint32_t confidence, const char *text) {
  ap_event event;
  ap_event_init(&event, AP_KIND_PRIV);
  event.seq = seq;
  event.ts_ns = ts;
  event.pid = 42;
  event.subkind = subkind;
  event.severity = AP_SEV_HIGH;
  event.confidence_x1000 = confidence;
  std::snprintf(event.text, sizeof(event.text), "%s", text);
  ap_verdict verdict;
  ap_flow_feed(handle, &event, &verdict);
  return verdict;
}

static ap_verdict feed_pid_event(ap_flow_handle *handle, uint64_t seq, int64_t pid,
                                 uint16_t kind, uint32_t subkind, uint64_t ts,
                                 uint64_t a, uint64_t b, uint64_t c,
                                 uint32_t confidence, const char *text) {
  ap_event event;
  ap_event_init(&event, kind);
  event.seq = seq;
  event.ts_ns = ts;
  event.pid = pid;
  event.tid = pid;
  event.subkind = subkind;
  event.severity = AP_SEV_HIGH;
  event.confidence_x1000 = confidence;
  event.arg[0] = a;
  event.arg[1] = b;
  event.arg[2] = c;
  std::snprintf(event.text, sizeof(event.text), "%s", text);
  ap_verdict verdict;
  ap_flow_feed(handle, &event, &verdict);
  return verdict;
}

int main() {
  ap_flow_handle *handle = ap_flow_new();
  check(handle != nullptr, "handle allocation");

  ap_verdict clean = feed(handle, 1, AP_KIND_MEMREGION, 1, 100, 0x1000, 0x2000, 5, 1000, "/bin/app");
  check(clean.rule == AP_RULE_NONE, "clean executable region");

  ap_verdict wx = feed(handle, 2, AP_KIND_MEMPROT, 1, 200, 0x3000, 0x1000, 7, 950, "mprotect");
  check(wx.rule == AP_RULE_WX_TRANSITION, "wx transition");

  ap_verdict weak1 = feed(handle, 3, AP_KIND_FLOW, AP_FLOW_RETURN_SITE, 300, 0x5000, 0, 0, 250, "weak");
  check(weak1.rule == AP_RULE_NONE, "single weak indicator stays quiet");
  ap_verdict correlated = feed(handle, 4, AP_KIND_FLOW, AP_FLOW_RETURN_SITE, 400, 0x6000, 0, 0, 250, "weak");
  check(correlated.rule == AP_RULE_CORRELATED, "correlation after wx and weak sites");
  ap_verdict reset = feed(handle, 5, AP_KIND_FLOW, AP_FLOW_RETURN_SITE, 500, 0x7000, 0, 0, 250, "weak");
  check(reset.rule == AP_RULE_NONE, "correlation window resets");

  ap_verdict stack = feed(handle, 6, AP_KIND_MEMREGION, 1, 600, 0x8000, 0x9000, 7, 1000, "[stack]");
  check(stack.rule == AP_RULE_STACK_EXEC, "executable stack");

  ap_verdict strong = feed(handle, 7, AP_KIND_FLOW, AP_FLOW_RETURN_SITE, 700, 0xdead00, 0, 0, 900, "strong");
  check(strong.rule == AP_RULE_RETURN_OUTSIDE_EXEC, "strong return site");

  feed(handle, 8, AP_KIND_FLOW, AP_FLOW_SHADOW, 800, 0, 0xabc, 0, 900, "call");
  ap_verdict shadow = feed(handle, 9, AP_KIND_FLOW, AP_FLOW_SHADOW, 900, 0xabd, 0, 0, 900, "ret");
  check(shadow.rule == AP_RULE_SHADOW_MISMATCH, "shadow mismatch");

  ap_flow_handle *exec_handle = ap_flow_new();
  check(exec_handle != nullptr, "exec handle allocation");
  ap_verdict lone_exec = feed(exec_handle, 30, AP_KIND_EXEC, 1, 100, 0, 0, 0, 900, "/bin/app");
  check(lone_exec.rule == AP_RULE_NONE, "exec without wx stays quiet");
  (void)feed(exec_handle, 31, AP_KIND_MEMPROT, 1, 200, 0x3000, 0x1000, 7, 950, "mprotect");
  ap_verdict after_wx = feed(exec_handle, 32, AP_KIND_EXEC, 1, 300, 0, 0, 0, 900, "/bin/app");
  check(after_wx.rule == AP_RULE_EXEC_AFTER_WX, "exec after wx transition");
  ap_verdict exec_again = feed(exec_handle, 33, AP_KIND_EXEC, 1, 400, 0, 0, 0, 900, "/bin/app");
  check(exec_again.rule == AP_RULE_NONE, "exec after wx fires once");
  check(ap_flow_reset(exec_handle) == AP_OK, "exec reset one");
  (void)feed(exec_handle, 34, AP_KIND_MEMPROT, 1, 1000, 0x3000, 0x1000, 7, 950, "mprotect");
  ap_verdict stale_exec = feed(exec_handle, 35, AP_KIND_EXEC, 1, 6000001000ull, 0, 0, 0, 900, "/bin/app");
  check(stale_exec.rule == AP_RULE_NONE, "stale wx does not flag exec");
  check(ap_flow_reset(exec_handle) == AP_OK, "exec reset two");
  (void)feed(exec_handle, 36, AP_KIND_MEMREGION, 1, 100, 0x9000, 0xa000, 6, 1000, "/tmp/wx");
  ap_verdict after_region = feed(exec_handle, 37, AP_KIND_EXEC, 1, 200, 0, 0, 0, 900, "/bin/app");
  check(after_region.rule == AP_RULE_EXEC_AFTER_WX, "exec after wx mapping");
  ap_flow_free(exec_handle);

  ap_flow_handle *kernel_handle = ap_flow_new();
  check(kernel_handle != nullptr, "kernel handle allocation");
  check(feed_kernel(kernel_handle, 40, 42, 100, "module_load").rule == AP_RULE_NONE,
        "module alone stays quiet");
  check(feed_kernel(kernel_handle, 41, 42, 200, "mount").rule == AP_RULE_NONE,
        "two non-kexec labels stay quiet");
  check(feed_kernel(kernel_handle, 42, 42, 300, "namespace_change").rule == AP_RULE_KERNEL_CHAIN,
        "module with two kernel interfaces chains");
  check(feed_kernel(kernel_handle, 43, 42, 400, "namespace_change").rule == AP_RULE_NONE,
        "kernel chain fires once");
  check(feed_kernel(kernel_handle, 44, 43, 100, "module_load").rule == AP_RULE_NONE,
        "kernel chain is per pid");
  check(ap_flow_reset(kernel_handle) == AP_OK, "kernel reset one");
  (void)feed_kernel(kernel_handle, 45, 42, 1000, "module_load");
  (void)feed_kernel(kernel_handle, 46, 42, 1001, "mount");
  check(feed_kernel(kernel_handle, 47, 42, 6000001002ull, "namespace_change").rule == AP_RULE_NONE,
        "stale kernel window does not chain");
  check(ap_flow_reset(kernel_handle) == AP_OK, "kernel reset two");
  check(feed_kernel(kernel_handle, 48, 42, 100, "kexec").rule == AP_RULE_NONE,
        "kexec alone stays quiet");
  check(feed_kernel(kernel_handle, 49, 42, 200, "kernel_interface").rule == AP_RULE_KERNEL_CHAIN,
        "kexec chains with one interface");
  check(ap_flow_reset(kernel_handle) == AP_OK, "kernel reset three");
  check(feed_kernel(kernel_handle, 50, 42, 100, "bpf").rule == AP_RULE_NONE,
        "bpf alone stays quiet");
  ap_verdict bpf_ptrace = feed_kernel(kernel_handle, 51, 42, 200, "ptrace");
  check(bpf_ptrace.rule == AP_RULE_KERNEL_CHAIN, "bpf and ptrace chain");
  check(std::strstr(bpf_ptrace.text, "bpf+ptrace") != nullptr,
        "kernel chain explains labels");
  ap_flow_free(kernel_handle);

  ap_flow_handle *persist = ap_flow_new();
  check(persist != nullptr, "persistence handle allocation");
  check(feed_ksensor(persist, 200, 42, 1000, "cron_write").rule == AP_RULE_NONE,
        "single write label stays quiet");
  check(feed_ksensor(persist, 201, 42, 1100, "systemd_unit_write").rule == AP_RULE_NONE,
        "two write labels stay quiet");
  check(feed_ksensor(persist, 202, 42, 1200, "exec").rule == AP_RULE_NONE,
        "persistence exec stays quiet before network");
  ap_verdict persist_alert = feed_ksensor(persist, 203, 42, 1300, "connect");
  check(persist_alert.rule == AP_RULE_PERSISTENCE,
        "write+write+exec+connect forms persistence chain");
  check(std::strstr(persist_alert.text,
                    "persistence_chain:cron_write+systemd_unit_write+exec+connect") != nullptr,
        "persistence detail explains labels");
  check(persist_alert.confidence_x1000 == 860u, "persistence confidence is 860");
  check(feed_ksensor(persist, 204, 42, 1400, "connect").rule == AP_RULE_NONE,
        "persistence chain fires once");

  check(feed_ksensor(persist, 205, 43, 2000, "rc_write").rule == AP_RULE_NONE,
        "alternate write label stays quiet");
  check(feed_ksensor(persist, 206, 43, 2100, "ssh_key_write").rule == AP_RULE_NONE,
        "second alternate write label stays quiet");
  check(feed_ksensor(persist, 207, 43, 2200, "process_start").rule == AP_RULE_NONE,
        "process start stays quiet before network");
  ap_verdict persist_alt = feed_ksensor(persist, 208, 43, 2300, "net_packet");
  check(persist_alt.rule == AP_RULE_PERSISTENCE,
        "alternate write+start+packet forms persistence chain");
  check(std::strstr(persist_alt.text,
                    "persistence_chain:rc_write+ssh_key_write+process_start+net_packet") != nullptr,
        "alternate persistence detail explains labels");

  (void)feed_ksensor(persist, 209, 44, 10000, "cron_write");
  (void)feed_ksensor(persist, 210, 44, 10100, "rc_write");
  (void)feed_ksensor(persist, 211, 44, 10200, "exec");
  check(feed_ksensor(persist, 212, 44, 10000010200ull, "connect").rule == AP_RULE_NONE,
        "stale persistence window does not chain");
  (void)feed_ksensor(persist, 213, 45, 3000, "cron_write");
  (void)feed_ksensor(persist, 214, 45, 3100, "cron_write");
  (void)feed_ksensor(persist, 215, 45, 3200, "exec");
  check(feed_ksensor(persist, 216, 45, 3300, "connect").rule == AP_RULE_NONE,
        "repeated write label is not two distinct writes");
  ap_flow_free(persist);

  ap_flow_handle *escape = ap_flow_new();
  check(escape != nullptr, "container escape handle allocation");
  check(feed_ksensor(escape, 220, 50, 1000, "namespace_change").rule == AP_RULE_NONE,
        "namespace alone stays quiet");
  check(feed_ksensor(escape, 221, 50, 1100, "mount").rule == AP_RULE_NONE,
        "namespace and mount stay quiet without privilege");
  ap_verdict escape_alert = feed_ksensor(escape, 222, 50, 1200, "capset");
  check(escape_alert.rule == AP_RULE_CONTAINER_ESCAPE,
        "namespace+mount+capset forms container escape");
  check(std::strstr(escape_alert.text,
                    "container_escape:namespace_change+mount+capset") != nullptr,
        "container escape detail explains labels");
  check(escape_alert.confidence_x1000 == 880u, "container escape confidence is 880");
  check(feed_ksensor(escape, 223, 50, 1300, "capset").rule == AP_RULE_NONE,
        "container escape fires once");

  (void)feed_ksensor(escape, 224, 51, 1000, "namespace_change");
  (void)feed_ksensor(escape, 225, 51, 1100, "mount");
  ap_verdict cgroup_alert = feed_ksensor(escape, 226, 51, 1200, "cgroup_write");
  check(cgroup_alert.rule == AP_RULE_CONTAINER_ESCAPE,
        "cgroup write satisfies privileged stage");
  check(std::strstr(cgroup_alert.text,
                    "container_escape:namespace_change+mount+cgroup_write") != nullptr,
        "cgroup escape detail explains labels");

  (void)feed_ksensor(escape, 227, 52, 1000, "namespace_change");
  (void)feed_ksensor(escape, 228, 52, 1100, "mount");
  ap_verdict cred_alert = feed_ksensor(escape, 229, 52, 1200, "cred");
  check(cred_alert.rule == AP_RULE_CONTAINER_ESCAPE,
        "cred label satisfies privileged stage");
  check(std::strstr(cred_alert.text,
                    "container_escape:namespace_change+mount+cred") != nullptr,
        "cred escape detail explains labels");

  (void)feed_ksensor(escape, 230, 53, 1000, "namespace_change");
  (void)feed_ksensor(escape, 231, 53, 1100, "mount");
  ap_verdict uid_alert = feed_ksensor(escape, 232, 53, 1200, "exec_uid_change");
  check(uid_alert.rule == AP_RULE_CONTAINER_ESCAPE,
        "exec uid change satisfies privileged stage");
  check(std::strstr(uid_alert.text,
                    "container_escape:namespace_change+mount+exec_uid_change") != nullptr,
        "uid escape detail explains labels");

  check(feed_ksensor(escape, 233, 54, 1000, "mount").rule == AP_RULE_NONE,
        "mount alone stays quiet");
  check(feed_ksensor(escape, 234, 54, 1100, "capset").rule == AP_RULE_NONE,
        "privilege alone without namespace stays quiet");
  (void)feed_ksensor(escape, 235, 55, 1000, "namespace_change");
  check(feed_ksensor(escape, 236, 55, 1100, "capset").rule == AP_RULE_NONE,
        "namespace and privilege without mount stays quiet");
  ap_flow_free(escape);

  static const char *const generic_labels[] = {
      "kernel_rootkit", "credential_theft", "fileless_exec", "anti_analysis",
      "bpf_prog_load", "kernel_text_write", "ftrace_write", "kcore_open",
      "debugfs_write"};
  const size_t generic_count = sizeof(generic_labels) / sizeof(generic_labels[0]);
  for (size_t i = 0; i < generic_count; ++i) {
    ap_flow_handle *generic = ap_flow_new();
    check(generic != nullptr, "generic kernel handle allocation");
    check(feed_ksensor(generic, (uint64_t)(300 + i), 70 + (int64_t)i, 1000,
                       generic_labels[i]).rule == AP_RULE_NONE,
          "single generic kernel label stays quiet");
    const char *partner = std::strcmp(generic_labels[i], "debugfs_write") == 0
                              ? "kernel_rootkit"
                              : "debugfs_write";
    ap_verdict generic_chain = feed_ksensor(generic, (uint64_t)(400 + i),
                                            70 + (int64_t)i, 1100, partner);
    check(generic_chain.rule == AP_RULE_KERNEL_CHAIN,
          "generic kernel label joins kernel chain");
    check(std::strstr(generic_chain.text, "kernel_chain:") != nullptr &&
              std::strstr(generic_chain.text, generic_labels[i]) != nullptr &&
              std::strstr(generic_chain.text, partner) != nullptr,
          "generic kernel chain explains labels");
    ap_flow_free(generic);
  }

  ap_flow_handle *marked_chain = ap_flow_new();
  check(marked_chain != nullptr, "marked chain handle allocation");
  (void)feed_ksensor(marked_chain, 500, 80, 1000, "module_load");
  (void)feed_ksensor(marked_chain, 501, 80, 1100, "mount");
  check(feed_ksensor(marked_chain, 502, 80, 1200, "namespace_change").rule ==
            AP_RULE_KERNEL_CHAIN,
        "sensor labels keep existing kernel chain behavior");
  ap_flow_free(marked_chain);

  ap_flow_handle *replay = ap_flow_new();
  check(replay != nullptr, "replay mark handle allocation");
  (void)feed_marked_kernel(replay, 510, 90, 1000, 2u, "kernel_rootkit");
  check(feed_marked_kernel(replay, 511, 90, 1100, 2u, "credential_theft").rule ==
            AP_RULE_NONE,
        "replay mark ignores new generic kernel labels");
  (void)feed_marked_kernel(replay, 512, 91, 1000, 2u, "cron_write");
  (void)feed_marked_kernel(replay, 513, 91, 1100, 2u, "systemd_unit_write");
  (void)feed_marked_kernel(replay, 514, 91, 1200, 2u, "exec");
  check(feed_marked_kernel(replay, 515, 91, 1300, 2u, "connect").rule == AP_RULE_NONE,
        "replay mark ignores persistence labels");
  (void)feed_marked_kernel(replay, 516, 92, 1000, 2u, "namespace_change");
  (void)feed_marked_kernel(replay, 517, 92, 1100, 2u, "mount");
  check(feed_marked_kernel(replay, 518, 92, 1200, 2u, "capset").rule == AP_RULE_NONE,
        "replay mark ignores container escape labels");
  ap_flow_free(replay);

  ap_flow_handle *priv_handle = ap_flow_new();
  check(priv_handle != nullptr, "privilege handle allocation");
  check(feed_priv(priv_handle, 60, 100, 1u, 450u, "setid").rule == AP_RULE_NONE,
        "setid alone stays quiet in flow");
  ap_verdict cred_bpf = feed_kernel(priv_handle, 61, 42, 200, "bpf");
  check(cred_bpf.rule == AP_RULE_PRIV_CROSSING,
        "setid and bpf correlate as privilege crossing");
  check(std::strstr(cred_bpf.text, "bpf+setid") != nullptr,
        "bpf privilege crossing explains labels");
  ap_verdict cred_crossing = feed_kernel(priv_handle, 62, 42, 300, "ptrace");
  check(cred_crossing.rule == AP_RULE_KERNEL_CHAIN,
        "bpf and ptrace still chain after credential telemetry");
  check(ap_flow_reset(priv_handle) == AP_OK, "privilege reset one");
  check(feed_priv(priv_handle, 63, 400, 1u, 450u, "setid").rule == AP_RULE_NONE,
        "setid alone stays quiet after reset");
  ap_verdict priv_crossing = feed_kernel(priv_handle, 64, 42, 500, "ptrace");
  check(priv_crossing.rule == AP_RULE_PRIV_CROSSING,
        "setid and ptrace correlate as privilege crossing");
  check(std::strstr(priv_crossing.text, "ptrace+setid") != nullptr,
        "privilege crossing explains labels");
  check(ap_flow_reset(priv_handle) == AP_OK, "privilege reset two");
  (void)feed_priv(priv_handle, 65, 600, 1u, 450u, "setid");
  ap_verdict uid_crossing = feed_priv(priv_handle, 66, 700, 2u, 800u, "exec_uid_change");
  check(uid_crossing.rule == AP_RULE_PRIV_CROSSING,
        "setid and exec uid change correlate");
  check(std::strstr(uid_crossing.text, "setid+exec_uid_change") != nullptr,
        "uid crossing explains labels");
  ap_flow_free(priv_handle);

  ap_flow_handle *entity = ap_flow_new();
  check(entity != nullptr, "entity handle allocation");
  check(ap_flow_set_window_ms(entity, 1000) == AP_OK, "entity window accepts 1000 ms");
  check(ap_flow_set_window_ms(entity, 50) == AP_ERR_RANGE, "entity window rejects 50 ms");
  check(ap_flow_set_window_ms(entity, 60001) == AP_ERR_RANGE,
        "entity window rejects 60001 ms");
  check(feed_pid_event(entity, 70, 100, AP_KIND_MEMREGION, 2, 100,
                       0x1000, 0x2000, 6, 1000, "/srv/payload").rule == AP_RULE_WX_REGION,
        "entity wx stage starts with a mapping");
  check(feed_pid_event(entity, 71, 101, AP_KIND_EXEC, 1, 200,
                       0, 0, 0, 900, "/srv/payload").rule == AP_RULE_NONE,
        "entity exec stage links by binary");
  (void)feed_pid_event(entity, 72, 102, AP_KIND_EXEC, 1, 300,
                       0, 0, 0, 900, "/srv/payload");
  check(feed_pid_event(entity, 73, 102, AP_KIND_PRIV, 2, 400,
                       0, 1000, 0, 800, "init").rule == AP_RULE_NONE,
        "entity privilege stage waits for more stages");
  (void)feed_pid_event(entity, 74, 103, AP_KIND_EXEC, 1, 500,
                       0, 0, 0, 900, "/srv/payload");
  ap_verdict entity_chain = feed_pid_event(entity, 75, 103, AP_KIND_NET,
                                           AP_NET_CONNECT, 600, 0, 0, 0, 900,
                                           "peer:10.0.0.9:4444");
  check(entity_chain.rule == AP_RULE_CORRELATED, "four stages across entities correlate");
  check(std::strstr(entity_chain.text, "entity_chain:wx+exec+priv+net") != nullptr,
        "entity chain explains stages");
  check(std::strstr(entity_chain.text, "pid+binary+peer") != nullptr,
        "entity chain explains links");
  check(std::strstr(entity_chain.text, "10.0.0.9") != nullptr,
        "entity chain keeps the peer key");
  check(feed_pid_event(entity, 76, 103, AP_KIND_NET, AP_NET_CONNECT, 700,
                       0, 0, 0, 900, "peer:10.0.0.9:4444").rule == AP_RULE_NONE,
        "entity chain fires once");
  ap_flow_free(entity);

  ap_flow_handle *jit = ap_flow_new();
  check(jit != nullptr, "benign jit handle allocation");
  (void)feed_pid_event(jit, 80, 300, AP_KIND_MEMREGION, 2, 100,
                       0x4000, 0x5000, 6, 1000, "/opt/jit/code");
  ap_verdict jit_exec = feed_pid_event(jit, 81, 300, AP_KIND_EXEC, 1, 200,
                                       0, 0, 0, 900, "/opt/jit/code");
  check(jit_exec.rule != AP_RULE_CORRELATED, "benign jit wx and exec stay quiet");
  ap_flow_free(jit);

  ap_flow_handle *container = ap_flow_new();
  check(container != nullptr, "benign container handle allocation");
  (void)feed_pid_event(container, 82, 400, AP_KIND_EXEC, 1, 100,
                       0, 0, 0, 900, "/usr/bin/init");
  (void)feed_pid_event(container, 83, 400, AP_KIND_PRIV, 2, 200,
                       0, 1000, 0, 800, "init");
  ap_verdict container_net = feed_pid_event(container, 84, 400, AP_KIND_NET,
                                            AP_NET_CONNECT, 300, 0, 0, 0, 900,
                                            "peer:10.0.0.10:443");
  check(container_net.rule != AP_RULE_CORRELATED,
        "benign container exec, uid change and network stay quiet");
  ap_flow_free(container);

  ap_flow_handle *stale = ap_flow_new();
  check(stale != nullptr, "stale entity handle allocation");
  check(ap_flow_set_window_ms(stale, 100) == AP_OK, "entity window accepts 100 ms");
  (void)feed_pid_event(stale, 85, 500, AP_KIND_MEMREGION, 2, 1000000000ull,
                       0x1000, 0x2000, 6, 1000, "/srv/stale");
  (void)feed_pid_event(stale, 86, 500, AP_KIND_EXEC, 1, 1050000000ull,
                       0, 0, 0, 900, "/srv/stale");
  (void)feed_pid_event(stale, 87, 500, AP_KIND_PRIV, 2, 1100000000ull,
                       0, 1000, 0, 800, "init");
  ap_verdict stale_net = feed_pid_event(stale, 88, 500, AP_KIND_NET,
                                        AP_NET_CONNECT, 1400000000ull, 0, 0, 0, 900,
                                        "peer:10.0.0.11:4444");
  check(stale_net.rule == AP_RULE_NONE, "stale entity stages do not correlate");
  ap_flow_free(stale);

  ap_flow_handle *aged = ap_flow_new();
  check(aged != nullptr, "aged entity handle allocation");
  check(ap_flow_set_window_ms(aged, 1000) == AP_OK, "aged entity window accepts 1000 ms");
  (void)feed_pid_event(aged, 95, 700, AP_KIND_EXEC, 1, 1000000000ull,
                       0, 0, 0, 900, "/srv/old");
  (void)feed_pid_event(aged, 96, 700, AP_KIND_MEMPROT, 0, 3000000000ull,
                       0, 0, 6, 900, "");
  (void)feed_pid_event(aged, 97, 700, AP_KIND_EXEC, 1, 3000000001ull,
                       0, 0, 0, 900, "");
  (void)feed_pid_event(aged, 98, 700, AP_KIND_PRIV, 3, 3000000002ull,
                       0, 0, 0, 800, "setid");
  ap_verdict aged_net = feed_pid_event(aged, 99, 700, AP_KIND_NET,
                                       AP_NET_CONNECT, 3000000003ull, 0, 0, 0, 900,
                                       "peer:10.0.0.12:4444");
  check(aged_net.rule == AP_RULE_NONE,
        "expired binary reference does not link fresh stages");
  ap_flow_counters aged_counters;
  check(ap_flow_stats(aged, &aged_counters) == AP_OK &&
            aged_counters.entity_refs_expired >= 1u,
        "expired entity references are counted");
  ap_flow_free(aged);

  ap_flow_handle *packet = ap_flow_new();
  check(packet != nullptr, "packet peer handle allocation");
  (void)feed_pid_event(packet, 90, 600, AP_KIND_MEMREGION, 2, 100,
                       0x1000, 0x2000, 6, 1000, "/srv/packet");
  (void)feed_pid_event(packet, 91, 600, AP_KIND_EXEC, 1, 200,
                       0, 0, 0, 900, "/srv/packet");
  (void)feed_pid_event(packet, 92, 600, AP_KIND_PRIV, 2, 300,
                       0, 1000, 0, 800, "init");
  ap_verdict packet_chain = feed_pid_event(
      packet, 93, 600, AP_KIND_NET, AP_NET_PACKET, 400, 0, 0, 0, 900,
      "45000028000000004006f77cc0a80101c0a80102050a008000000000000000005003ffff00000000");
  check(packet_chain.rule == AP_RULE_CORRELATED, "packet peer feeds the entity graph");
  check(std::strstr(packet_chain.text, "v4:c0a80101:c0a80102:1290:128") != nullptr,
        "packet peer key is auditable");
  ap_flow_free(packet);

  ap_flow_handle *evade = ap_flow_new();
  check(evade != nullptr, "evasion handle allocation");
  (void)feed(evade, 20, AP_KIND_MEMPROT, 1, 1000, 0x3000, 0x1000, 7, 950, "mprotect");
  ap_verdict late1 = feed(evade, 21, AP_KIND_FLOW, AP_FLOW_RETURN_SITE,
                          6000001000ull, 0x5100, 0, 0, 250, "weak");
  ap_verdict late2 = feed(evade, 22, AP_KIND_FLOW, AP_FLOW_RETURN_SITE,
                          6000001001ull, 0x5200, 0, 0, 250, "weak");
  ap_verdict late3 = feed(evade, 23, AP_KIND_FLOW, AP_FLOW_RETURN_SITE,
                          6000001002ull, 0x5300, 0, 0, 250, "weak");
  check(late1.rule == AP_RULE_NONE && late2.rule == AP_RULE_NONE &&
        late3.rule == AP_RULE_NONE, "stale wx does not correlate");

  check(ap_flow_reset(evade) == AP_OK, "evasion reset one");
  (void)feed(evade, 24, AP_KIND_MEMPROT, 1, 1000, 0x3000, 0x1000, 7, 950, "mprotect");
  (void)feed(evade, 25, AP_KIND_FLOW, AP_FLOW_RETURN_SITE, 1001, 0x5400, 0, 0, 250, "weak");
  (void)feed(evade, 26, AP_KIND_FLOW, AP_FLOW_RETURN_SITE, 1002, 0x5500, 0, 0, 250, "weak");
  ap_verdict split = feed(evade, 27, AP_KIND_FLOW, AP_FLOW_RETURN_SITE,
                          2002001003ull, 0x5600, 0, 0, 250, "weak");
  check(split.rule == AP_RULE_NONE, "weak window gap resets correlation");

  check(ap_flow_reset(evade) == AP_OK, "evasion reset two");
  (void)feed(evade, 28, AP_KIND_MEMREGION, 1, 100, 0x9000, 0xa000, 5, 1000, "/bin/app");
  ap_verdict inside = feed(evade, 29, AP_KIND_FLOW, AP_FLOW_RETURN_SITE,
                           200, 0x9500, 0, 0, 900, "inside");
  check(inside.rule == AP_RULE_NONE, "strong return inside exec range stays quiet");

  check(ap_flow_reset(evade) == AP_OK, "evasion reset three");
  ap_verdict underflow = feed(evade, 30, AP_KIND_FLOW, AP_FLOW_SHADOW,
                              300, 0xabc, 0xabc, 0, 900, "ret_without_call");
  check(underflow.rule == AP_RULE_NONE, "shadow underflow stays quiet");
  ap_flow_free(evade);

  for (int i = 0; i < 64; ++i) {
    (void)feed(handle, (uint64_t)(100 + i), AP_KIND_MEMREGION, 1,
               (uint64_t)(1000 + i), (uint64_t)i, (uint64_t)(i + 1), 5, 1000, "/bin/app");
  }
  ap_flow_counters counters;
  check(ap_flow_stats(handle, &counters) == AP_OK && counters.events > 70, "stats");
  check(ap_flow_reset(handle) == AP_OK, "reset");

  ap_flow_free(handle);
  std::printf("flow tests: %s\n", failures == 0 ? "ok" : "failed");
  return failures == 0 ? 0 : 1;
}
