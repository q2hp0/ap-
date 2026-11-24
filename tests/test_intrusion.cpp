#include "apintrusion.h"

#include <cstdio>
#include <cstring>

static int failures = 0;
static const uint64_t stage_step = 1000000000ull;

static void check(bool condition, const char *name) {
  if (!condition) {
    std::fprintf(stderr, "fail: %s\n", name);
    ++failures;
  }
}

static ap_verdict feed(ap_intrusion *handle, uint64_t seq, uint16_t kind,
                       uint32_t subkind, uint64_t ts, uint64_t a, uint64_t b,
                       uint64_t c, const char *text) {
  ap_event event;
  ap_event_init(&event, kind);
  event.seq = seq;
  event.ts_ns = ts;
  event.pid = 42;
  event.tid = 42;
  event.subkind = subkind;
  event.severity = AP_SEV_HIGH;
  event.confidence_x1000 = 900u;
  event.arg[0] = a;
  event.arg[1] = b;
  event.arg[2] = c;
  if (kind == AP_KIND_KERNEL) {
    event.arg[3] = 3u;
  }
  std::snprintf(event.text, sizeof(event.text), "%s", text);
  ap_verdict verdict;
  check(ap_intrusion_feed(handle, &event, &verdict) == AP_OK, "feed ok");
  return verdict;
}

static void stats_growth(ap_intrusion *handle, ap_intrusion_counters_t *prior,
                         const char *name) {
  ap_intrusion_counters_t now;
  check(ap_intrusion_stats(handle, &now) == AP_OK, name);
  check(now.added >= prior->added && now.evicted >= prior->evicted &&
            now.findings >= prior->findings && now.suppressed >= prior->suppressed,
        name);
  check(now.added <= 10000u && now.evicted <= 10000u &&
            now.findings <= 10000u && now.suppressed <= 10000u,
        name);
  *prior = now;
}

static void test_injection(void) {
  ap_intrusion *handle = ap_intrusion_new();
  check(handle != nullptr, "injection handle");
  ap_intrusion_counters_t prior;
  std::memset(&prior, 0, sizeof(prior));
  uint64_t ts = stage_step;

  ap_verdict write = feed(handle, 1u, AP_KIND_KERNEL, 1u, ts, 0u, 0u, 0u, "ptrace");
  check(write.rule == AP_RULE_NONE, "remote write alone stays quiet");
  check(write.text[0] == '\0', "quiet verdict has no detail");
  stats_growth(handle, &prior, "injection write stats");

  ts += stage_step;
  ap_verdict alert = feed(handle, 2u, AP_KIND_MEMPROT, 1u, ts, 0u, 0u, 7u, "mprotect");
  check(alert.rule == AP_RULE_PROCESS_INJECTION, "remote write with wx reports injection");
  check(std::strstr(alert.text, "process_injection:") != nullptr,
        "injection detail has prefix");
  check(std::strstr(alert.text, "ptrace") != nullptr &&
            std::strstr(alert.text, "wx") != nullptr,
        "injection detail names stages");
  check(alert.severity == AP_SEV_CRITICAL && alert.confidence_x1000 == 870u,
        "injection confidence without redirect");
  check(alert.kind == AP_KIND_FLOW && alert.event_seq == 2u,
        "injection verdict is bound to the event");
  stats_growth(handle, &prior, "injection alert stats");

  ap_intrusion_counters_t before_duplicate;
  check(ap_intrusion_stats(handle, &before_duplicate) == AP_OK, "duplicate stats before");
  ts += stage_step;
  ap_verdict duplicate = feed(handle, 3u, AP_KIND_EXEC, 1u, ts, 0u, 0u, 0u, "/bin/app");
  check(duplicate.rule == AP_RULE_NONE, "duplicate chain emits nothing");
  stats_growth(handle, &prior, "injection duplicate stats");
  check(prior.suppressed == before_duplicate.suppressed + 1u &&
            prior.findings == before_duplicate.findings,
        "suppressed duplicate increments only suppressed");

  ap_intrusion_reset(handle);
  ap_intrusion_counters_t cleared;
  check(ap_intrusion_stats(handle, &cleared) == AP_OK &&
            cleared.added == 0u && cleared.evicted == 0u &&
            cleared.findings == 0u && cleared.suppressed == 0u,
        "reset clears stats");
  ap_intrusion_free(handle);
}

static void test_injection_redirect(void) {
  ap_intrusion *handle = ap_intrusion_new();
  check(handle != nullptr, "redirect handle");
  (void)feed(handle, 1u, AP_KIND_KERNEL, 1u, stage_step, 0u, 0u, 0u,
             "process_vm_writev");
  ap_verdict alert = feed(handle, 2u, AP_KIND_FLOW, AP_FLOW_RETURN_SITE,
                          stage_step * 2u, 0xdead00u, 0u, 0u, "strong");
  check(alert.rule == AP_RULE_PROCESS_INJECTION,
        "remote write with redirect reports injection");
  check(alert.confidence_x1000 == 890u, "injection confidence with redirect");
  ap_intrusion_free(handle);
}

static void test_exploit(void) {
  ap_intrusion *handle = ap_intrusion_new();
  check(handle != nullptr, "exploit handle");
  ap_intrusion_counters_t prior;
  std::memset(&prior, 0, sizeof(prior));

  ap_verdict wx = feed(handle, 1u, AP_KIND_MEMREGION, 2u, stage_step,
                       0x1000u, 0x2000u, 6u, "/tmp/wx");
  check(wx.rule == AP_RULE_NONE, "wx region alone stays quiet");
  stats_growth(handle, &prior, "exploit wx stats");
  ap_verdict redirect = feed(handle, 2u, AP_KIND_FLOW, AP_FLOW_STACK,
                             stage_step * 2u, 0x7000u, 0u, 0u, "stack");
  check(redirect.rule == AP_RULE_NONE, "wx with redirect stays quiet");
  stats_growth(handle, &prior, "exploit redirect stats");
  ap_verdict alert = feed(handle, 3u, AP_KIND_PRIV, 1u, stage_step * 3u,
                          0u, 0u, 0u, "setid");
  check(alert.rule == AP_RULE_EXPLOIT_CHAIN, "wx plus redirect plus priv reports exploit");
  check(std::strstr(alert.text, "exploit_chain:") != nullptr,
        "exploit detail has prefix");
  check(std::strstr(alert.text, "wx") != nullptr &&
            std::strstr(alert.text, "redirect") != nullptr &&
            std::strstr(alert.text, "priv") != nullptr,
        "exploit detail names stages");
  check(alert.severity == AP_SEV_CRITICAL && alert.confidence_x1000 == 920u,
        "exploit confidence with privilege");
  stats_growth(handle, &prior, "exploit alert stats");
  ap_intrusion_free(handle);
}

static void test_credential_dump(void) {
  ap_intrusion *handle = ap_intrusion_new();
  check(handle != nullptr, "credential handle");
  (void)feed(handle, 1u, AP_KIND_KERNEL, 1u, stage_step, 0u, 0u, 0u,
             "process_vm_readv");
  ap_verdict cred = feed(handle, 2u, AP_KIND_KERNEL, 1u, stage_step * 2u,
                         0u, 0u, 0u, "credential_theft");
  check(cred.rule == AP_RULE_NONE, "remote read with credential access stays quiet");
  ap_verdict alert = feed(handle, 3u, AP_KIND_PRIV, 1u, stage_step * 3u,
                          0u, 0u, 0u, "setid");
  check(alert.rule == AP_RULE_CREDENTIAL_DUMP,
        "remote read plus credential access plus priv reports dump");
  check(std::strstr(alert.text, "credential_dump:") != nullptr,
        "credential dump detail has prefix");
  check(std::strstr(alert.text, "process_vm_readv") != nullptr &&
            std::strstr(alert.text, "credential_theft") != nullptr &&
            std::strstr(alert.text, "priv") != nullptr,
        "credential dump detail names stages");
  check(alert.severity == AP_SEV_CRITICAL && alert.confidence_x1000 == 900u,
        "credential dump confidence");
  check(alert.evidence == 42u, "credential dump evidence falls back to pid");
  ap_intrusion_free(handle);
}

static void test_benign(void) {
  ap_intrusion *write = ap_intrusion_new();
  check(write != nullptr, "benign write handle");
  ap_verdict write_verdict = feed(write, 1u, AP_KIND_KERNEL, 1u, stage_step,
                                  0u, 0u, 0u, "ptrace");
  check(write_verdict.rule == AP_RULE_NONE, "single remote write is benign");
  ap_intrusion_free(write);

  ap_intrusion *wx = ap_intrusion_new();
  check(wx != nullptr, "benign wx handle");
  ap_verdict wx_verdict = feed(wx, 1u, AP_KIND_MEMPROT, 1u, stage_step,
                               0u, 0u, 7u, "mprotect");
  check(wx_verdict.rule == AP_RULE_NONE, "single wx is benign");
  ap_intrusion_free(wx);

  ap_intrusion *read = ap_intrusion_new();
  check(read != nullptr, "benign read handle");
  ap_verdict read_verdict = feed(read, 1u, AP_KIND_KERNEL, 1u, stage_step,
                                 0u, 0u, 0u, "process_vm_readv");
  check(read_verdict.rule == AP_RULE_NONE, "single remote read is benign");
  ap_intrusion_free(read);
}

int main() {
  test_injection();
  test_injection_redirect();
  test_exploit();
  test_credential_dump();
  test_benign();
  std::printf("intrusion tests: %s\n", failures == 0 ? "ok" : "failed");
  return failures == 0 ? 0 : 1;
}
