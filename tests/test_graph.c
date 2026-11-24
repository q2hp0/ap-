#include "apgraph.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;
static int findings = 0;
static ap_graph_finding last;

static void check(int condition, const char *name) {
  if (!condition) {
    fprintf(stderr, "graph test fail: %s\n", name);
    ++failures;
  }
}

static int on_finding(const ap_graph_finding *finding, void *user) {
  int *count = (int *)user;
  if (finding == NULL || count == NULL) return AP_ERR_ARG;
  last = *finding;
  (*count)++;
  return AP_OK;
}

static void add_observation(ap_graph *graph, uint64_t ts, uint32_t tactic,
                            const char *key, uint32_t confidence) {
  ap_graph_observation observation;
  memset(&observation, 0, sizeof(observation));
  observation.ts_ns = ts;
  observation.pid = 4242;
  observation.tactic = tactic;
  observation.label_id = tactic;
  observation.confidence_x1000 = confidence;
  snprintf(observation.key, sizeof(observation.key), "%s", key);
  check(ap_graph_add(graph, &observation) == AP_OK, "add observation");
}

int main(void) {
  ap_graph graph;
  uint64_t added = 0u;
  uint64_t evicted = 0u;
  uint64_t found = 0u;
  uint64_t suppressed = 0u;
  uint32_t i;

  ap_graph_init(&graph);
  ap_graph_stats(&graph, &added, &evicted, &found, &suppressed);
  check(added == 0u && evicted == 0u && found == 0u && suppressed == 0u,
        "initial stats");

  add_observation(&graph, 1000u, AP_GRAPH_TACTIC_EXECUTION, "host-alpha", 700u);
  add_observation(&graph, 2000u, AP_GRAPH_TACTIC_CREDENTIAL_ACCESS, "host-alpha", 700u);
  add_observation(&graph, 3000u, AP_GRAPH_TACTIC_PRIVILEGE_ESCALATION, "host-alpha", 700u);
  check(ap_graph_evaluate(&graph, 4000u, on_finding, &findings) == AP_OK,
        "evaluate graph");
  check(findings == 1, "one finding");
  check(last.nodes == 3u, "three linked nodes");
  check(last.confidence_x1000 == 2100u, "confidence sum");
  check(strcmp(last.key, "host-alpha") == 0, "finding key");
  check(last.pid == 4242, "finding pid");

  check(ap_graph_evaluate(&graph, 4001u, on_finding, &findings) == AP_OK,
        "evaluate suppressed graph");
  check(findings == 1, "suppressed repeat");
  ap_graph_stats(&graph, NULL, NULL, &found, &suppressed);
  check(found == 1u && suppressed == 1u, "finding and suppression counters");

  check(ap_graph_evaluate(&graph, AP_GRAPH_SUPPRESS_NS + 5000u, on_finding,
                          &findings) == AP_OK, "evaluate after suppression");
  check(findings == 2, "finding after suppression window");

  check(ap_graph_add(NULL, NULL) == AP_ERR_ARG, "null add arguments");
  check(ap_graph_evaluate(&graph, 0u, on_finding, &findings) == AP_ERR_ARG,
        "zero evaluate time");
  check(ap_graph_evaluate(&graph, 1000u, NULL, &findings) == AP_ERR_ARG,
        "null callback");
  {
    ap_graph_observation bad;
    memset(&bad, 0, sizeof(bad));
    bad.ts_ns = 1u;
    bad.tactic = AP_GRAPH_TACTIC_MAX + 1u;
    check(ap_graph_add(&graph, &bad) == AP_ERR_ARG, "invalid tactic");
  }

  for (i = 0u; i < AP_GRAPH_MAX_NODES + 8u; ++i) {
    char key[32];
    snprintf(key, sizeof(key), "evict-%u", i);
    add_observation(&graph, 100000u + (uint64_t)i, AP_GRAPH_TACTIC_DISCOVERY,
                    key, 100u);
  }
  ap_graph_stats(&graph, &added, &evicted, NULL, NULL);
  check(added == 139u, "added count");
  check(evicted >= 8u, "bounded eviction");

  check(strcmp(ap_graph_tactic_name(AP_GRAPH_TACTIC_IMPACT), "impact") == 0,
        "tactic name");
  check(strcmp(ap_graph_tactic_name(999u), "unknown") == 0, "unknown tactic");

  printf("graph tests: %s\n", failures == 0 ? "ok" : "failed");
  return failures == 0 ? 0 : 1;
}
