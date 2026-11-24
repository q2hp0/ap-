#include "apgraph.h"

#include <stdio.h>
#include <string.h>

static const char *const ap_graph_tactics[AP_GRAPH_TACTIC_MAX + 1u] = {
  "none",
  "initial_access",
  "execution",
  "persistence",
  "privilege_escalation",
  "defense_evasion",
  "credential_access",
  "discovery",
  "lateral_movement",
  "collection",
  "command_and_control",
  "exfiltration",
  "impact"
};

static uint32_t ap_graph_bit(uint32_t tactic) {
  if (tactic == 0u || tactic > AP_GRAPH_TACTIC_MAX) return 0u;
  return 1u << tactic;
}

static uint32_t ap_graph_confidence(uint32_t value) {
  return value > 1000000u ? 1000000u : value;
}

static void ap_graph_copy_key(char out[AP_GRAPH_KEY_LEN], const char *key,
                              int64_t pid) {
  if (key != NULL && key[0] != '\0') {
    size_t i;
    for (i = 0u; i + 1u < AP_GRAPH_KEY_LEN && key[i] != '\0'; ++i) {
      out[i] = key[i];
    }
    out[i] = '\0';
    return;
  }
  if (pid == 0) {
    snprintf(out, AP_GRAPH_KEY_LEN, "pid-%lld", (long long)0);
    return;
  }
  snprintf(out, AP_GRAPH_KEY_LEN, "pid-%lld", (long long)pid);
}

static int ap_graph_link(ap_graph *graph, uint32_t next) {
  uint64_t now = graph->nodes[next].ts_ns;
  uint32_t i;

  for (i = 0u; i < AP_GRAPH_MAX_NODES; ++i) {
    uint32_t j;
    int linked = 0;

    if (i == next || graph->nodes[i].used == 0u) continue;
    if (now < graph->nodes[i].ts_ns) continue;
    if (now - graph->nodes[i].ts_ns > AP_GRAPH_WINDOW_NS) continue;
    if (strcmp(graph->nodes[i].key, graph->nodes[next].key) != 0 &&
        !(graph->nodes[i].pid != 0 && graph->nodes[i].pid == graph->nodes[next].pid)) {
      continue;
    }
    for (j = 0u; j < AP_GRAPH_MAX_EDGES; ++j) {
      if (graph->edges[j].used != 0u && graph->edges[j].from == i &&
          graph->edges[j].to == next) {
        linked = 1;
        break;
      }
    }
    if (linked != 0) continue;
    {
      uint32_t at = (uint32_t)(graph->edge_cursor % AP_GRAPH_MAX_EDGES);
      graph->edges[at].from = i;
      graph->edges[at].to = next;
      graph->edges[at].used = 1u;
      graph->edge_cursor++;
    }
  }
  return AP_OK;
}

void ap_graph_init(ap_graph *graph) {
  if (graph == NULL) return;
  memset(graph, 0, sizeof(*graph));
}

int ap_graph_add(ap_graph *graph, const ap_graph_observation *observation) {
  uint32_t at;

  if (graph == NULL || observation == NULL) return AP_ERR_ARG;
  if (observation->ts_ns == 0u) return AP_ERR_ARG;
  if (ap_graph_bit(observation->tactic) == 0u) return AP_ERR_ARG;

  at = (uint32_t)(graph->node_cursor % AP_GRAPH_MAX_NODES);
  if (graph->nodes[at].used != 0u) graph->evicted++;
  graph->nodes[at].ts_ns = observation->ts_ns;
  graph->nodes[at].pid = observation->pid;
  graph->nodes[at].tactic = observation->tactic;
  graph->nodes[at].label_id = observation->label_id;
  graph->nodes[at].confidence_x1000 = ap_graph_confidence(observation->confidence_x1000);
  graph->nodes[at].used = 1u;
  ap_graph_copy_key(graph->nodes[at].key, observation->key, observation->pid);
  graph->node_cursor++;
  graph->added++;
  return ap_graph_link(graph, at);
}

int ap_graph_evaluate(ap_graph *graph, uint64_t now_ns, ap_graph_cb callback,
                      void *user) {
  ap_graph_finding finding;
  uint32_t high = (1u << 3) | (1u << 4) | (1u << 6) | (1u << 10) |
                  (1u << 11) | (1u << 12);
  uint32_t i;

  if (graph == NULL || callback == NULL) return AP_ERR_ARG;
  if (now_ns == 0u) return AP_ERR_ARG;

  memset(&finding, 0, sizeof(finding));
  for (i = 0u; i < AP_GRAPH_MAX_NODES; ++i) {
    uint32_t tactics = 0u;
    uint32_t confidence = 0u;
    uint32_t nodes = 0u;
    uint64_t newest = 0u;
    int64_t pid = 0;
    uint32_t j;
    uint32_t chain = 0u;
    int suppressed = 0;

    if (graph->nodes[i].used == 0u) continue;
    if (graph->nodes[i].key[0] == '\0') continue;
    if (now_ns < graph->nodes[i].ts_ns) continue;
    if (now_ns - graph->nodes[i].ts_ns > AP_GRAPH_WINDOW_NS) continue;
    {
      uint32_t newer = 0u;
      for (j = 0u; j < AP_GRAPH_MAX_NODES; ++j) {
        if (j == i || graph->nodes[j].used == 0u) continue;
        if (strcmp(graph->nodes[i].key, graph->nodes[j].key) != 0) continue;
        if (graph->nodes[j].ts_ns > graph->nodes[i].ts_ns) {
          newer = 1u;
          break;
        }
      }
      if (newer != 0u) continue;
    }

    for (j = 0u; j < AP_GRAPH_MAX_CHAINS; ++j) {
      if (graph->chains[j].used == 0u) continue;
      if (strcmp(graph->chains[j].key, graph->nodes[i].key) != 0) continue;
      if (graph->chains[j].last_ns <= now_ns &&
          now_ns - graph->chains[j].last_ns < AP_GRAPH_SUPPRESS_NS) {
        suppressed = 1;
      }
      chain = j + 1u;
      break;
    }
    if (suppressed != 0) {
      graph->suppressed++;
      continue;
    }

    for (j = 0u; j < AP_GRAPH_MAX_NODES; ++j) {
      if (graph->nodes[j].used == 0u) continue;
      if (strcmp(graph->nodes[i].key, graph->nodes[j].key) != 0) continue;
      if (now_ns < graph->nodes[j].ts_ns) continue;
      if (now_ns - graph->nodes[j].ts_ns > AP_GRAPH_WINDOW_NS) continue;
      tactics |= ap_graph_bit(graph->nodes[j].tactic);
      confidence += graph->nodes[j].confidence_x1000;
      nodes++;
      if (graph->nodes[j].ts_ns >= newest) {
        newest = graph->nodes[j].ts_ns;
        pid = graph->nodes[j].pid;
      }
    }

    if (nodes < 3u) continue;
    {
      uint32_t count = 0u;
      uint32_t bit;
      for (bit = 1u; bit <= AP_GRAPH_TACTIC_MAX; ++bit) {
        if ((tactics & (1u << bit)) != 0u) count++;
      }
      if (count < 3u) continue;
    }
    if ((tactics & high) == 0u) continue;
    if (confidence < 1800u) continue;

    finding.ts_ns = newest;
    finding.pid = pid;
    finding.tactics = tactics;
    finding.confidence_x1000 = ap_graph_confidence(confidence);
    finding.nodes = nodes;
    snprintf(finding.key, AP_GRAPH_KEY_LEN, "%s", graph->nodes[i].key);
    if (callback(&finding, user) == AP_OK) graph->findings++;

    if (chain == 0u) {
      chain = (uint32_t)(graph->chain_cursor % AP_GRAPH_MAX_CHAINS) + 1u;
      graph->chain_cursor++;
      if (graph->chains[chain - 1u].used == 0u) graph->evicted++;
    }
    graph->chains[chain - 1u].last_ns = now_ns;
    graph->chains[chain - 1u].used = 1u;
    snprintf(graph->chains[chain - 1u].key, AP_GRAPH_KEY_LEN, "%s", finding.key);
  }
  return AP_OK;
}

const char *ap_graph_tactic_name(uint32_t tactic) {
  if (tactic > AP_GRAPH_TACTIC_MAX) return "unknown";
  return ap_graph_tactics[tactic];
}

void ap_graph_stats(const ap_graph *graph, uint64_t *added, uint64_t *evicted,
                    uint64_t *findings, uint64_t *suppressed) {
  if (graph == NULL) return;
  if (added != NULL) *added = graph->added;
  if (evicted != NULL) *evicted = graph->evicted;
  if (findings != NULL) *findings = graph->findings;
  if (suppressed != NULL) *suppressed = graph->suppressed;
}
