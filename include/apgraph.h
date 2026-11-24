#ifndef APGRAPH_H
#define APGRAPH_H

#include "apabi.h"

#include <stddef.h>
#include <stdint.h>

#define AP_GRAPH_MAX_NODES 128u
#define AP_GRAPH_MAX_EDGES 256u
#define AP_GRAPH_MAX_CHAINS 32u
#define AP_GRAPH_KEY_LEN 64u
#define AP_GRAPH_WINDOW_NS 60000000000ULL
#define AP_GRAPH_SUPPRESS_NS 30000000000ULL

enum ap_graph_tactic {
  AP_GRAPH_TACTIC_NONE = 0,
  AP_GRAPH_TACTIC_INITIAL_ACCESS = 1,
  AP_GRAPH_TACTIC_EXECUTION = 2,
  AP_GRAPH_TACTIC_PERSISTENCE = 3,
  AP_GRAPH_TACTIC_PRIVILEGE_ESCALATION = 4,
  AP_GRAPH_TACTIC_DEFENSE_EVASION = 5,
  AP_GRAPH_TACTIC_CREDENTIAL_ACCESS = 6,
  AP_GRAPH_TACTIC_DISCOVERY = 7,
  AP_GRAPH_TACTIC_LATERAL_MOVEMENT = 8,
  AP_GRAPH_TACTIC_COLLECTION = 9,
  AP_GRAPH_TACTIC_COMMAND_AND_CONTROL = 10,
  AP_GRAPH_TACTIC_EXFILTRATION = 11,
  AP_GRAPH_TACTIC_IMPACT = 12,
  AP_GRAPH_TACTIC_MAX = 12
};

typedef struct ap_graph_observation {
  uint64_t ts_ns;
  int64_t pid;
  uint32_t tactic;
  uint32_t label_id;
  uint32_t confidence_x1000;
  char key[AP_GRAPH_KEY_LEN];
} ap_graph_observation;

typedef struct ap_graph_finding {
  uint64_t ts_ns;
  int64_t pid;
  uint32_t tactics;
  uint32_t confidence_x1000;
  uint32_t nodes;
  char key[AP_GRAPH_KEY_LEN];
} ap_graph_finding;

typedef int (*ap_graph_cb)(const ap_graph_finding *finding, void *user);

typedef struct ap_graph_node {
  uint64_t ts_ns;
  int64_t pid;
  uint32_t tactic;
  uint32_t label_id;
  uint32_t confidence_x1000;
  uint32_t used;
  char key[AP_GRAPH_KEY_LEN];
} ap_graph_node;

typedef struct ap_graph_edge {
  uint32_t from;
  uint32_t to;
  uint32_t used;
} ap_graph_edge;

typedef struct ap_graph_chain {
  uint64_t last_ns;
  uint32_t used;
  char key[AP_GRAPH_KEY_LEN];
} ap_graph_chain;

typedef struct ap_graph {
  ap_graph_node nodes[AP_GRAPH_MAX_NODES];
  ap_graph_edge edges[AP_GRAPH_MAX_EDGES];
  ap_graph_chain chains[AP_GRAPH_MAX_CHAINS];
  uint64_t node_cursor;
  uint64_t edge_cursor;
  uint64_t chain_cursor;
  uint64_t added;
  uint64_t evicted;
  uint64_t findings;
  uint64_t suppressed;
} ap_graph;

#ifdef __cplusplus
extern "C" {
#endif

void ap_graph_init(ap_graph *graph);
int ap_graph_add(ap_graph *graph, const ap_graph_observation *observation);
int ap_graph_evaluate(ap_graph *graph, uint64_t now_ns, ap_graph_cb callback,
                      void *user);
const char *ap_graph_tactic_name(uint32_t tactic);
void ap_graph_stats(const ap_graph *graph, uint64_t *added, uint64_t *evicted,
                    uint64_t *findings, uint64_t *suppressed);

#ifdef __cplusplus
}
#endif

#endif
