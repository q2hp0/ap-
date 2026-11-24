# current repository structure

the tree is organized by real ownership: c owns syscall and kernel interfaces, c++
owns bounded analyzers, rust owns policy and the single event loop, and each module
has tests in the same change. no placeholder files are created.

```
ap/
  include/
    apabi.h           fixed event and verdict abi
    apbeacon.h        bounded beacon analyzer api and limits
    apcap.h           capability bit definitions
    apcapture.h       bounded packet capture api
    apcollector.h     bounded /proc collector api with map limits
    apcrypto.h        sha-256 and hmac primitives
    apevidence.h      bounded finding-dedupe ledger api
    apflow.h          c++ flow analysis and entity stage api
    apgraph.h         bounded attack graph api and tactic ids
    apintrusion.h     bounded intrusion-stage analyzer api and limits
    apheap.h          ld_preload allocator shim api
    apkernel.h        bounded apk1 kernel event file api
    apksensor.h       kernel sensor sample, labels, counters and status
    apnet.h           c++ protocol analysis api
    apreplay.h        authenticated datagram tag ring and sequence table
    aprisk.h          bounded risk accumulator api
    apsys.h           platform primitives and seccomp
    aptaxonomy.h      canonical label/tactic/confidence entries
    aptelemetry.h     capability-aware source descriptors
    aptrace.h         ptrace syscall supervision api
    aptransport.h     authenticated datagram layout and key handling
  c/
    abi.c             abi helpers
    cap.c             capability probe
    capture.c         bounded AF_PACKET and frame-file reader
    collector.c       bounded /proc process, privilege and map deltas
    crypto.c          sha-256 and hmac
    evidence.c        256-record finding ledger with dedupe and eviction
    graph.c           128-node bounded attack graph and chain suppression
    heap.c            ld_preload allocator shim
    kernel.c          strict apk1 event file parser
    ksensor.c         raw bpf/perf_event_open/LSM sensor with hand-encoded programs
    replay.c          exact-duplicate tag ring and epoch-aware sequence table
    sys.c             platform primitives and /proc starttime parser
    taxonomy.c        canonical labels and aliases to rule/tactic/confidence
    telemetry.c       source descriptors
    trace.c           ptrace/seccomp supervision and explicit process-memory labels
    transport.c       packet signing, verification and key files
  cpp/
    beacon.cpp        bounded 64-peer timing analyzer
    destructive.cpp   64-pid file and chain analyzer for rules 30/31/32
    flow.cpp          w+x, kernel, persistence, container and entity correlations
    intrusion.cpp     64-pid stage analyzer for rules 27/28/29
    net.cpp           ipv4/ipv6 and transport protocol engines
    risk.cpp          bounded 64-entity risk accumulator
  rust/src/
    main.rs           cli entry and one-shot verification modes
    lib.rs            public modules
    build.rs          native library linker wiring
    abi.rs            fixed-layout mirror and validation
    adversarial.rs    deterministic fuzz tests
    audit.rs          audit writer child and status
    auth.rs           local key lifecycle, hmac and constant-time compare
    capture.rs        rust wrapper around the c capture handle
    cli.rs            terminal stream
    collector.rs      rust wrapper around the c collector handle
    correlation.rs    graph/evidence/taxonomy/beacon/risk bridge and analyzer tactics
    detect.rs         validation, cheap rules, analyzer bridge and feeds
    detection/
      mod.rs          detector registry module
      registry.rs     32 detector descriptors, enable set, coverage output
    engine.rs         event loop, source threads and shutdown
    event.rs          normalization, source marks and findings
    ffi.rs            c ABI bindings, including intrusion and destructive wrappers
    guard.rs          opt-in enforcement, bounded chain gate and honest status
    ipc.rs            sealed datagram receive, duplicate and sequence counting
    kernel.rs         rust wrapper around the c kernel event reader
    ksensor.rs        sensor probe, open flags, state and counters wrapper
    policy.rs         configuration and cli parsing
    policyfile.rs     sealed policy parsing and verification
    risk.rs           bounded decaying per-pid rust risk
    source.rs         named source registry and degraded states (10 sources)
    store.rs          bounded audit store and hmac chain
    update.rs         bounded update verification, staging and local snapshots
  tests/
    test_abi.c, test_cap.c, test_capture.c, test_kernel.c, test_collector.c,
    test_crypto.c, test_ipc.c, test_audit.c, test_replay.c, test_trace.c,
    test_ksensor.c, test_graph.c, test_taxonomy.c, test_evidence.c          c suites
    test_net.cpp, test_flow.cpp, test_beacon.cpp, test_risk.cpp,
    test_intrusion.cpp, fuzz_analyzers.cpp                                 c++ suites
    inject.c, fuzz_inject.c                                                telemetry generators
    capture_fixture.c, kernel_fixture.c                                    framed input fixtures
    rwx_probe.c, heap_probe.c, kernel_probe.c, heap_recv.c                 controlled probes
  scripts/
    test_ksensor.sh, test_correlation.sh, test_detectors.sh, test_intrusion.sh,
    test_kernel.sh, test_kernel_chain.sh, test_entity_chain.sh, test_capture.sh,
    test_proc.sh, test_replay.sh, test_sequence.sh, test_store.sh, test_policy.sh,
    test_update.sh, test_guard.sh, test_matrix.sh, test_adversarial.sh,
    test_limits.sh, test_integration.sh, test_audit_process.sh,
    test_heap.sh, test_sanitizers.sh
  bench/
    bench.sh          measurement harness
  docs/
    architecture.md, interfaces.md, status.md, testing.md, limitations.md,
    security.md, compatibility.md, performance.md
    detection/        advanced_rules.md, attack_graph.md, beacon.md, taxonomy.md
    kernel/           sensor.md
    transformation/   assessment.md, inventory.md, weaknesses.md,
                      coverage_matrix.md, structure.md, integration_plan.md,
                      roadmap.md
```

the kernel sensor is one c source plus its header, not a separate eBPF object or
external crate. bpf-lsm is an optional program built by the same c module, not a
new enforcement service. `cpp/intrusion.cpp` builds into `build/libapintrusion.a`
and is linked through `rust/src/ffi.rs`; `fuzz_analyzers` links that library too.
all listed files exist; modules are added only with implementation and tests in
the same change.
