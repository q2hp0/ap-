CC ?= gcc
CXX ?= g++
AR ?= ar
CARGO ?= cargo
CFLAGS := -std=c11 -O2 -Wall -Wextra -Werror -fPIC -Iinclude
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -Werror -fPIC -Iinclude
BUILD := build
OUT := out

C_OBJS := $(BUILD)/abi.o $(BUILD)/cap.o $(BUILD)/capture.o $(BUILD)/collector.o $(BUILD)/crypto.o $(BUILD)/evidence.o $(BUILD)/graph.o $(BUILD)/kernel.o $(BUILD)/ksensor.o $(BUILD)/replay.o $(BUILD)/telemetry.o $(BUILD)/transport.o $(BUILD)/sys.o $(BUILD)/taxonomy.o $(BUILD)/trace.o
CPP_OBJS := $(BUILD)/net.o $(BUILD)/flow.o $(BUILD)/beacon.o $(BUILD)/risk.o $(BUILD)/intrusion.o $(BUILD)/destructive.o
LIBS := $(BUILD)/libapsys.a $(BUILD)/libaptrace.a $(BUILD)/libapnet.a $(BUILD)/libapflow.a $(BUILD)/libapbeacon.a $(BUILD)/libaprisk.a $(BUILD)/libapintrusion.a $(BUILD)/libapdestructive.a

.PHONY: all libs tests check asan clean bench gui help

all: $(OUT)/ap $(OUT)/apgui

libs: $(LIBS) $(BUILD)/libapheap.so

$(BUILD)/%.o: c/%.c include/*.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/%.o: cpp/%.cpp include/*.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD)/libapsys.a: $(BUILD)/abi.o $(BUILD)/cap.o $(BUILD)/capture.o $(BUILD)/collector.o $(BUILD)/crypto.o $(BUILD)/evidence.o $(BUILD)/graph.o $(BUILD)/kernel.o $(BUILD)/ksensor.o $(BUILD)/replay.o $(BUILD)/telemetry.o $(BUILD)/transport.o $(BUILD)/sys.o $(BUILD)/taxonomy.o
	$(AR) rcs $@ $^

$(BUILD)/libaptrace.a: $(BUILD)/trace.o
	$(AR) rcs $@ $^

$(BUILD)/libapnet.a: $(BUILD)/net.o
	$(AR) rcs $@ $^

$(BUILD)/libapflow.a: $(BUILD)/flow.o
	$(AR) rcs $@ $^

$(BUILD)/libapbeacon.a: $(BUILD)/beacon.o
	$(AR) rcs $@ $^

$(BUILD)/libapintrusion.a: $(BUILD)/intrusion.o
	$(AR) rcs $@ $^

$(BUILD)/libapdestructive.a: $(BUILD)/destructive.o
	$(AR) rcs $@ $^

$(BUILD)/libaprisk.a: $(BUILD)/risk.o
	$(AR) rcs $@ $^

$(BUILD)/libapheap.so: $(BUILD)/abi.o $(BUILD)/crypto.o $(BUILD)/transport.o $(BUILD)/heap.o
	$(CC) -shared -o $@ $^ -ldl -lpthread

$(BUILD)/heap.o: c/heap.c include/*.h
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT)/ap: $(LIBS) $(shell find rust -name '*.rs' -o -name 'Cargo.toml')
	$(CARGO) build --release --offline --manifest-path rust/Cargo.toml
	cp rust/target/release/ap $@

$(OUT)/apgui: $(BUILD)/gui.o $(BUILD)/guiparse.o
	$(CXX) $(CXXFLAGS) $^ -lX11 -o $@

gui: $(OUT)/apgui

tests: $(BUILD)/test_abi $(BUILD)/test_cap $(BUILD)/test_ksensor $(BUILD)/test_graph $(BUILD)/test_taxonomy $(BUILD)/test_evidence $(BUILD)/test_capture $(BUILD)/test_collector $(BUILD)/test_crypto $(BUILD)/test_ipc $(BUILD)/test_audit $(BUILD)/test_replay $(BUILD)/test_net $(BUILD)/test_flow $(BUILD)/test_intrusion $(BUILD)/test_destructive $(BUILD)/test_beacon $(BUILD)/test_risk $(BUILD)/test_trace $(BUILD)/test_gui \
       $(BUILD)/fuzz_analyzers $(BUILD)/fuzz_inject $(BUILD)/inject $(BUILD)/capture_fixture $(BUILD)/kernel_fixture $(BUILD)/rwx_probe $(BUILD)/heap_probe \
       $(BUILD)/heap_recv $(BUILD)/kernel_probe $(BUILD)/test_kernel $(BUILD)/libapheap.so

$(BUILD)/test_abi: tests/test_abi.c $(BUILD)/libapsys.a
	$(CC) $(CFLAGS) $< $(BUILD)/libapsys.a -o $@

$(BUILD)/test_cap: tests/test_cap.c $(BUILD)/libapsys.a
	$(CC) $(CFLAGS) $< $(BUILD)/libapsys.a -o $@

$(BUILD)/test_ksensor: tests/test_ksensor.c $(BUILD)/libapsys.a
	$(CC) $(CFLAGS) $< $(BUILD)/libapsys.a -o $@

$(BUILD)/test_graph: tests/test_graph.c $(BUILD)/libapsys.a
	$(CC) $(CFLAGS) $< $(BUILD)/libapsys.a -o $@

$(BUILD)/test_evidence: tests/test_evidence.c $(BUILD)/libapsys.a
	$(CC) $(CFLAGS) $< $(BUILD)/libapsys.a -o $@

$(BUILD)/test_taxonomy: tests/test_taxonomy.c $(BUILD)/libapsys.a
	$(CC) $(CFLAGS) $< $(BUILD)/libapsys.a -o $@

$(BUILD)/test_capture: tests/test_capture.c $(BUILD)/libapsys.a
	$(CC) $(CFLAGS) $< $(BUILD)/libapsys.a -o $@

$(BUILD)/test_kernel: tests/test_kernel.c $(BUILD)/libapsys.a
	$(CC) $(CFLAGS) $< $(BUILD)/libapsys.a -o $@

$(BUILD)/test_collector: tests/test_collector.c $(BUILD)/libapsys.a
	$(CC) $(CFLAGS) $< $(BUILD)/libapsys.a -o $@

$(BUILD)/test_crypto: tests/test_crypto.c $(BUILD)/libapsys.a
	$(CC) $(CFLAGS) $< $(BUILD)/libapsys.a -o $@

$(BUILD)/test_ipc: tests/test_ipc.c $(BUILD)/libapsys.a
	$(CC) $(CFLAGS) $< $(BUILD)/libapsys.a -o $@

$(BUILD)/test_audit: tests/test_audit.c $(BUILD)/libapsys.a
	$(CC) $(CFLAGS) $< $(BUILD)/libapsys.a -o $@

$(BUILD)/test_replay: tests/test_replay.c $(BUILD)/libapsys.a
	$(CC) $(CFLAGS) $< $(BUILD)/libapsys.a -o $@

$(BUILD)/test_trace: tests/test_trace.c $(BUILD)/libaptrace.a $(BUILD)/libapsys.a
	$(CC) $(CFLAGS) $< $(BUILD)/libaptrace.a $(BUILD)/libapsys.a -o $@

$(BUILD)/test_net: tests/test_net.cpp $(BUILD)/libapnet.a $(BUILD)/libapsys.a
	$(CXX) $(CXXFLAGS) $< $(BUILD)/libapnet.a $(BUILD)/libapsys.a -o $@

$(BUILD)/test_flow: tests/test_flow.cpp $(BUILD)/libapflow.a $(BUILD)/libapsys.a
	$(CXX) $(CXXFLAGS) $< $(BUILD)/libapflow.a $(BUILD)/libapsys.a -o $@

$(BUILD)/test_intrusion: tests/test_intrusion.cpp $(BUILD)/libapintrusion.a $(BUILD)/libapsys.a
	$(CXX) $(CXXFLAGS) $< $(BUILD)/libapintrusion.a $(BUILD)/libapsys.a -o $@

$(BUILD)/test_destructive: tests/test_destructive.cpp $(BUILD)/libapdestructive.a $(BUILD)/libapsys.a
	$(CXX) $(CXXFLAGS) $< $(BUILD)/libapdestructive.a $(BUILD)/libapsys.a -o $@

$(BUILD)/test_gui: tests/test_gui.cpp $(BUILD)/guiparse.o
	$(CXX) $(CXXFLAGS) $< $(BUILD)/guiparse.o -o $@

$(BUILD)/test_beacon: tests/test_beacon.cpp $(BUILD)/libapbeacon.a $(BUILD)/libapsys.a
	$(CXX) $(CXXFLAGS) $< $(BUILD)/libapbeacon.a $(BUILD)/libapsys.a -o $@

$(BUILD)/test_risk: tests/test_risk.cpp $(BUILD)/libaprisk.a $(BUILD)/libapsys.a
	$(CXX) $(CXXFLAGS) $< $(BUILD)/libaprisk.a $(BUILD)/libapsys.a -o $@

$(BUILD)/fuzz_analyzers: tests/fuzz_analyzers.cpp $(BUILD)/libapnet.a $(BUILD)/libapflow.a $(BUILD)/libapintrusion.a $(BUILD)/libapdestructive.a $(BUILD)/libapsys.a
	$(CXX) $(CXXFLAGS) $< $(BUILD)/libapnet.a $(BUILD)/libapflow.a $(BUILD)/libapintrusion.a $(BUILD)/libapdestructive.a $(BUILD)/libapsys.a -o $@

$(BUILD)/fuzz_inject: tests/fuzz_inject.c $(BUILD)/libapsys.a
	$(CC) $(CFLAGS) $< $(BUILD)/libapsys.a -o $@

$(BUILD)/inject: tests/inject.c $(BUILD)/libapsys.a
	$(CC) $(CFLAGS) $< $(BUILD)/libapsys.a -o $@

$(BUILD)/capture_fixture: tests/capture_fixture.c $(BUILD)/libapsys.a
	$(CC) $(CFLAGS) $< $(BUILD)/libapsys.a -o $@

$(BUILD)/kernel_fixture: tests/kernel_fixture.c $(BUILD)/libapsys.a
	$(CC) $(CFLAGS) $< $(BUILD)/libapsys.a -o $@

$(BUILD)/rwx_probe: tests/rwx_probe.c
	$(CC) -std=c11 -O0 $< -o $@

$(BUILD)/kernel_probe: tests/kernel_probe.c
	$(CC) -std=c11 -O0 -Wall -Wextra -Werror $< -o $@

$(BUILD)/heap_probe: tests/heap_probe.c
	$(CC) -std=c11 -O0 $< -o $@

$(BUILD)/heap_recv: tests/heap_recv.c $(BUILD)/libapsys.a
	$(CC) $(CFLAGS) $< $(BUILD)/libapsys.a -o $@

check: all tests
	./$(BUILD)/test_abi
	./$(BUILD)/test_cap
	./$(BUILD)/test_ksensor
	./$(BUILD)/test_graph
	./$(BUILD)/test_taxonomy
	./$(BUILD)/test_evidence
	./$(BUILD)/test_capture
	./$(BUILD)/test_kernel
	./$(BUILD)/test_collector
	./$(BUILD)/test_crypto
	./$(BUILD)/test_ipc
	./$(BUILD)/test_audit
	./$(BUILD)/test_replay
	./scripts/test_replay.sh
	./scripts/test_sequence.sh
	./$(BUILD)/test_net
	./$(BUILD)/test_flow
	./$(BUILD)/test_intrusion
	./$(BUILD)/test_destructive
	./$(BUILD)/test_gui
	./$(BUILD)/test_beacon
	./$(BUILD)/test_risk
	./$(BUILD)/fuzz_analyzers
	./$(BUILD)/test_trace $(BUILD)/kernel_probe
	$(CARGO) test --offline --manifest-path rust/Cargo.toml
	./scripts/test_heap.sh
	./scripts/test_integration.sh
	./scripts/test_detectors.sh
	./scripts/test_proc.sh
	./scripts/test_guard.sh
	./scripts/test_matrix.sh
	./scripts/test_adversarial.sh
	./scripts/test_store.sh
	./scripts/test_policy.sh
	./scripts/test_limits.sh
	./scripts/test_kernel_chain.sh
	./scripts/test_entity_chain.sh
	./scripts/test_intrusion.sh
	./scripts/test_destructive.sh
	./scripts/test_capture.sh
	./scripts/test_kernel.sh
	./scripts/test_ksensor.sh
	./scripts/test_correlation.sh
	./scripts/test_update.sh
	./scripts/test_audit_process.sh

asan:
	./scripts/test_sanitizers.sh

bench: all
	./bench/bench.sh

clean:
	rm -f $(BUILD)/*.o $(BUILD)/*.a $(BUILD)/libapheap.so $(BUILD)/test_* $(BUILD)/fuzz_analyzers $(BUILD)/fuzz_inject $(BUILD)/inject $(BUILD)/capture_fixture $(BUILD)/kernel_fixture $(BUILD)/rwx_probe $(BUILD)/heap_probe $(BUILD)/heap_recv $(BUILD)/kernel_probe
	rm -rf $(BUILD)-asan
	rm -f $(OUT)/ap $(OUT)/apgui
	$(CARGO) clean --manifest-path rust/Cargo.toml

help:
	@echo "targets: all libs tests check asan bench gui clean"
