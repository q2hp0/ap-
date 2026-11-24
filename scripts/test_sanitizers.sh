#!/bin/sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
build="$root/build-asan"
rm -rf "$build"
mkdir -p "$build"

common="-g -O1 -Wall -Wextra -Werror -fPIC -Iinclude -fsanitize=address,undefined -fno-omit-frame-pointer"
make -C "$root" BUILD=build-asan CC=gcc CXX=g++ \
  CFLAGS="-std=c11 $common" CXXFLAGS="-std=c++17 $common" \
  build-asan/test_abi build-asan/test_cap build-asan/test_ksensor build-asan/test_graph build-asan/test_taxonomy build-asan/test_evidence build-asan/test_capture build-asan/test_kernel build-asan/test_collector build-asan/test_crypto build-asan/test_ipc build-asan/test_audit build-asan/test_net build-asan/test_flow build-asan/test_intrusion build-asan/test_destructive build-asan/test_gui build-asan/test_beacon build-asan/test_risk build-asan/fuzz_analyzers \
  build-asan/test_replay build-asan/test_trace build-asan/kernel_probe build-asan/libapheap.so >/dev/null

export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1
export UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1

"$build/test_abi"
"$build/test_cap"
"$build/test_ksensor"
"$build/test_graph"
"$build/test_taxonomy"
"$build/test_evidence"
"$build/test_capture"
"$build/test_kernel"
"$build/test_collector"
"$build/test_crypto"
"$build/test_ipc"
"$build/test_audit"
"$build/test_replay"
"$build/test_net"
"$build/test_flow"
"$build/test_intrusion"
"$build/test_destructive"
"$build/test_gui"
"$build/test_beacon"
"$build/test_risk"
"$build/fuzz_analyzers"
"$build/test_trace" "$build/kernel_probe"
echo "sanitizer tests: ok"
