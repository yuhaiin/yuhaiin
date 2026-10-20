#!/usr/bin/env bash
set -euo pipefail

# Run sequentially on an idle host. Compare the same topology/toolchain/settings.
repo_dir="$(git rev-parse --show-toplevel)"
output_dir="${OUTPUT_DIR:-$(mktemp -d /tmp/yuhaiin-tc-bench.XXXXXX)}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"
export GOMAXPROCS="${GOMAXPROCS:-2}"
bench_count="${BENCH_COUNT:-3}"
bench_time="${BENCH_TIME:-1s}"
baseline_dir=''
cleanup() {
  if [[ -n "$baseline_dir" ]]; then
    git -C "$repo_dir" worktree remove "$baseline_dir" --force
  fi
}
trap cleanup EXIT

run_stack() {
  local checkout="$1" label="$2"
  (
    cd "$checkout"
    go test ./pkg/net/proxy/tun/lightweight -run '^$' \
      -bench '^BenchmarkUDP$/^payload=(64|1200)$/^flows=1$' \
      -benchtime="$bench_time" -count="$bench_count" -benchmem -timeout=240s
  ) | tee "$output_dir/udp-$label.log"
  (
    cd "$checkout"
    go test ./pkg/net/proxy/tun/lightweight -run '^$' \
      -bench '^BenchmarkTCP$/^reno$/^mtu=1500$/^flows=1$/^payload=(64|65536)$/^(upload|download)$' \
      -benchtime="$bench_time" -count="$bench_count" -benchmem -timeout=240s
  ) | tee "$output_dir/tcp-$label.log"
}
if [[ -n "${BASE_REF:-}" ]]; then
  baseline_dir="$(mktemp -d /tmp/yuhaiin-tc-base.XXXXXX)"
  rmdir "$baseline_dir"
  git -C "$repo_dir" worktree add --detach "$baseline_dir" "$BASE_REF"
  run_stack "$baseline_dir" baseline
fi
run_stack "$repo_dir" current
(
  cd "$repo_dir"
  go test ./pkg/net/trafficcontrol ./pkg/net/relay ./pkg/net/nat \
    ./pkg/net/proxy/tun/lightweight -run '^$' \
    -bench '^Benchmark(FairQueue|GroupedFairQueue|OutputQueue|OutputHostHash|OutputFlowHash|Governor|Shaper|Policy|Datagram|NATSession)' \
    -benchtime="$bench_time" -count="$bench_count" -benchmem -timeout=300s
) | tee "$output_dir/core-current.log"
printf 'Benchmark logs: %s\n' "$output_dir"
