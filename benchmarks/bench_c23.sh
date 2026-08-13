#!/usr/bin/env bash

set -euo pipefail

BINARY="${1:-./build/zeus}"
TARGET="${BENCH_TARGET:-127.0.0.1}"
PASS_FILE="${BENCH_PASSFILE:-/usr/share/wordlists/rockyou.txt}"
TASKS="${BENCH_TASKS:-16}"
RESULTS_DIR="benchmarks/results/c23"

mkdir -p "$RESULTS_DIR"

bench_service() {
    local service="$1"
    local port="$2"
    local login="${3:-admin}"

    echo "Benchmarking: $service (port: $port, tasks: $TASKS)"

    local start elapsed attempts

    start=$(date +%s%N)
    timeout 30 "$BINARY" \
        -l "$login" -P "$PASS_FILE" \
        -t "$TASKS" -q \
        -s "$port" \
        "$TARGET" "$service" 2>/dev/null || true
    elapsed=$(( ($(date +%s%N) - start) / 1000000 )) # ms

    echo "  time: ${elapsed}ms"
    echo "${service},${elapsed}" >> "$RESULTS_DIR/timing.csv"
}

echo "service,time_ms" > "$RESULTS_DIR/timing.csv"
echo "=== C23 Zeus Benchmarks ==="
echo "Target: $TARGET | Tasks: $TASKS | Wordlist: $PASS_FILE"
echo ""

bench_service ftp   21  admin
bench_service ssh   22  root
bench_service http-get 80 admin
bench_service smtp  25  user
bench_service redis 6379 ""

echo ""
echo "Results saved to: $RESULTS_DIR/timing.csv"