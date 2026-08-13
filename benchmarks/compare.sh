#!/usr/bin/env bash

set -euo pipefail

C23_RESULTS="benchmarks/results/c23/timing.csv"
RUST_RESULTS="benchmarks/results/rust/timing.csv"

if [[ ! -f "$C23_RESULTS" || ! -f "$RUST_RESULTS" ]]; then
    echo "Run bench_c23.sh and bench_rust.sh first"
    exit 1
fi

echo "╔══════════════════════════════════════════════════════════╗"
echo "║           C23 vs Rust — Zeus Benchmark Results          ║"
echo "╠══════════════╦══════════════╦══════════════╦════════════╣"
echo "║ Service      ║   C23 (ms)   ║  Rust (ms)   ║  Winner   ║"
echo "╠══════════════╬══════════════╬══════════════╬════════════╣"

while IFS=',' read -r service c23_time; do
    [[ "$service" == "service" ]] && continue
    rust_time=$(grep "^$service," "$RUST_RESULTS" | cut -d',' -f2)
    if [[ -z "$rust_time" ]]; then
        rust_time="N/A"
        winner="?"
    elif (( c23_time < rust_time )); then
        winner="C23 🏆"
    elif (( rust_time < c23_time )); then
        winner="Rust 🦀"
    else
        winner="Tie 🤝"
    fi
    printf "║ %-12s ║ %12s ║ %12s ║ %-10s║\n" \
        "$service" "${c23_time}ms" "${rust_time}ms" "$winner"
done < "$C23_RESULTS"

echo "╚══════════════╩══════════════╩══════════════╩════════════╝"