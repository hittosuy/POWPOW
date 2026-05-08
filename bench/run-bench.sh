#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
./build.sh >/dev/null
printf 'JS single-thread benchmarks\n'
for mode in node wasm-full wasm-prefix; do node bench/bench-js.js --mode "$mode" --iters 1000000; done
printf '\nC benchmarks\n'
for mode in original prefix singleblock; do ./bench/bench-miners --mode "$mode" --threads 1 --iters 10000000; done
for mode in original prefix singleblock; do ./bench/bench-miners --mode "$mode" --threads 6 --iters 60000000; done
printf '\nFinal native binary quick solve\n'
./rpow-native-miner --prefix 00112233445566778899aabbccddeeff --difficulty 20 --workers 6 --progress-ms 0
