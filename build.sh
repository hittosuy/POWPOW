#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
gcc -O3 -march=native -flto -pthread rpow-native-miner.c -o rpow-native-miner
chmod +x rpow-native-miner
echo "built $(pwd)/rpow-native-miner"
if command -v nvcc >/dev/null 2>&1; then
  ./build-cuda.sh
else
  echo "nvcc not found; skipped CUDA miner build. On GPU instances install CUDA toolkit and run ./build-cuda.sh"
fi
