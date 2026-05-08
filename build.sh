#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
gcc -O3 -march=native -flto -pthread rpow-native-miner.c -o rpow-native-miner
chmod +x rpow-native-miner
echo "built $(pwd)/rpow-native-miner"
