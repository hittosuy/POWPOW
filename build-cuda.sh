#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if ! command -v nvcc >/dev/null 2>&1; then
  echo "nvcc not found. Install CUDA toolkit on the GPU instance, then rerun ./build-cuda.sh" >&2
  exit 1
fi
args=(-O3 -std=c++17 -lineinfo)
if [[ -n "${CUDA_ARCH:-}" ]]; then
  args+=("-arch=${CUDA_ARCH}")
fi
nvcc "${args[@]}" rpow-cuda-miner.cu -o rpow-cuda-miner
chmod +x rpow-cuda-miner
echo "built $(pwd)/rpow-cuda-miner${CUDA_ARCH:+ with CUDA_ARCH=$CUDA_ARCH}"
