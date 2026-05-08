#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if ! command -v node >/dev/null 2>&1; then
  echo "Node.js belum ada. Install Node 20+ dulu." >&2
  exit 1
fi
if ! command -v gcc >/dev/null 2>&1; then
  echo "gcc belum ada. Ubuntu/Debian: sudo apt update && sudo apt install -y build-essential" >&2
  exit 1
fi
npm install
./build.sh
npm test
