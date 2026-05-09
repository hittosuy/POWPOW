# RPOWFinal

Hybrid RPOW2 headless miner:

- `miner.js` = Node.js orchestrator: config, session, HTTP keep-alive, retry, logging, expiry cutoff, ledger/reward/cap tracking.
- `rpow-native-miner.c` = native C CPU PoW engine, specialized single-block SHA-256 for RPOW2 input (`nonce_prefix` 16 bytes + nonce 8 bytes).
- `rpow-cuda-miner.cu` = CUDA GPU PoW engine for NVIDIA GPU instances.
- No browser required for mining.

## Build

```bash
cd /home/sbram/RPOWFinal-clean
./build.sh
npm test
```

`./build.sh` always builds the CPU miner. If `nvcc` is available, it also builds `rpow-cuda-miner`.
On GPU instances without auto-detected CUDA, install the CUDA toolkit and run:

```bash
./build-cuda.sh
```

Optional CUDA arch override (useful if your nvcc does not auto-target the GPU):

```bash
CUDA_ARCH=sm_89 ./build-cuda.sh
```

## Configure official mining

Edit `config.json`:

```json
{
  "api": "https://api.rpow2.com",
  "rpow_session": "COOKIE_OFFICIAL_RPOW_SESSION",
  "engine": "native",
  "workers": "auto",
  "max_workers": 6
}
```

`rpow_session` must be the official cookie from `https://rpow2.com` / `https://api.rpow2.com`.
Local RPOW cookies are not valid on official API.

## New mint model

The official API now controls issuance from `/ledger`:

- Miner still solves `SHA256(nonce_prefix || uint64_le(solution_nonce))` against `difficulty_bits` from `/challenge`.
- Reward is no longer assumed fixed by the miner; `/ledger.current_reward_base_units` is logged after mint.
- Halving/cap state is tracked through `/ledger` fields like `halving_index`, `base_units_to_next_halving`, and `is_capped`.
- If `/ledger.is_capped` or a cap-related `/mint` error appears, all lanes stop cleanly.
- `ledger_every`, `ledger_interval_ms`, and `ledger_min_interval_ms` control how often supply/reward state is refreshed.

## Run

```bash
cd /home/sbram/RPOWFinal-clean
node miner.js config.json
```

## CUDA GPU mode

Use this on NVIDIA GPU instances:

```json
{
  "api": "https://api.rpow2.com",
  "rpow_session": "COOKIE_OFFICIAL_RPOW_SESSION",
  "engine": "cuda",
  "cuda_binary": "./rpow-cuda-miner",
  "cuda_blocks": 4096,
  "cuda_threads": 256,
  "cuda_iterations": 512,
  "cuda_device": 0,
  "lanes": 1,
  "workers_per_lane": 1,
  "http_client": "curl",
  "curl_ip_version": "auto",
  "use_undici_pool": false,
  "http_timeout_ms": 45000,
  "curl_retries": 3,
  "curl_retry_delay_sec": 2,
  "curl_proxy": "",
  "curl_proxy_insecure": false,
  "challenge_safety_ms": 5000,
  "balance_every": 50
}
```

GPU tuning rules:

- Start with `lanes=1`; one CUDA lane can already saturate many GPUs.
- Increase `cuda_blocks` first (`4096` → `8192`) if GPU utilization is low.
- Keep `cuda_threads=256` unless occupancy is poor on your card.
- `cuda_iterations` controls kernel batch length. Higher is faster but less responsive to challenge expiry. Recommended range: `256–2048`.
- For official API, keep `http_client="curl"` because Node/undici was flaky against `api.rpow2.com` on some instances.
- `curl_retries` retries transient `502`, timeout, and TLS/network errors inside curl before the miner loop retries.
- Set `curl_proxy` only on VPS providers that cannot TLS-handshake with `api.rpow2.com`; prefer `socks5h://USER:PASS@HOST:PORT` so DNS goes through the proxy.
- If API timeouts increase, do not add more lanes; GPU is probably already faster than the API path.

Background:

```bash
nohup node miner.js config.json > /dev/null 2>&1 &
```

Logs go to `./logs/*.jsonl` and are auto-deleted after `log_retention_hours`.

## Benchmark result on this instance

CPU: Intel i5-12400F, 6 physical cores / 12 threads.

- Node crypto: ~0.69 MH/s single thread
- hash-wasm full: ~1.47 MH/s single thread
- hash-wasm prefixState: ~0.90 MH/s single thread
- C original-style: ~4.29 MH/s single thread, ~18.6 MH/s at 6 threads
- C prefix-copy: ~4.15 MH/s single thread, ~21.0 MH/s at 6 threads
- C specialized single-block: ~4.10 MH/s single thread, ~21.9 MH/s at 6 threads

Best measured setting here: native C, 6 workers.

## Multi-lane mode for large VPS

For high-core VPS, do not use one huge single lane. Use multiple lanes so CPU stays busy while other lanes wait for `/mint` and `/challenge` HTTP responses.

Example for 128 logical CPUs:

```json
{
  "lanes": 16,
  "workers_per_lane": 8,
  "max_total_workers": 128,
  "http_connections": 32,
  "log_challenges": false,
  "balance_every": 100
}
```

Alternative profiles:

- 32 CPU: `lanes=4`, `workers_per_lane=8`
- 64 CPU: `lanes=8`, `workers_per_lane=8`
- 128 CPU: `lanes=16`, `workers_per_lane=8`

Restart after changing config:

```bash
pm2 restart rpowfinal
# or if using nohup/manual, kill old node process then run again
node miner.js config.json
```

