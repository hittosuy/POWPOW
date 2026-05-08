# RPOWFinal

Hybrid RPOW2 headless miner:

- `miner.js` = Node.js orchestrator: config, session, HTTP keep-alive, retry, logging, expiry cutoff.
- `rpow-native-miner.c` = native C PoW engine, specialized single-block SHA-256 for RPOW2 input (`nonce_prefix` 16 bytes + nonce 8 bytes).
- No browser required for mining.

## Build

```bash
cd /home/sbram/RPOWFinal
./build.sh
npm test
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

## Run

```bash
cd /home/sbram/RPOWFinal
node miner.js config.json
```

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

