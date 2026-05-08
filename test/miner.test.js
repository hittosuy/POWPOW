const test = require('node:test');
const assert = require('node:assert/strict');
const miner = require('../miner.js');

test('cookie header normalizes bare rpow_session', () => {
  assert.equal(miner.buildCookieHeader({ rpow_session: 'abc' }), 'rpow_session=abc');
});

test('cookie header preserves cookie assignment', () => {
  assert.equal(miner.buildCookieHeader({ rpow_session: 'rpow_session=abc' }), 'rpow_session=abc');
});

test('normalizeWorkers auto reserves cpu and caps max', () => {
  assert.equal(miner.normalizeWorkers('auto', { cpus: 12, max_workers: 8, cpu_reserve: 1 }), 8);
});

test('challenge cutoff applies safety margin', () => {
  const cutoff = miner.challengeCutoffMs('2030-01-01T00:00:10.000Z', 5000);
  assert.equal(cutoff, Date.parse('2030-01-01T00:00:05.000Z'));
});

test('selects cuda solver when engine is cuda', () => {
  assert.equal(miner.normalizeEngine('CUDA'), 'cuda');
});

test('cuda solver command uses gpu binary and tuning flags', () => {
  const ch = { nonce_prefix: '001122', difficulty_bits: 20 };
  const cmd = miner.buildSolverCommand(ch, {
    engine: 'cuda',
    rootDir: '/repo',
    laneId: 2,
    workers: 6,
    cutoff: 123456,
    config: {
      cuda_binary: './rpow-cuda-miner',
      cuda_blocks: 512,
      cuda_threads: 256,
      cuda_iterations: 512,
      cuda_device: 1,
      log_progress: true,
      progress_interval_ms: 1000,
    },
  });
  assert.equal(cmd.label, 'cuda');
  assert.equal(cmd.bin, '/repo/rpow-cuda-miner');
  assert.deepEqual(cmd.args, [
    '--prefix', '001122',
    '--difficulty', '20',
    '--start', String(2n << 48n),
    '--cutoff-ms', '123456',
    '--progress-ms', '1000',
    '--blocks', '512',
    '--threads', '256',
    '--iterations', '512',
    '--device', '1',
  ]);
});

test('buildMiningPlan supports explicit multi-lane layout', () => {
  assert.deepEqual(miner.buildMiningPlan({ lanes: 16, workers_per_lane: 8, max_total_workers: 128 }, { cpus: 128 }), {
    lanes: 16,
    workersPerLane: 8,
    totalWorkers: 128,
  });
});

test('buildMiningPlan auto lanes splits total workers', () => {
  assert.deepEqual(miner.buildMiningPlan({ lanes: 'auto', workers_per_lane: 8, max_total_workers: 128, cpu_reserve: 2 }, { cpus: 128 }), {
    lanes: 15,
    workersPerLane: 8,
    totalWorkers: 120,
  });
});

test('formatError expands AggregateError details', () => {
  const err = new AggregateError([new Error('connect ENETUNREACH 2606::1'), new Error('connect ETIMEDOUT 1.2.3.4')], 'fetch failed');
  const out = miner.formatError(err);
  assert.equal(out.name, 'AggregateError');
  assert.equal(out.message, 'fetch failed');
  assert.deepEqual(out.errors, ['connect ENETUNREACH 2606::1', 'connect ETIMEDOUT 1.2.3.4']);
});

test('isRetryableStartupError retries network timeouts but not unauthorized', () => {
  assert.equal(miner.isRetryableStartupError(new Error('connect ETIMEDOUT 1.2.3.4:443')), true);
  assert.equal(miner.isRetryableStartupError(new Error('curl GET /me failed: curl: (35) OpenSSL SSL_connect: SSL_ERROR_SYSCALL')), true);
  assert.equal(miner.isRetryableStartupError(new Error('AggregateError')), true);
  assert.equal(miner.isRetryableStartupError(new Error('GET /me HTTP 401: login required')), false);
});

test('shouldUsePool can disable undici pool for flaky VPS networking', () => {
  assert.equal(miner.shouldUsePool({ use_undici_pool: false }), false);
  assert.equal(miner.shouldUsePool({ http_client: 'fetch' }), false);
  assert.equal(miner.shouldUsePool({ http_client: 'curl' }), false);
  assert.equal(miner.shouldUsePool({}), true);
});

test('buildCurlArgs creates safe curl API request', () => {
  const args = miner.buildCurlArgs('https://api.rpow2.com', 'POST', '/challenge', { a: 1 }, 'rpow_session=abc', 30, '4');
  assert.deepEqual(args, ['-4', '-sS', '--max-time', '30', '-w', '\nHTTP_STATUS:%{http_code}\n', '-H', 'cookie: rpow_session=abc', '-H', 'content-type: application/json', '--data', '{"a":1}', '-X', 'POST', 'https://api.rpow2.com/challenge']);
});

test('buildCurlArgs can use auto IP family for hosts with broken IPv4 TLS', () => {
  const args = miner.buildCurlArgs('https://api.rpow2.com', 'GET', '/me', null, 'rpow_session=abc', 30, 'auto');
  assert.deepEqual(args, ['-sS', '--max-time', '30', '-w', '\nHTTP_STATUS:%{http_code}\n', '-H', 'cookie: rpow_session=abc', '-X', 'GET', 'https://api.rpow2.com/me']);
});

test('buildCurlArgs supports proxy and curl-level retries', () => {
  const args = miner.buildCurlArgs('https://api.rpow2.com', 'GET', '/me', null, 'rpow_session=abc', 30, 'auto', {
    curl_proxy: 'socks5h://user:pass@proxy.example:1080',
    curl_retries: 3,
    curl_retry_delay_sec: 2,
  });
  assert.deepEqual(args, ['--proxy', 'socks5h://user:pass@proxy.example:1080', '--retry', '3', '--retry-delay', '2', '--retry-all-errors', '-sS', '--max-time', '30', '-w', '\nHTTP_STATUS:%{http_code}\n', '-H', 'cookie: rpow_session=abc', '-X', 'GET', 'https://api.rpow2.com/me']);
});
