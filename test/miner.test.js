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
  assert.equal(miner.isRetryableStartupError(new Error('AggregateError')), true);
  assert.equal(miner.isRetryableStartupError(new Error('GET /me HTTP 401: login required')), false);
});

test('shouldUsePool can disable undici pool for flaky VPS networking', () => {
  assert.equal(miner.shouldUsePool({ use_undici_pool: false }), false);
  assert.equal(miner.shouldUsePool({ http_client: 'fetch' }), false);
  assert.equal(miner.shouldUsePool({}), true);
});
