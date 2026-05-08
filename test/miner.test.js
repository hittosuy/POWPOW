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
