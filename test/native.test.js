const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const cp = require('node:child_process');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const BIN = path.join(ROOT, 'rpow-native-miner');
const PREFIX = '00112233445566778899aabbccddeeff';

function nodeDigest(prefixHex, nonce) {
  const prefix = Buffer.from(prefixHex, 'hex');
  const buf = Buffer.alloc(prefix.length + 8);
  prefix.copy(buf, 0);
  let x = BigInt(nonce);
  for (let i = 0; i < 8; i++) { buf[prefix.length + i] = Number(x & 255n); x >>= 8n; }
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function run(args) {
  return cp.execFileSync(BIN, args, { cwd: ROOT, encoding: 'utf8' }).trim();
}

test('native digest matches Node SHA256 reference', () => {
  const out = run(['--self-test-digest', '--prefix', PREFIX, '--nonce', '12345']);
  assert.equal(out, nodeDigest(PREFIX, 12345n));
});

test('native miner finds a valid low-difficulty nonce and reports JSON', () => {
  const out = run(['--prefix', PREFIX, '--difficulty', '12', '--workers', '2', '--start', '0', '--progress-ms', '0']);
  const msg = JSON.parse(out.split('\n').at(-1));
  assert.equal(msg.type, 'found');
  assert.match(msg.solution_nonce, /^\d+$/);
  assert.ok(Number(msg.hashes) > 0);
  const digest = nodeDigest(PREFIX, BigInt(msg.solution_nonce));
  let bits = 0;
  const b = Buffer.from(digest, 'hex');
  for (let i = b.length - 1; i >= 0; i--) {
    if (b[i] === 0) { bits += 8; continue; }
    let j = 0;
    while ((b[i] & (1 << j)) === 0) j++;
    bits += j;
    break;
  }
  assert.ok(bits >= 12, `trailing bits ${bits} digest ${digest}`);
});
