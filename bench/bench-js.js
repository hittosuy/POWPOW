#!/usr/bin/env node
'use strict';
const crypto = require('crypto');
const { createSHA256 } = require('hash-wasm');

const prefixHex = process.argv.includes('--prefix') ? process.argv[process.argv.indexOf('--prefix') + 1] : '00112233445566778899aabbccddeeff';
const mode = process.argv.includes('--mode') ? process.argv[process.argv.indexOf('--mode') + 1] : 'node';
const iters = BigInt(process.argv.includes('--iters') ? process.argv[process.argv.indexOf('--iters') + 1] : '1000000');
const nonceArg = BigInt(process.argv.includes('--nonce') ? process.argv[process.argv.indexOf('--nonce') + 1] : '12345');
const digestOnly = process.argv.includes('--digest');
const prefix = Buffer.from(prefixHex, 'hex');

function writeU64LE(buf, off, n) { let x = BigInt(n); for (let i = 0; i < 8; i++) { buf[off+i] = Number(x & 255n); x >>= 8n; } }
function digestNode(nonce) { const buf = Buffer.alloc(prefix.length + 8); prefix.copy(buf,0); writeU64LE(buf,prefix.length,nonce); return crypto.createHash('sha256').update(buf).digest(); }

(async () => {
  if (digestOnly) { console.log(digestNode(nonceArg).toString('hex')); return; }
  let sink = 0;
  const t0 = process.hrtime.bigint();
  if (mode === 'node') {
    const buf = Buffer.alloc(prefix.length + 8); prefix.copy(buf,0);
    for (let i = 0n; i < iters; i++) { writeU64LE(buf,prefix.length,i); const h = crypto.createHash('sha256').update(buf).digest(); sink += h[31]; }
  } else if (mode === 'wasm-full') {
    const sha = await createSHA256();
    const buf = new Uint8Array(prefix.length + 8); buf.set(prefix,0);
    for (let i = 0n; i < iters; i++) { writeU64LE(buf,prefix.length,i); sha.init(); sha.update(buf); const h = sha.digest('binary'); sink += h[31]; }
  } else if (mode === 'wasm-prefix') {
    const sha = await createSHA256(); const nonceBuf = new Uint8Array(8);
    sha.init(); sha.update(prefix); const state = sha.save();
    for (let i = 0n; i < iters; i++) { writeU64LE(nonceBuf,0,i); sha.load(state); sha.update(nonceBuf); const h = sha.digest('binary'); sink += h[31]; }
  } else throw new Error('unknown mode');
  const sec = Number(process.hrtime.bigint() - t0) / 1e9;
  console.log(JSON.stringify({ mode, iters: iters.toString(), sec, mhps: Number(iters) / sec / 1e6, sink }));
})();
