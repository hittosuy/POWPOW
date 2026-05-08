#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
let Pool;
try { ({ Pool } = require('undici')); } catch { Pool = null; }

let running = true;
let logStream = null;
let pool = null;
let configPath = process.argv[2] || './config.json';
let config = null;
let rootDir = __dirname;

process.on('SIGINT', () => { running = false; log('warn', 'stop requested'); });
process.on('SIGTERM', () => { running = false; });

if (require.main === module) main().catch((err) => { log('error', 'fatal', { error: err.message || String(err) }); process.exit(1); });

async function main() {
  configPath = path.resolve(process.cwd(), configPath);
  rootDir = path.dirname(configPath);
  config = loadConfig(configPath);
  if (!config.rpow_session || String(config.rpow_session).includes('ISI_RPOW_SESSION')) throw new Error('Isi config.json -> rpow_session official/lokal');
  setupLogging(config, rootDir);
  cleanupOldLogs(config, rootDir);
  setInterval(() => cleanupOldLogs(config, rootDir), 3600_000).unref();
  setupPool(config.api || 'https://api.rpow2.com');

  const workers = normalizeWorkers(config.workers ?? 'auto', config);
  const engine = String(config.engine || 'native');
  const maxMints = Number(config.max_mints || 0);
  const statusEvery = Number(config.status_every || 1);
  const retryDelay = Number(config.retry_delay_ms || 3000);
  const balanceEvery = Number(config.balance_every || 10);
  let minted = 0, failed = 0, expired = 0, totalHashes = 0n;
  const startedAt = Date.now();

  log('info', 'RPOWFinal started', { api: apiBase(config), engine, workers, max_mints: maxMints || 'nonstop' });
  const me = await api('GET', '/me');
  log('info', 'Login OK', { email: me.email, balance: me.balance, minted: me.minted });

  while (running && (maxMints === 0 || minted < maxMints)) {
    try {
      const ch = await api('POST', '/challenge');
      const cutoff = challengeCutoffMs(ch.expires_at, Number(config.challenge_safety_ms || 5000));
      if (cutoff <= Date.now()) { expired++; log('warn', 'challenge too close to expiry', { challenge_id: short(ch.challenge_id), expires_at: ch.expires_at }); continue; }
      log('info', 'challenge', { id: short(ch.challenge_id), diff: ch.difficulty_bits, expires_at: ch.expires_at });
      const solveStart = Date.now();
      const solution = engine === 'native'
        ? await solveNative(ch, { workers, cutoff, rootDir, config })
        : await solveNode(ch, { workers: Math.min(workers, 8), cutoff });
      const solveMs = Date.now() - solveStart;
      if (solution.type === 'expired') { expired++; log('warn', 'challenge expired while mining', { hashes: solution.hashes }); continue; }
      const mint = await api('POST', '/mint', { challenge_id: ch.challenge_id, solution_nonce: String(solution.solution_nonce) });
      minted++;
      totalHashes += BigInt(solution.hashes || 0);
      const rate = Number(solution.hashes || 0) / Math.max(0.001, solveMs / 1000);
      const avg = Number(totalHashes) / Math.max(0.001, (Date.now() - startedAt) / 1000);
      if (minted % statusEvery === 0) log('mint', 'Mint OK', { run: minted, token: short(mint?.token?.id), diff: ch.difficulty_bits, nonce: String(solution.solution_nonce), hashes: String(solution.hashes), solve_ms: solveMs, rate_mhs: +(rate / 1e6).toFixed(3), avg_mhs: +(avg / 1e6).toFixed(3) });
      if (balanceEvery > 0 && minted % balanceEvery === 0) { const nowMe = await api('GET', '/me'); log('info', 'balance', { email: nowMe.email, balance: nowMe.balance, minted: nowMe.minted }); }
    } catch (err) {
      failed++;
      log('error', 'loop error', { failed, error: err.message || String(err) });
      if (/401|UNAUTHORIZED/i.test(String(err.message))) throw new Error('Session expired/invalid; update rpow_session');
      if (running) await sleep(retryDelay);
    }
  }
  try { const end = await api('GET', '/me'); log('info', 'stopped', { balance: end.balance, minted_total_user: end.minted, run: minted, failed, expired }); }
  catch { log('info', 'stopped', { run: minted, failed, expired }); }
  if (pool) await pool.close();
}

function solveNative(ch, opts) {
  const bin = path.resolve(opts.rootDir, opts.config.native_binary || './rpow-native-miner');
  const progressMs = Number(opts.config.progress_interval_ms || 5000);
  const args = ['--prefix', ch.nonce_prefix, '--difficulty', String(ch.difficulty_bits), '--workers', String(opts.workers), '--start', '0', '--cutoff-ms', String(opts.cutoff), '--progress-ms', String(opts.config.log_progress ? progressMs : 0)];
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, { cwd: opts.rootDir, stdio: ['ignore', 'pipe', 'pipe'] });
    let done = false, stderr = '', buf = '';
    const finish = (v) => { if (done) return; done = true; child.kill('SIGTERM'); resolve(v); };
    child.stdout.on('data', (chunk) => {
      buf += chunk.toString();
      let idx;
      while ((idx = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, idx).trim(); buf = buf.slice(idx + 1); if (!line) continue;
        let msg; try { msg = JSON.parse(line); } catch { log('warn', 'native non-json', { line }); continue; }
        if (msg.type === 'progress') { if (opts.config.log_progress) log('progress', 'mining', { hashes: msg.hashes, nonce: msg.nonce, rate_mhs: +(Number(msg.rate_hs || 0) / 1e6).toFixed(3) }); saveState(opts.rootDir, ch, msg); }
        else if (msg.type === 'found') finish(msg);
        else if (msg.type === 'expired') finish(msg);
      }
    });
    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('error', reject);
    child.on('exit', (code) => { if (!done) reject(new Error(`native miner exit ${code}: ${stderr.trim()}`)); });
  });
}

async function solveNode(ch, opts) {
  const prefix = Buffer.from(ch.nonce_prefix, 'hex');
  let nonce = 0n, hashes = 0n;
  while (Date.now() < opts.cutoff) {
    const buf = Buffer.alloc(prefix.length + 8); prefix.copy(buf, 0); writeU64LE(buf, prefix.length, nonce);
    const digest = crypto.createHash('sha256').update(buf).digest(); hashes++;
    if (trailingZeroBits(digest) >= ch.difficulty_bits) return { type: 'found', solution_nonce: nonce.toString(), hashes: hashes.toString(), digest: digest.toString('hex') };
    nonce++;
  }
  return { type: 'expired', hashes: hashes.toString() };
}

function setupPool(api) { if (!Pool) return; const u = new URL(apiBase({ api })); pool = new Pool(u.origin, { connections: 2, pipelining: 1 }); }
async function api(method, endpoint, body) {
  const base = apiBase(config);
  const headers = { cookie: buildCookieHeader(config) };
  if (body) headers['content-type'] = 'application/json';
  let status, text;
  if (pool) {
    const u = new URL(base + endpoint);
    const res = await pool.request({ path: u.pathname + u.search, method, headers, body: body ? JSON.stringify(body) : undefined, bodyTimeout: Number(config.http_timeout_ms || 30000), headersTimeout: Number(config.http_timeout_ms || 30000) });
    status = res.statusCode; text = await res.body.text();
  } else {
    const res = await fetch(base + endpoint, { method, headers, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(Number(config.http_timeout_ms || 30000)) });
    status = res.status; text = await res.text();
  }
  let data = null; try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (status < 200 || status >= 300) throw new Error(`${method} ${endpoint} HTTP ${status}: ${text}`);
  return data;
}

function loadConfig(file) { return JSON.parse(fs.readFileSync(file, 'utf8')); }
function apiBase(c) { return String(c.api || 'https://api.rpow2.com').replace(/\/$/, ''); }
function buildCookieHeader(c) { const s = String(c.rpow_session || '').trim(); return s.startsWith('rpow_session=') ? s : `rpow_session=${s}`; }
function normalizeWorkers(v, c = {}) { const cpus = Number(c.cpus || os.cpus().length); if (v !== 'auto' && v !== undefined && v !== null) return Math.max(1, Number(v) || 1); const reserve = Math.max(0, Number(c.cpu_reserve ?? 1)); const max = Math.max(1, Number(c.max_workers || 6)); return Math.max(1, Math.min(max, cpus - reserve)); }
function challengeCutoffMs(expiresAt, safetyMs = 5000) { return Date.parse(expiresAt) - Number(safetyMs || 0); }
function writeU64LE(buf, offset, n) { let x = BigInt(n); for (let i = 0; i < 8; i++) { buf[offset + i] = Number(x & 255n); x >>= 8n; } }
function trailingZeroBits(buf) { let count = 0; for (let i = buf.length - 1; i >= 0; i--) { const b = buf[i]; if (b === 0) { count += 8; continue; } let bit = 0; while ((b & (1 << bit)) === 0) bit++; return count + bit; } return count; }
function setupLogging(c, dir) { if (c.log_to_file === false) return; const logDir = path.resolve(dir, c.log_dir || './logs'); fs.mkdirSync(logDir, { recursive: true }); const stamp = new Date().toISOString().slice(0,13).replace(/[-:T]/g,''); logStream = fs.createWriteStream(path.join(logDir, `miner-${stamp}.jsonl`), { flags: 'a' }); }
function cleanupOldLogs(c, dir) { if (c.log_to_file === false) return; const logDir = path.resolve(dir, c.log_dir || './logs'); if (!fs.existsSync(logDir)) return; const cutoff = Date.now() - Number(c.log_retention_hours || 24) * 3600_000; for (const name of fs.readdirSync(logDir)) { const p = path.join(logDir, name); try { const st = fs.statSync(p); if (st.isFile() && st.mtimeMs < cutoff) fs.rmSync(p, { force: true }); } catch {} } }
function saveState(dir, ch, msg) { try { fs.writeFileSync(path.join(dir, 'state.json'), JSON.stringify({ t: new Date().toISOString(), challenge_id: ch.challenge_id, nonce_prefix: ch.nonce_prefix, difficulty_bits: ch.difficulty_bits, expires_at: ch.expires_at, nonce: msg.nonce, hashes: msg.hashes }, null, 2)); } catch {} }
function log(level, msg, data = {}) { const line = JSON.stringify({ t: new Date().toISOString(), level, msg, ...data }); console.log(line); if (logStream) logStream.write(line + '\n'); }
function short(s) { const x = String(s || ''); return x.length <= 14 ? x : `${x.slice(0,6)}...${x.slice(-4)}`; }
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

module.exports = { buildCookieHeader, normalizeWorkers, challengeCutoffMs, trailingZeroBits, writeU64LE };
