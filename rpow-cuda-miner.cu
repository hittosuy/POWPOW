// CUDA RPOW miner.
// Same stdout protocol as rpow-native-miner.c:
//   {"type":"found","solution_nonce":"...","hashes":"...","digest":"..."}
//   {"type":"expired","hashes":"..."}
//   {"type":"progress","hashes":"...","nonce":"...","rate_hs":...}
//
// Optimization notes:
// - RPOW hashes exactly one SHA-256 block: prefix || uint64_le(nonce) || padding.
// - Every CUDA thread scans a strided nonce stream within a short batch.
// - Host launches short kernels repeatedly so challenge expiry is checked between batches.
// - Low difficulty means atomicCAS contention is rare and acceptable.

#include <cuda_runtime.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CHECK_CUDA(call) do { \
  cudaError_t _e = (call); \
  if (_e != cudaSuccess) { \
    fprintf(stderr, "CUDA error %s:%d: %s\n", __FILE__, __LINE__, cudaGetErrorString(_e)); \
    exit(3); \
  } \
} while (0)

static const uint32_t H0_HOST[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
static const uint32_t K_HOST[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

__constant__ uint32_t K_DEV[64];
__constant__ uint8_t PREFIX_DEV[55];

#define ROTR32(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH32(x,y,z) (((x)&(y)) ^ (~(x)&(z)))
#define MAJ32(x,y,z) (((x)&(y)) ^ ((x)&(z)) ^ ((y)&(z)))
#define EP0(x) (ROTR32(x,2) ^ ROTR32(x,13) ^ ROTR32(x,22))
#define EP1(x) (ROTR32(x,6) ^ ROTR32(x,11) ^ ROTR32(x,25))
#define SIG0(x) (ROTR32(x,7) ^ ROTR32(x,18) ^ ((x)>>3))
#define SIG1(x) (ROTR32(x,17) ^ ROTR32(x,19) ^ ((x)>>10))

static uint64_t now_ms(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static int parse_hex(const char *hex, uint8_t *out, size_t *out_len) {
  size_t n = strlen(hex);
  // The miner is specialized for one SHA-256 block over prefix || uint64_le(nonce).
  // SHA-256 single-block payload limit before padding is 55 bytes, so prefix <= 47.
  if (n % 2 || n / 2 > 47) return -1;
  for (size_t i = 0; i < n / 2; ++i) {
    int hi = hexval(hex[i * 2]), lo = hexval(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) return -1;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  *out_len = n / 2;
  return 0;
}

static uint64_t parse_u64(const char *s) {
  errno = 0;
  uint64_t v = strtoull(s, NULL, 10);
  if (errno) { fprintf(stderr, "bad integer: %s\n", s); exit(2); }
  return v;
}

__device__ __host__ static inline void nonce_le(uint64_t nonce, uint8_t out[8]) {
  for (int i = 0; i < 8; ++i) { out[i] = (uint8_t)(nonce & 0xffu); nonce >>= 8; }
}

__device__ static inline void sha256_transform_dev(uint32_t state[8], const uint8_t data[64]) {
  uint32_t a,b,c,d,e,f,g,h,t1,t2,m[64];
#pragma unroll
  for (int i = 0, j = 0; i < 16; ++i, j += 4) {
    m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j+1] << 16) | ((uint32_t)data[j+2] << 8) | data[j+3];
  }
#pragma unroll
  for (int i = 16; i < 64; ++i) m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
  a=state[0]; b=state[1]; c=state[2]; d=state[3]; e=state[4]; f=state[5]; g=state[6]; h=state[7];
#pragma unroll
  for (int i = 0; i < 64; ++i) {
    t1 = h + EP1(e) + CH32(e,f,g) + K_DEV[i] + m[i];
    t2 = EP0(a) + MAJ32(a,b,c);
    h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
  }
  state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d; state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

__device__ static inline void digest_singleblock_dev(size_t prefix_len, uint64_t nonce, uint8_t hash[32]) {
  uint8_t block[64];
  uint32_t state[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
#pragma unroll
  for (int i = 0; i < 64; ++i) block[i] = 0;
  for (size_t i = 0; i < prefix_len; ++i) block[i] = PREFIX_DEV[i];
  nonce_le(nonce, block + prefix_len);
  size_t len = prefix_len + 8;
  block[len] = 0x80;
  uint64_t bitlen = (uint64_t)len * 8;
#pragma unroll
  for (int s = 0; s < 8; ++s) block[63 - s] = (uint8_t)(bitlen >> (8 * s));
  sha256_transform_dev(state, block);
#pragma unroll
  for (int i = 0; i < 4; ++i) {
    hash[i]    = (state[0] >> (24 - i * 8)) & 255;
    hash[i+4]  = (state[1] >> (24 - i * 8)) & 255;
    hash[i+8]  = (state[2] >> (24 - i * 8)) & 255;
    hash[i+12] = (state[3] >> (24 - i * 8)) & 255;
    hash[i+16] = (state[4] >> (24 - i * 8)) & 255;
    hash[i+20] = (state[5] >> (24 - i * 8)) & 255;
    hash[i+24] = (state[6] >> (24 - i * 8)) & 255;
    hash[i+28] = (state[7] >> (24 - i * 8)) & 255;
  }
}

__device__ static inline int trailing_zero_bits_dev(const uint8_t hash[32]) {
  int bits = 0;
  for (int i = 31; i >= 0; --i) {
    uint8_t b = hash[i];
    if (b == 0) { bits += 8; continue; }
    for (int j = 0; j < 8; ++j) { if ((b & (1u << j)) == 0) bits++; else return bits; }
  }
  return bits;
}

__global__ void mine_kernel(size_t prefix_len, int difficulty, uint64_t base_nonce, uint64_t iterations,
                            unsigned int *done, unsigned long long *solution, unsigned long long *found_offset, uint8_t *solution_hash) {
  const uint64_t tid = (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
  const uint64_t stride = (uint64_t)gridDim.x * blockDim.x;
  uint8_t hash[32];
  for (uint64_t i = 0; i < iterations; ++i) {
    if (*done) return;
    uint64_t nonce = base_nonce + tid + i * stride;
    digest_singleblock_dev(prefix_len, nonce, hash);
    if (trailing_zero_bits_dev(hash) >= difficulty) {
      if (atomicCAS(done, 0u, 1u) == 0u) {
        *solution = (unsigned long long)nonce;
        *found_offset = (unsigned long long)(tid + i * stride);
#pragma unroll
        for (int j = 0; j < 32; ++j) solution_hash[j] = hash[j];
      }
      return;
    }
  }
}

// Host digest only for --self-test-digest parity checks without requiring a GPU launch.
static void sha256_transform_host(uint32_t state[8], const uint8_t data[64]) {
  uint32_t a,b,c,d,e,f,g,h,t1,t2,m[64];
  for (int i = 0, j = 0; i < 16; ++i, j += 4) m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j+1] << 16) | ((uint32_t)data[j+2] << 8) | data[j+3];
  for (int i = 16; i < 64; ++i) m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
  a=state[0]; b=state[1]; c=state[2]; d=state[3]; e=state[4]; f=state[5]; g=state[6]; h=state[7];
  for (int i = 0; i < 64; ++i) { t1 = h + EP1(e) + CH32(e,f,g) + K_HOST[i] + m[i]; t2 = EP0(a) + MAJ32(a,b,c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2; }
  state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d; state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

static void digest_singleblock_host(const uint8_t *prefix, size_t prefix_len, uint64_t nonce, uint8_t hash[32]) {
  uint8_t block[64]; uint32_t state[8]; memset(block, 0, 64); memcpy(block, prefix, prefix_len); nonce_le(nonce, block + prefix_len);
  size_t len = prefix_len + 8; block[len] = 0x80; uint64_t bitlen = (uint64_t)len * 8; for (int s = 0; s < 8; ++s) block[63 - s] = (uint8_t)(bitlen >> (8 * s));
  memcpy(state, H0_HOST, 32); sha256_transform_host(state, block);
  for (int i = 0; i < 4; ++i) { hash[i]=(state[0]>>(24-i*8))&255; hash[i+4]=(state[1]>>(24-i*8))&255; hash[i+8]=(state[2]>>(24-i*8))&255; hash[i+12]=(state[3]>>(24-i*8))&255; hash[i+16]=(state[4]>>(24-i*8))&255; hash[i+20]=(state[5]>>(24-i*8))&255; hash[i+24]=(state[6]>>(24-i*8))&255; hash[i+28]=(state[7]>>(24-i*8))&255; }
}

static void usage(void) {
  fprintf(stderr, "usage: rpow-cuda-miner --prefix HEX --difficulty N [--start N] [--cutoff-ms MS] [--progress-ms MS] [--blocks N] [--threads N] [--iterations N]\n");
}

int main(int argc, char **argv) {
  uint8_t prefix[55], solution_hash[32];
  size_t prefix_len = 0;
  const char *prefix_hex = NULL;
  int difficulty = 0, self_digest = 0, device = 0;
  uint64_t start_nonce = 0, cutoff_ms = 0, progress_ms = 5000, digest_nonce = 0;
  int blocks = 4096, threads = 256;
  uint64_t iterations = 512;

  for (int i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "--prefix") && i + 1 < argc) prefix_hex = argv[++i];
    else if (!strcmp(argv[i], "--difficulty") && i + 1 < argc) difficulty = atoi(argv[++i]);
    else if (!strcmp(argv[i], "--start") && i + 1 < argc) start_nonce = parse_u64(argv[++i]);
    else if (!strcmp(argv[i], "--cutoff-ms") && i + 1 < argc) cutoff_ms = parse_u64(argv[++i]);
    else if (!strcmp(argv[i], "--progress-ms") && i + 1 < argc) progress_ms = parse_u64(argv[++i]);
    else if (!strcmp(argv[i], "--blocks") && i + 1 < argc) blocks = atoi(argv[++i]);
    else if (!strcmp(argv[i], "--threads") && i + 1 < argc) threads = atoi(argv[++i]);
    else if (!strcmp(argv[i], "--iterations") && i + 1 < argc) iterations = parse_u64(argv[++i]);
    else if (!strcmp(argv[i], "--device") && i + 1 < argc) device = atoi(argv[++i]);
    else if (!strcmp(argv[i], "--nonce") && i + 1 < argc) digest_nonce = parse_u64(argv[++i]);
    else if (!strcmp(argv[i], "--self-test-digest")) self_digest = 1;
  }

  if (!prefix_hex || parse_hex(prefix_hex, prefix, &prefix_len) || blocks <= 0 || threads <= 0 || threads > 1024 || iterations == 0 || (!self_digest && difficulty <= 0)) {
    usage(); return 2;
  }
  if (self_digest) {
    uint8_t h[32]; digest_singleblock_host(prefix, prefix_len, digest_nonce, h);
    for (int i = 0; i < 32; ++i) printf("%02x", h[i]);
    printf("\n");
    return 0;
  }

  CHECK_CUDA(cudaSetDevice(device));
  CHECK_CUDA(cudaMemcpyToSymbol(K_DEV, K_HOST, sizeof(K_HOST)));
  CHECK_CUDA(cudaMemcpyToSymbol(PREFIX_DEV, prefix, sizeof(prefix)));

  unsigned int *d_done = NULL;
  unsigned long long *d_solution = NULL;
  unsigned long long *d_found_offset = NULL;
  uint8_t *d_hash = NULL;
  CHECK_CUDA(cudaMalloc(&d_done, sizeof(unsigned int)));
  CHECK_CUDA(cudaMalloc(&d_solution, sizeof(unsigned long long)));
  CHECK_CUDA(cudaMalloc(&d_found_offset, sizeof(unsigned long long)));
  CHECK_CUDA(cudaMalloc(&d_hash, 32));
  CHECK_CUDA(cudaMemset(d_done, 0, sizeof(unsigned int)));
  CHECK_CUDA(cudaMemset(d_solution, 0, sizeof(unsigned long long)));
  CHECK_CUDA(cudaMemset(d_found_offset, 0, sizeof(unsigned long long)));
  CHECK_CUDA(cudaMemset(d_hash, 0, 32));

  const uint64_t batch_hashes = (uint64_t)blocks * (uint64_t)threads * iterations;
  uint64_t base_nonce = start_nonce;
  uint64_t total = 0;
  uint64_t started = now_ms(), last = started;
  unsigned int h_done = 0;
  unsigned long long h_solution = 0;
  unsigned long long h_found_offset = 0;

  while (!h_done) {
    if (cutoff_ms && now_ms() >= cutoff_ms) break;
    mine_kernel<<<blocks, threads>>>(prefix_len, difficulty, base_nonce, iterations, d_done, d_solution, d_found_offset, d_hash);
    CHECK_CUDA(cudaGetLastError());
    CHECK_CUDA(cudaDeviceSynchronize());
    CHECK_CUDA(cudaMemcpy(&h_done, d_done, sizeof(h_done), cudaMemcpyDeviceToHost));
    CHECK_CUDA(cudaMemcpy(&h_solution, d_solution, sizeof(h_solution), cudaMemcpyDeviceToHost));
    CHECK_CUDA(cudaMemcpy(&h_found_offset, d_found_offset, sizeof(h_found_offset), cudaMemcpyDeviceToHost));
    total += h_done ? ((uint64_t)h_found_offset + 1ull) : batch_hashes;
    base_nonce += batch_hashes;

    uint64_t now = now_ms();
    if (progress_ms && now - last >= progress_ms) {
      double sec = (double)(now - started) / 1000.0;
      printf("{\"type\":\"progress\",\"hashes\":\"%" PRIu64 "\",\"nonce\":\"%" PRIu64 "\",\"rate_hs\":%.0f}\n", total, base_nonce, sec > 0 ? (double)total / sec : 0);
      fflush(stdout);
      last = now;
    }
  }

  if (!h_done) {
    printf("{\"type\":\"expired\",\"hashes\":\"%" PRIu64 "\"}\n", total);
  } else {
    CHECK_CUDA(cudaMemcpy(solution_hash, d_hash, 32, cudaMemcpyDeviceToHost));
    printf("{\"type\":\"found\",\"solution_nonce\":\"%llu\",\"hashes\":\"%" PRIu64 "\",\"digest\":\"", h_solution, total);
    for (int i = 0; i < 32; ++i) printf("%02x", solution_hash[i]);
    printf("\"}\n");
  }
  fflush(stdout);
  cudaFree(d_done); cudaFree(d_solution); cudaFree(d_found_offset); cudaFree(d_hash);
  return 0;
}
