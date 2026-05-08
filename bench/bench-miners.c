#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct { uint8_t data[64]; uint32_t datalen; uint64_t bitlen; uint32_t state[8]; } sha256_ctx;
static const uint32_t H0[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
static const uint32_t k[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
#define ROTR(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x)&(y)) ^ (~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y)) ^ ((x)&(z)) ^ ((y)&(z)))
#define EP0(x) (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define EP1(x) (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define SIG0(x) (ROTR(x,7) ^ ROTR(x,18) ^ ((x)>>3))
#define SIG1(x) (ROTR(x,17) ^ ROTR(x,19) ^ ((x)>>10))
static void sha256_transform_state(uint32_t state[8], const uint8_t data[64]) {
  uint32_t a,b,c,d,e,f,g,h,i,j,t1,t2,m[64];
  for (i=0,j=0;i<16;++i,j+=4) m[i]=((uint32_t)data[j]<<24)|((uint32_t)data[j+1]<<16)|((uint32_t)data[j+2]<<8)|data[j+3];
  for (;i<64;++i) m[i]=SIG1(m[i-2])+m[i-7]+SIG0(m[i-15])+m[i-16];
  a=state[0]; b=state[1]; c=state[2]; d=state[3]; e=state[4]; f=state[5]; g=state[6]; h=state[7];
  for (i=0;i<64;++i) { t1=h+EP1(e)+CH(e,f,g)+k[i]+m[i]; t2=EP0(a)+MAJ(a,b,c); h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2; }
  state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d; state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}
static void sha256_transform(sha256_ctx *ctx, const uint8_t data[64]) { sha256_transform_state(ctx->state, data); }
static void sha256_init(sha256_ctx *ctx) { ctx->datalen=0; ctx->bitlen=0; memcpy(ctx->state,H0,32); }
static void sha256_update(sha256_ctx *ctx, const uint8_t data[], size_t len) { for(size_t i=0;i<len;++i){ctx->data[ctx->datalen++]=data[i]; if(ctx->datalen==64){sha256_transform(ctx,ctx->data);ctx->bitlen+=512;ctx->datalen=0;}} }
static void sha256_final(sha256_ctx *ctx, uint8_t hash[32]) { uint32_t i=ctx->datalen; ctx->data[i++]=0x80; if(ctx->datalen<56){while(i<56)ctx->data[i++]=0;}else{while(i<64)ctx->data[i++]=0;sha256_transform(ctx,ctx->data);memset(ctx->data,0,56);} ctx->bitlen+=ctx->datalen*8; for(int s=0;s<8;s++) ctx->data[63-s]=(uint8_t)(ctx->bitlen>>(8*s)); sha256_transform(ctx,ctx->data); for(i=0;i<4;++i){hash[i]=(ctx->state[0]>>(24-i*8))&255;hash[i+4]=(ctx->state[1]>>(24-i*8))&255;hash[i+8]=(ctx->state[2]>>(24-i*8))&255;hash[i+12]=(ctx->state[3]>>(24-i*8))&255;hash[i+16]=(ctx->state[4]>>(24-i*8))&255;hash[i+20]=(ctx->state[5]>>(24-i*8))&255;hash[i+24]=(ctx->state[6]>>(24-i*8))&255;hash[i+28]=(ctx->state[7]>>(24-i*8))&255;} }
static void nonce_le(uint64_t nonce, uint8_t out[8]) { for(int i=0;i<8;++i){out[i]=(uint8_t)(nonce&255u); nonce >>= 8;} }
static uint64_t now_ns(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return (uint64_t)ts.tv_sec*1000000000ull+(uint64_t)ts.tv_nsec; }
static int hexval(char c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; }
static int parse_hex(const char *hex, uint8_t *out, size_t *out_len){ size_t n=strlen(hex); if(n%2||n/2>55)return -1; for(size_t i=0;i<n/2;i++){int hi=hexval(hex[i*2]),lo=hexval(hex[i*2+1]); if(hi<0||lo<0)return -1; out[i]=(uint8_t)((hi<<4)|lo);} *out_len=n/2; return 0; }
static void digest_singleblock(const uint8_t *prefix, size_t prefix_len, uint64_t nonce, uint8_t hash[32]){
  uint8_t block[64]; uint32_t state[8]; memset(block,0,64); memcpy(block,prefix,prefix_len); nonce_le(nonce, block+prefix_len); size_t len=prefix_len+8; block[len]=0x80; uint64_t bitlen=(uint64_t)len*8; for(int s=0;s<8;s++) block[63-s]=(uint8_t)(bitlen>>(8*s)); memcpy(state,H0,32); sha256_transform_state(state, block); for(int i=0;i<4;i++){hash[i]=(state[0]>>(24-i*8))&255;hash[i+4]=(state[1]>>(24-i*8))&255;hash[i+8]=(state[2]>>(24-i*8))&255;hash[i+12]=(state[3]>>(24-i*8))&255;hash[i+16]=(state[4]>>(24-i*8))&255;hash[i+20]=(state[5]>>(24-i*8))&255;hash[i+24]=(state[6]>>(24-i*8))&255;hash[i+28]=(state[7]>>(24-i*8))&255;}
}
typedef struct { const char *mode; uint8_t prefix[55]; size_t prefix_len; uint64_t iters; uint64_t start; atomic_uint_fast64_t *sink; } arg_t;
static void *worker(void *p){ arg_t *a=(arg_t*)p; uint8_t hash[32], input[80], nb[8]; uint64_t acc=0; sha256_ctx prefix_ctx; if(!strcmp(a->mode,"prefix")){sha256_init(&prefix_ctx);sha256_update(&prefix_ctx,a->prefix,a->prefix_len);} memcpy(input,a->prefix,a->prefix_len); for(uint64_t i=0;i<a->iters;i++){ uint64_t nonce=a->start+i; if(!strcmp(a->mode,"original")){ nonce_le(nonce,nb); memcpy(input+a->prefix_len,nb,8); sha256_ctx ctx; sha256_init(&ctx); sha256_update(&ctx,input,a->prefix_len+8); sha256_final(&ctx,hash); } else if(!strcmp(a->mode,"prefix")){ nonce_le(nonce,nb); sha256_ctx ctx=prefix_ctx; sha256_update(&ctx,nb,8); sha256_final(&ctx,hash); } else { digest_singleblock(a->prefix,a->prefix_len,nonce,hash); } acc += hash[31]; } atomic_fetch_add(a->sink,acc); return NULL; }
int main(int argc,char**argv){ const char *mode="singleblock", *prefix_hex="00112233445566778899aabbccddeeff"; int threads=1; uint64_t iters=5000000; uint64_t nonce=12345; int digest=0; for(int i=1;i<argc;i++){ if(!strcmp(argv[i],"--mode")&&i+1<argc)mode=argv[++i]; else if(!strcmp(argv[i],"--prefix")&&i+1<argc)prefix_hex=argv[++i]; else if(!strcmp(argv[i],"--threads")&&i+1<argc)threads=atoi(argv[++i]); else if(!strcmp(argv[i],"--iters")&&i+1<argc)iters=strtoull(argv[++i],0,10); else if(!strcmp(argv[i],"--nonce")&&i+1<argc)nonce=strtoull(argv[++i],0,10); else if(!strcmp(argv[i],"--digest"))digest=1; }
  uint8_t prefix[55], hash[32]; size_t prefix_len=0; if(parse_hex(prefix_hex,prefix,&prefix_len)){fprintf(stderr,"bad prefix\n");return 2;} if(digest){ if(!strcmp(mode,"singleblock")) digest_singleblock(prefix,prefix_len,nonce,hash); else { uint8_t input[80],nb[8]; memcpy(input,prefix,prefix_len); nonce_le(nonce,nb); memcpy(input+prefix_len,nb,8); sha256_ctx ctx; sha256_init(&ctx); sha256_update(&ctx,input,prefix_len+8); sha256_final(&ctx,hash);} for(int i=0;i<32;i++)printf("%02x",hash[i]); printf("\n"); return 0; }
  pthread_t *th=calloc(threads,sizeof(*th)); arg_t *args=calloc(threads,sizeof(*args)); atomic_uint_fast64_t sink=0; uint64_t per=iters/(uint64_t)threads; uint64_t rem=iters%(uint64_t)threads; uint64_t pos=0; uint64_t t0=now_ns(); for(int i=0;i<threads;i++){args[i].mode=mode;memcpy(args[i].prefix,prefix,prefix_len);args[i].prefix_len=prefix_len;args[i].iters=per+(i<(int)rem);args[i].start=pos;args[i].sink=&sink;pos+=args[i].iters;pthread_create(&th[i],0,worker,&args[i]);} for(int i=0;i<threads;i++)pthread_join(th[i],0); uint64_t t1=now_ns(); double sec=(double)(t1-t0)/1e9; printf("{\"mode\":\"%s\",\"threads\":%d,\"iters\":\"%" PRIu64 "\",\"sec\":%.6f,\"mhps\":%.3f,\"sink\":\"%" PRIuFAST64 "\"}\n",mode,threads,iters,sec,(double)iters/sec/1e6,atomic_load(&sink)); free(th); free(args); return 0; }
