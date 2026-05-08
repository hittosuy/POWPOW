#include <openssl/sha.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
static uint64_t now_ns(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return (uint64_t)ts.tv_sec*1000000000ull+ts.tv_nsec;}
static void nonce_le(uint64_t nonce,unsigned char*out){for(int i=0;i<8;i++){out[i]=nonce&255;nonce>>=8;}}
static int hexval(char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;}
static int parse_hex(const char*hex,unsigned char*out,size_t*len){size_t n=strlen(hex);if(n%2||n/2>64)return-1;for(size_t i=0;i<n/2;i++){int hi=hexval(hex[i*2]),lo=hexval(hex[i*2+1]);if(hi<0||lo<0)return-1;out[i]=(hi<<4)|lo;}*len=n/2;return 0;}
typedef struct{unsigned char prefix[64];size_t prefix_len;uint64_t start,iters;atomic_uint_fast64_t*sink;} arg_t;
static void*worker(void*p){arg_t*a=p;unsigned char input[80],hash[32];memcpy(input,a->prefix,a->prefix_len);uint64_t acc=0;for(uint64_t i=0;i<a->iters;i++){nonce_le(a->start+i,input+a->prefix_len);SHA256(input,a->prefix_len+8,hash);acc+=hash[31];}atomic_fetch_add(a->sink,acc);return 0;}
int main(int argc,char**argv){const char*prefix_hex="00112233445566778899aabbccddeeff";int threads=1,digest=0;uint64_t iters=10000000,nonce=12345;for(int i=1;i<argc;i++){if(!strcmp(argv[i],"--threads"))threads=atoi(argv[++i]);else if(!strcmp(argv[i],"--iters"))iters=strtoull(argv[++i],0,10);else if(!strcmp(argv[i],"--prefix"))prefix_hex=argv[++i];else if(!strcmp(argv[i],"--nonce"))nonce=strtoull(argv[++i],0,10);else if(!strcmp(argv[i],"--digest"))digest=1;}unsigned char prefix[64],hash[32],input[80];size_t prefix_len;if(parse_hex(prefix_hex,prefix,&prefix_len))return 2;if(digest){memcpy(input,prefix,prefix_len);nonce_le(nonce,input+prefix_len);SHA256(input,prefix_len+8,hash);for(int i=0;i<32;i++)printf("%02x",hash[i]);puts("");return 0;}pthread_t*th=calloc(threads,sizeof(*th));arg_t*args=calloc(threads,sizeof(*args));atomic_uint_fast64_t sink=0;uint64_t per=iters/threads,rem=iters%threads,pos=0,t0=now_ns();for(int i=0;i<threads;i++){memcpy(args[i].prefix,prefix,prefix_len);args[i].prefix_len=prefix_len;args[i].start=pos;args[i].iters=per+(i<rem);args[i].sink=&sink;pos+=args[i].iters;pthread_create(&th[i],0,worker,&args[i]);}for(int i=0;i<threads;i++)pthread_join(th[i],0);double sec=(now_ns()-t0)/1e9;printf("{\"mode\":\"openssl\",\"threads\":%d,\"iters\":\"%lu\",\"sec\":%.6f,\"mhps\":%.3f,\"sink\":\"%lu\"}\n",threads,iters,sec,iters/sec/1e6,(uint64_t)atomic_load(&sink));}
