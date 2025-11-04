#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define ROTR(x, n) ((x >> n) | (x << (64 - n)))
#define CH(x, y, z) ((x & y) ^ ((~x) & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define S0(x) (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define S1(x) (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))
#define s0(x) (ROTR(x, 1) ^ ROTR(x, 8) ^ (x >> 7))
#define s1(x) (ROTR(x, 19) ^ ROTR(x, 61) ^ (x >> 6))

// vaules taken from https://en.wikipedia.org/wiki/SHA-2
static uint64_t K[80] = {
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 
            0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe, 
            0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 
            0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab, 
            0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 
            0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 
            0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, 
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 
            0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 
            0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 
            0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c, 
            0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 
            0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 
            0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

typedef struct {
  uint64_t h[8];
  uint8_t buffer[128];
  size_t buffer_len;
  uint64_t bitlen_high;
  uint64_t bitlen_low;
} SHA512_CTX;

void sha512_init(SHA512_CTX *ctx) {
  ctx->h[0] = 0x6a09e667f3bcc908;
  ctx->h[1] = 0xbb67ae8584caa73b;
  ctx->h[2] = 0x3c6ef372fe94f82b;
  ctx->h[3] = 0xa54ff53a5f1d36f1;
  ctx->h[4] = 0x510e527fade682d1;
  ctx->h[5] = 0x9b05688c2b3e6c1f;
  ctx->h[6] = 0x1f83d9abfb41bd6b;
  ctx->h[7] = 0x5be0cd19137e2179;

  ctx->buffer_len = 0;
  ctx->bitlen_high = 0;
  ctx->bitlen_low = 0;
}

void sha512_transform(SHA512_CTX *ctx, const uint8_t *data) {
  uint64_t W[80];

  for(size_t t = 0; t < 16; ++t) {
    W[t] = ((uint64_t)data[t * 8 + 0] << 56) | 
           ((uint64_t)data[t * 8 + 1] << 48) |
           ((uint64_t)data[t * 8 + 2] << 40) |
           ((uint64_t)data[t * 8 + 3] << 32) |
           ((uint64_t)data[t * 8 + 4] << 24) |
           ((uint64_t)data[t * 8 + 5] << 16) |
           ((uint64_t)data[t * 8 + 6] << 8) |
           ((uint64_t)data[t * 8 + 7]);
  }

  for(size_t t = 16; t < 80; ++t) {
    W[t] = s1(W[t-2]) + W[t-7] + s0(W[t-15]) + W[t-16];
  }

  uint64_t a = ctx->h[0];
  uint64_t b = ctx->h[1];
  uint64_t c = ctx->h[2];
  uint64_t d = ctx->h[3];
  uint64_t e = ctx->h[4];
  uint64_t f = ctx->h[5];
  uint64_t g = ctx->h[6];
  uint64_t h = ctx->h[7];

  for(size_t t = 0; t < 80; ++t) {
    uint64_t temp1 = h + S1(e) + CH(e, f, g) + K[t] + W[t];
    uint64_t temp2 = S0(a) + MAJ(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  ctx->h[0] += a;
  ctx->h[1] += b;
  ctx->h[2] += c;
  ctx->h[3] += d;
  ctx->h[4] += e;
  ctx->h[5] += f;
  ctx->h[6] += g;
  ctx->h[7] += h;
}

void sha512_update(SHA512_CTX *ctx, const uint8_t *data, size_t len) {
  uint64_t prev_low = ctx->bitlen_low;
  ctx->bitlen_low += len * 8;

  if (ctx->bitlen_low < prev_low) {
      ctx->bitlen_high++;
  }

  size_t i = 0;
  while(i < len) {
    size_t space = 128 - ctx->buffer_len;
    size_t copy_len = (len - i < space) ? (len - i) : space;

    memcpy(ctx->buffer + ctx->buffer_len, data + i, copy_len);
    ctx->buffer_len += copy_len;
    i += copy_len;

    if (ctx->buffer_len == 128) {
      sha512_transform(ctx, ctx->buffer);
      ctx->buffer_len = 0;
    }
  }
}

void sha512_final(SHA512_CTX *ctx, uint8_t *digest) {
  ctx->buffer[ctx->buffer_len++] = 0x80;

  if(ctx->buffer_len > 112) {
    while(ctx->buffer_len < 128) {
      ctx->buffer[ctx->buffer_len++] = 0;
    }

    sha512_transform(ctx, ctx->buffer);
    ctx->buffer_len = 0;
  }

  while(ctx->buffer_len < 112) {
    ctx->buffer[ctx->buffer_len++] = 0;
  }

  for(size_t i = 0; i < 8; ++i) {
    ctx->buffer[112 + i] = (ctx->bitlen_high >> (56 - 8 * i)) & 0xFF;
    ctx->buffer[120 + i] = (ctx->bitlen_low >> (56 - 8 * i)) & 0xFF;
  }

  sha512_transform(ctx, ctx->buffer);

  for(size_t i = 0; i < 8; ++i) {
    digest[i * 8 + 0] = (ctx->h[i] >> 56) & 0xFF;
    digest[i * 8 + 1] = (ctx->h[i] >> 48) & 0xFF;
    digest[i * 8 + 2] = (ctx->h[i] >> 40) & 0xFF;
    digest[i * 8 + 3] = (ctx->h[i] >> 32) & 0xFF;
    digest[i * 8 + 4] = (ctx->h[i] >> 24) & 0xFF;
    digest[i * 8 + 5] = (ctx->h[i] >> 16) & 0xFF;
    digest[i * 8 + 6] = (ctx->h[i] >> 8) & 0xFF;
    digest[i * 8 + 7] = (ctx->h[i]) & 0xFF;
  }
}

#define CHUNK_SIZE 1024

int main() {
  uint8_t message[CHUNK_SIZE];
  uint8_t digest[64];
  SHA512_CTX ctx;
  sha512_init(&ctx);

  size_t bytes_read;

  while ((bytes_read = fread(message, 1, CHUNK_SIZE, stdin)) > 0) {
    if (feof(stdin) && bytes_read > 0 && message[bytes_read-1] == '\n') {
      sha512_update(&ctx, message, bytes_read - 1);
    } else {
      sha512_update(&ctx, message, bytes_read);
    }
  }

  sha512_final(&ctx, digest);

  for (int i = 0; i < 64; ++i) {
      printf("%02x", digest[i]);
  }
  printf("\n");

  return 0;
}

