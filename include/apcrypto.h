#ifndef APCRYPTO_H
#define APCRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define AP_SHA256_DIGEST_LEN 32u
#define AP_SHA256_BLOCK_LEN 64u

typedef struct ap_sha256 {
  uint32_t state[8];
  uint64_t bits;
  uint8_t block[AP_SHA256_BLOCK_LEN];
  size_t used;
} ap_sha256;

#ifdef __cplusplus
extern "C" {
#endif

void ap_sha256_init(ap_sha256 *ctx);
void ap_sha256_update(ap_sha256 *ctx, const void *data, size_t len);
void ap_sha256_final(ap_sha256 *ctx, uint8_t out[AP_SHA256_DIGEST_LEN]);
void ap_hmac_sha256(const void *key, size_t key_len, const void *data, size_t data_len,
                    uint8_t out[AP_SHA256_DIGEST_LEN]);
int ap_constant_time_eq(const void *a, const void *b, size_t len);

#ifdef __cplusplus
}
#endif

#endif
