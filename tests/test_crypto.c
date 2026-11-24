#define _POSIX_C_SOURCE 200809L
#include "apcrypto.h"
#include "apabi.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

static void check(bool condition, const char *name) {
  if (!condition) {
    fprintf(stderr, "crypto test fail: %s\n", name);
    ++failures;
  }
}

static void check_sha(const char *input, const char *expected, const char *name) {
  uint8_t digest[AP_SHA256_DIGEST_LEN];
  char hex[AP_SHA256_DIGEST_LEN * 2u + 1u];
  ap_sha256 ctx;

  ap_sha256_init(&ctx);
  ap_sha256_update(&ctx, input, strlen(input));
  ap_sha256_final(&ctx, digest);
  check(ap_hex_encode(digest, sizeof(digest), hex, sizeof(hex)) == AP_OK, name);
  check(strcmp(hex, expected) == 0, name);
}

static void check_hmac(const void *key, size_t key_len, const char *data, const char *expected,
                       const char *name) {
  uint8_t digest[AP_SHA256_DIGEST_LEN];
  char hex[AP_SHA256_DIGEST_LEN * 2u + 1u];

  ap_hmac_sha256(key, key_len, data, strlen(data), digest);
  check(ap_hex_encode(digest, sizeof(digest), hex, sizeof(hex)) == AP_OK, name);
  check(strcmp(hex, expected) == 0, name);
}

int main(void) {
  uint8_t ipad_key[20];
  uint8_t long_key[100];
  uint8_t first[AP_SHA256_DIGEST_LEN];
  uint8_t second[AP_SHA256_DIGEST_LEN];
  size_t i;

  check_sha("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "sha256 empty");
  check_sha("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "sha256 abc");
  check_sha("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            "sha256 multi block");

  memset(ipad_key, 0x0b, sizeof(ipad_key));
  check_hmac(ipad_key, sizeof(ipad_key), "Hi There",
             "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
             "hmac rfc4231 case 1");
  check_hmac("Jefe", 4u, "what do ya want for nothing?",
             "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
             "hmac rfc4231 case 2");

  for (i = 0u; i < sizeof(long_key); ++i) long_key[i] = (uint8_t)i;
  ap_hmac_sha256(long_key, sizeof(long_key), "abc", 3u, first);
  ap_hmac_sha256(long_key, 32u, "abc", 3u, second);
  check(!ap_constant_time_eq(first, second, sizeof(first)), "long key is hashed");

  check(ap_constant_time_eq("ap", "ap", 2u) == 1, "constant time equal");
  check(ap_constant_time_eq("ap", "ax", 2u) == 0, "constant time mismatch");
  check(strcmp(ap_status_name(AP_ERR_AUTH), "authentication_failed") == 0, "auth status name");
  check(strcmp(ap_status_name(AP_ERR_REPLAY), "replay_rejected") == 0, "replay status name");
  check(strcmp(ap_status_name(AP_ERR_SEQUENCE), "sequence_rejected") == 0, "sequence status name");

  printf("crypto tests: %s\n", failures == 0 ? "ok" : "failed");
  return failures == 0 ? 0 : 1;
}
