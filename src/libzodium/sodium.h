#pragma once

#include <stddef.h>

int sodium_init(void) __attribute__((warn_unused_result));
;

void sodium_memzero(void* const pnt, const size_t len);

void randombytes_buf(void* const buf, const size_t size) __attribute__((nonnull));

void* sodium_malloc(const size_t size) __attribute__((malloc));

void sodium_free(void* ptr);

#define crypto_pwhash_scryptsalsa208sha256_SALTBYTES          32U
#define crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN       32768U
#define crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN       16777216U
#define crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE 33554432U
#define crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE 1073741824U

int crypto_pwhash_scryptsalsa208sha256(unsigned char* const       out,
                                       unsigned long long         outlen,
                                       const char* const          passwd,
                                       unsigned long long         passwdlen,
                                       const unsigned char* const salt,
                                       unsigned long long         opslimit,
                                       size_t memlimit) __attribute__((warn_unused_result))
__attribute__((nonnull));

typedef struct crypto_generichash_state {
    unsigned char opaque[512];
} crypto_generichash_state;

#define crypto_generichash_BYTES_MAX 64U
#define crypto_generichash_BYTES     32U

int crypto_generichash_init(crypto_generichash_state* state, const unsigned char* key,
                            const size_t keylen, const size_t outlen) __attribute__((nonnull(1)));

int crypto_generichash_update(crypto_generichash_state* state,
                              const unsigned char*      in,
                              unsigned long long        inlen) __attribute__((nonnull(1)));

int crypto_generichash_final(crypto_generichash_state* state, unsigned char* out,
                             const size_t outlen) __attribute__((nonnull));

#define crypto_sign_SECRETKEYBYTES 64
#define crypto_sign_PUBLICKEYBYTES 32
#define crypto_sign_BYTES          64

int crypto_sign_keypair(unsigned char* pk, unsigned char* sk) __attribute__((nonnull));

int crypto_sign_detached(unsigned char* sig, unsigned long long* siglen_p, const unsigned char* m,
                         unsigned long long mlen, const unsigned char* sk)
    __attribute__((nonnull(1, 5)));

int crypto_sign_verify_detached(const unsigned char* sig,
                                const unsigned char* m,
                                unsigned long long   mlen,
                                const unsigned char* pk) __attribute__((warn_unused_result))
__attribute__((nonnull(1, 4)));