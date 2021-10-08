
#ifndef BASE64_H
#define BASE64_H

#include <stddef.h>

unsigned char *b64_to_bin(unsigned char *const bin, const char *b64, size_t bin_maxlen,
                          size_t b64_len, size_t *const bin_len_p);

char *bin_to_b64(char *const b64, const unsigned char *bin, size_t b64_maxlen, size_t bin_len);

#define B64_MAX_LEN_FROM_BIN_LEN(X) (((X) + 2) / 3 * 4 + 1)
#define BIN_MAX_LEN_FROM_B64_LEN(X) ((X) / 4 * 3)

#endif
