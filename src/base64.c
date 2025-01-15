
#include <stddef.h>
#include <stdint.h>

#include "base64.h"

unsigned char *
b64_to_bin(unsigned char *const bin, const char *b64, size_t bin_maxlen, size_t b64_len,
           size_t *const bin_len_p)
{
#define REV64_EOT  128U
#define REV64_NONE 64U
#define REV64_PAD  '='

    static const unsigned char rev64chars[256] = {
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, 62U,        REV64_NONE, REV64_NONE, REV64_NONE, 63U,        52U,
        53U,        54U,        55U,        56U,        57U,        58U,        59U,
        60U,        61U,        REV64_NONE, REV64_NONE, REV64_NONE, REV64_EOT,  REV64_NONE,
        REV64_NONE, REV64_NONE, 0U,         1U,         2U,         3U,         4U,
        5U,         6U,         7U,         8U,         9U,         10U,        11U,
        12U,        13U,        14U,        15U,        16U,        17U,        18U,
        19U,        20U,        21U,        22U,        23U,        24U,        25U,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, 26U,
        27U,        28U,        29U,        30U,        31U,        32U,        33U,
        34U,        35U,        36U,        37U,        38U,        39U,        40U,
        41U,        42U,        43U,        44U,        45U,        46U,        47U,
        48U,        49U,        50U,        51U,        REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE,
        REV64_NONE, REV64_NONE, REV64_NONE, REV64_NONE
    };
    const unsigned char *b64_u = (const unsigned char *) b64;
    unsigned char       *bin_w = bin;
    unsigned char        mask  = 0U;
    unsigned char        t0 = 0, t1 = 0, t2 = 0, t3 = 0;
    uint32_t             t = 0;
    size_t               i;

    if (b64_len % 4U != 0U || (i = b64_len / 4U) <= 0U ||
        bin_maxlen <
            i * 3U - (b64_u[b64_len - 1U] == REV64_PAD) - (b64_u[b64_len - 2U] == REV64_PAD)) {
        return NULL;
    }
    while (i-- > 0U) {
        t0   = rev64chars[*b64_u++];
        t1   = rev64chars[*b64_u++];
        t2   = rev64chars[*b64_u++];
        t3   = rev64chars[*b64_u++];
        t    = t3 | ((uint32_t) t2 << 6) | ((uint32_t) t1 << 12) | ((uint32_t) t0 << 18);
        mask = t0 | t1 | t2 | t3;
        if ((mask & (REV64_NONE | REV64_EOT)) != 0U) {
            if ((mask & REV64_NONE) != 0U || i > 0U) {
                return NULL;
            }
            break;
        }
        *bin_w++ = (unsigned char) (t >> 16);
        *bin_w++ = (unsigned char) (t >> 8);
        *bin_w++ = (unsigned char) t;
    }
    if ((mask & REV64_EOT) != 0U) {
        if (((t0 | t1) & REV64_EOT) != 0U || t3 != REV64_EOT) {
            return NULL;
        }
        *bin_w++ = (unsigned char) (t >> 16);
        if (t2 != REV64_EOT) {
            *bin_w++ = (unsigned char) (t >> 8);
        }
    }
    if (bin_len_p != NULL) {
        *bin_len_p = (size_t) (bin_w - bin);
    }
    return bin;
}

char *
bin_to_b64(char *const b64, const unsigned char *bin, size_t b64_maxlen, size_t bin_len)
{
#define B64_PAD '='

    static const char b64chars[64] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char *b64_w = b64;

    if (b64_maxlen < (((bin_len + 2U) / 3U) * 4U + 1U)) {
        return NULL;
    }
    while (bin_len > (size_t) 2U) {
        const unsigned char t0 = (unsigned char) *bin++;
        const unsigned char t1 = (unsigned char) *bin++;
        const unsigned char t2 = (unsigned char) *bin++;

        *b64_w++ = b64chars[(t0 >> 2) & 63];
        *b64_w++ = b64chars[((t0 << 4) & 48) | ((t1 >> 4) & 15)];
        *b64_w++ = b64chars[((t1 << 2) & 60) | ((t2 >> 6) & 3)];
        *b64_w++ = b64chars[t2 & 63];
        bin_len -= (size_t) 3U;
    }
    if (bin_len > (size_t) 0U) {
        const unsigned char t0 = (unsigned char) bin[0];

        *b64_w++ = b64chars[(t0 >> 2) & 63];
        if (bin_len == 1U) {
            *b64_w++ = b64chars[((t0 << 4) & 48)];
            *b64_w++ = B64_PAD;
        } else {
            const unsigned char t1 = (unsigned char) bin[1];

            *b64_w++ = b64chars[((t0 << 4) & 48) | ((t1 >> 4) & 15)];
            *b64_w++ = b64chars[((t1 << 2) & 60)];
        }
        *b64_w++ = B64_PAD;
    }
    *b64_w = 0;

    return b64;
}
