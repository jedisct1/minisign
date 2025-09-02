
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__)) || defined(__HAIKU__)
#    include <fcntl.h>
#    include <sys/stat.h>
#    include <sys/types.h>
#elif defined(_WIN32)
#    include <direct.h>
#endif

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef LIBZODIUM
#    include "libzodium/sodium.h"
#else
#    include <sodium.h>
#endif

#include "base64.h"
#include "helpers.h"

uint64_t
le64_load(const unsigned char *p)
{
    return ((uint64_t) (p[0])) | ((uint64_t) (p[1]) << 8) | ((uint64_t) (p[2]) << 16) |
           ((uint64_t) (p[3]) << 24) | ((uint64_t) (p[4]) << 32) | ((uint64_t) (p[5]) << 40) |
           ((uint64_t) (p[6]) << 48) | ((uint64_t) (p[7]) << 56);
}

void
le64_store(unsigned char *p, uint64_t x)
{
    p[0] = (unsigned char) x;
    p[1] = (unsigned char) (x >> 8);
    p[2] = (unsigned char) (x >> 16);
    p[3] = (unsigned char) (x >> 24);
    p[4] = (unsigned char) (x >> 32);
    p[5] = (unsigned char) (x >> 40);
    p[6] = (unsigned char) (x >> 48);
    p[7] = (unsigned char) (x >> 56);
}

void
exit_err(const char *msg)
{
    perror(msg == NULL ? "" : msg);
    exit(2);
}

void
exit_msg(const char *msg)
{
    fprintf(stderr, "%s\n", msg);
    exit(2);
}

void *
xmalloc(size_t size)
{
    void *pnt;

    if ((pnt = malloc(size)) == NULL) {
        exit_err("malloc()");
    }
    return pnt;
}

char *
xstrdup(const char *str)
{
    char *clone;

    if ((clone = strdup(str)) == NULL) {
        exit_err("strdup()");
    }
    return clone;
}

void *
xsodium_malloc(size_t size)
{
    void *pnt;

    if ((pnt = sodium_malloc(size)) == NULL) {
        exit_err("sodium_malloc()");
    }
    return pnt;
}

void
xor_buf(unsigned char *dst, const unsigned char *src, size_t len)
{
    size_t i;

    for (i = (size_t) 0U; i < len; i++) {
        dst[i] ^= src[i];
    }
}

int
xfprintf(FILE *fp, const char *format, ...)
{
    char   *out;
    size_t  out_maxlen = 4096U;
    int     len;
    va_list va;

    va_start(va, format);
    out = xsodium_malloc(out_maxlen);
    len = vsnprintf(out, out_maxlen, format, va);
    if (len < 0 || len >= (int) out_maxlen) {
        va_end(va);
        exit_msg("xfprintf() overflow");
    }
    va_end(va);
    if (fwrite(out, (size_t) len, 1U, fp) != 1U) {
        sodium_free(out);
        exit_err("fwrite()");
    }
    sodium_free(out);

    return 0;
}

int
xfput_b64(FILE *fp, const unsigned char *bin, size_t bin_len)
{
    const size_t b64_maxlen = (bin_len + 2) * 4 / 3 + 1;
    char        *b64;

    b64 = xsodium_malloc(b64_maxlen);
    if (bin_to_b64(b64, bin, b64_maxlen, bin_len) == NULL) {
        sodium_free(b64);
        abort();
    }
    xfprintf(fp, "%s\n", b64);
    sodium_free(b64);

    return 0;
}

int
xfclose(FILE *fp)
{
    if (fp == NULL) {
        abort();
    }
    if (fclose(fp) != 0) {
        exit_err("fclose()");
    }
    return 0;
}

int
trim(char *str)
{
    size_t i = strlen(str);
    int    t = 0;

    while (i-- > (size_t) 0U) {
        if (str[i] == '\n') {
            str[i] = 0;
            t      = 1;
        } else if (str[i] == '\r') {
            str[i] = 0;
        }
    }
    return t;
}

const char *
file_basename(const char *file)
{
    char *ptr;

    if ((ptr = strrchr(file, DIR_SEP)) != NULL) {
        return ptr + 1;
    }
    return file;
}

FILE *
fopen_create_useronly(const char *file)
{
#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__)) || defined(__HAIKU__)
    int fd;

    if ((fd = open(file, O_CREAT | O_TRUNC | O_WRONLY, (mode_t) 0600)) == -1) {
        return NULL;
    }
    return fdopen(fd, "w");
#else
    return fopen(file, "w");
#endif
}

int
basedir_create_useronly(const char *file)
{
    const char *basename;
    char       *dir;
    int         ret = -1;

    dir      = xstrdup(file);
    basename = file_basename(dir);
    if (basename == dir) {
        free(dir);
        return 0;
    }
    dir[basename - dir - 1] = 0;

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__)) || defined(__HAIKU__)
    if (*dir == 0 || mkdir(dir, 0700) == 0 || errno == EEXIST) {
        ret = 0;
    }
#elif defined(_WIN32)
    if (*dir == 0 || _mkdir(dir) == 0 || errno == EEXIST) {
        ret = 0;
    }
#endif
    free(dir);
    return ret;
}

char *
get_home_dir(void)
{
    char *dir;
#ifdef _WIN32
    const char *hd;
    const char *hp;
#endif

    if ((dir = getenv("HOME")) != NULL) {
        return xstrdup(dir);
    }
#ifdef _WIN32
    if ((dir = getenv("USERPROFILE")) != NULL) {
        return xstrdup(dir);
    }
    if ((hd = getenv("HOMEDRIVE")) != NULL && (hp = getenv("HOMEPATH")) != NULL) {
        if (asprintf(&dir, "%s%s", hd, hp) < 0) {
            exit_err("asprintf()");
        }
        return dir;
    }
#endif
    return NULL;
}
