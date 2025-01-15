
#ifndef HELPERS_H
#define HELPERS_H 1

#include <stdint.h>
#include <stdio.h>

#if !defined(__GNUC__) && !defined(__attribute__)
#    define __attribute__(X)
#endif
#ifdef _WIN32
#    define DIR_SEP '\\'
#else
#    define DIR_SEP '/'
#endif

uint64_t le64_load(const unsigned char *p);

void le64_store(unsigned char *p, uint64_t x);

void exit_err(const char *msg) __attribute__((noreturn));

void exit_msg(const char *msg) __attribute__((noreturn));

void *xmalloc(size_t size);

char *xstrdup(const char *str);

void *xsodium_malloc(size_t size);

void xor_buf(unsigned char *dst, const unsigned char *src, size_t len);

int xfput_b64(FILE *fp, const unsigned char *bin, size_t bin_len);

int xfprintf(FILE *fp, const char *format, ...) __attribute__((format(printf, 2, 3)));

int xfclose(FILE *fp);

int trim(char *str);

const char *file_basename(const char *file);

FILE *fopen_create_useronly(const char *file);

int basedir_create_useronly(const char *file);

char *get_home_dir(void);

#endif
