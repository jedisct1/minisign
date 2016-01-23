#define _GNU_SOURCE

#include <assert.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sodium.h>

#include "base64.h"
#include "get_line.h"
#include "helpers.h"
#include "minisign.h"

#ifndef VERIFY_ONLY
static const char *getopt_options = "GSVHhc:m:oP:p:qQs:t:vx:";
#else
static const char *getopt_options = "Vhm:oP:p:qQvx:";
#endif

static void usage(void) __attribute__((noreturn));

static void
usage(void)
{
    puts("Usage:\n"
#ifndef VERIFY_ONLY
         "minisign -G [-p pubkey] [-s seckey]\n"
         "minisign -S [-H] [-x sigfile] [-s seckey] [-c untrusted_comment] [-t trusted_comment] -m file\n"
#endif
         "minisign -V [-x sigfile] [-p pubkeyfile | -P pubkey] [-o] [-q] -m file\n"
         "\n"
#ifndef VERIFY_ONLY
         "-G                generate a new key pair\n"
         "-S                sign a file\n"
#endif
         "-V                verify that a signature is valid for a given file\n"
         "-m <file>         file to sign/verify\n"
         "-o                combined with -V, output the file content after verification\n"
#ifndef VERIFY_ONLY
         "-H                combined with -S, pre-hash in order to sign large files\n"
#endif
         "-p <pubkeyfile>   public key file (default: ./minisign.pub)\n"
         "-P <pubkey>       public key, as a base64 string\n"
#ifndef VERIFY_ONLY
         "-s <seckey>       secret key file (default: ./minisign.key)\n"
#endif
         "-x <sigfile>      signature file (default: <file>.minisig)\n"
#ifndef VERIFY_ONLY
         "-c <comment>      add a one-line untrusted comment\n"
         "-t <comment>      add a one-line trusted comment\n"
#endif
         "-q                quiet mode, suppress output\n"
         "-Q                pretty quiet mode, only print the trusted comment\n"
         "-v                display version number\n"
        );
    exit(2);
}

static unsigned char *
message_load_hashed(size_t *message_len, const char *message_file)
{
    crypto_generichash_state  hs;
    unsigned char             buf[65536U];
    unsigned char            *message;
    FILE                     *fp;
    size_t                    n;

    if ((fp = fopen(message_file, "rb")) == NULL) {
        exit_err(message_file);
    }
    crypto_generichash_init(&hs, NULL, 0U, crypto_generichash_BYTES_MAX);
    while ((n = fread(buf, 1U, sizeof buf, fp)) > 0U) {
        crypto_generichash_update(&hs, buf, n);
    }
    if (!feof(fp)) {
        exit_err(message_file);
    }
    xfclose(fp);
    message = xmalloc(crypto_generichash_BYTES_MAX);
    crypto_generichash_final(&hs, message, crypto_generichash_BYTES_MAX);
    *message_len = crypto_generichash_BYTES_MAX;

    return message;
}

static unsigned char *
message_load(size_t *message_len, const char *message_file, int hashed)
{
    FILE          *fp;
    unsigned char *message;
    off_t          message_len_;

    if (hashed != 0) {
        return message_load_hashed(message_len, message_file);
    }
    if ((fp = fopen(message_file, "rb")) == NULL ||
        fseeko(fp, 0, SEEK_END) != 0 ||
        (message_len_ = ftello(fp)) == (off_t) -1) {
        exit_err(message_file);
    }
    if (hashed == 0 && message_len_ > (off_t) 1L << 30) {
        exit_msg("Data has to be smaller than 1 Gb. Or use the -H option.");
    }
    if ((uintmax_t) message_len_ > (uintmax_t) SIZE_MAX ||
        message_len_ < (off_t) 0) {
        abort();
    }
    message = xmalloc((*message_len = (size_t) message_len_));
    rewind(fp);
    if (*message_len > 0U &&
        fread(message, *message_len, (size_t) 1U, fp) != 1U) {
        exit_err(message_file);
    }
    xfclose(fp);

    return message;
}

static int
output_file(const char *message_file)
{
    unsigned char  buf[65536U];
    FILE          *fp;
    size_t         n;

    if ((fp = fopen(message_file, "rb")) == NULL) {
        exit_err(message_file);
    }
    while ((n = fread(buf, 1U, sizeof buf, fp)) > 0U) {
        if (fwrite(buf, 1U, n, stdout) != n) {
            exit_err(message_file);
        }
    }
    if (!feof(fp) || fflush(stdout) != 0) {
        exit_err(message_file);
    }
    xfclose(fp);

    return 0;
}

static SigStruct *
sig_load(const char *sig_file, unsigned char global_sig[crypto_sign_BYTES],
         int *hashed, char trusted_comment[TRUSTEDCOMMENTMAXBYTES],
         size_t trusted_comment_maxlen)
{
    char       comment[COMMENTMAXBYTES];
    SigStruct *sig_struct;
    FILE      *fp;
    char      *global_sig_s;
    char      *sig_s;
    size_t     global_sig_len;
    size_t     global_sig_s_size;
    size_t     sig_s_size;
    size_t     sig_struct_len;

    if ((fp = fopen(sig_file, "r")) == NULL) {
        exit_err(sig_file);
    }
    if (fgets(comment, (int) sizeof comment, fp) == NULL) {
        exit_err(sig_file);
    }
    if (strncmp(comment, COMMENT_PREFIX, (sizeof COMMENT_PREFIX) - 1U) != 0) {
        exit_msg("Untrusted signature comment should start with "
                 "\"" COMMENT_PREFIX "\"");
    }
    sig_s_size = B64_MAX_LEN_FROM_BIN_LEN(sizeof *sig_struct) + 2U;
    sig_s = xmalloc(sig_s_size);
    if (fgets(sig_s, (int) sig_s_size, fp) == NULL) {
        exit_err(sig_file);
    }
    trim(sig_s);
    if (fgets(trusted_comment, (int) trusted_comment_maxlen, fp) == NULL) {
        exit_err(sig_file);
    }
    if (strncmp(trusted_comment, TRUSTED_COMMENT_PREFIX,
                (sizeof TRUSTED_COMMENT_PREFIX) - 1U) != 0) {
        exit_msg("Trusted signature comment should start with "
                 "\"" TRUSTED_COMMENT_PREFIX "\"");
    }
    memmove(trusted_comment,
            trusted_comment + sizeof TRUSTED_COMMENT_PREFIX - 1U,
            strlen(trusted_comment + sizeof TRUSTED_COMMENT_PREFIX - 1U) + 1U);
    trim(trusted_comment);
    global_sig_s_size = B64_MAX_LEN_FROM_BIN_LEN(crypto_sign_BYTES) + 2U;
    global_sig_s = xmalloc(global_sig_s_size);
    if (fgets(global_sig_s, (int) global_sig_s_size, fp) == NULL) {
        exit_err(sig_file);
    }
    trim(global_sig_s);
    xfclose(fp);

    sig_struct = xmalloc(sizeof *sig_struct);
    if (b64_to_bin((unsigned char *) (void *) sig_struct, sig_s,
                   sizeof *sig_struct, strlen(sig_s),
                   &sig_struct_len) == NULL ||
        sig_struct_len != sizeof *sig_struct) {
        exit_msg("base64 conversion failed - was an actual signature given?");
    }
    free(sig_s);
    if (memcmp(sig_struct->sig_alg, SIGALG, sizeof sig_struct->sig_alg) == 0) {
        *hashed = 0;
    } else if (memcmp(sig_struct->sig_alg, SIGALG_HASHED,
                      sizeof sig_struct->sig_alg) == 0) {
        *hashed = 1;
    } else {
        exit_msg("Unsupported signature algorithm");
    }
    if (b64_to_bin(global_sig, global_sig_s, crypto_sign_BYTES,
                   strlen(global_sig_s), &global_sig_len) == NULL ||
        global_sig_len != crypto_sign_BYTES) {
        exit_msg("base64 conversion failed - was an actual signature given?");
    }
    free(global_sig_s);

    return sig_struct;
}

static PubkeyStruct *
pubkey_load_string(const char *pubkey_s)
{
    PubkeyStruct *pubkey_struct;
    size_t        pubkey_struct_len;

    pubkey_struct = xmalloc(sizeof *pubkey_struct);
    if (b64_to_bin((unsigned char *) (void *) pubkey_struct, pubkey_s,
                   sizeof *pubkey_struct, strlen(pubkey_s),
                   &pubkey_struct_len) == NULL ||
        pubkey_struct_len != sizeof *pubkey_struct) {
        exit_msg("base64 conversion failed - was an actual public key given?");
    }
    if (memcmp(pubkey_struct->sig_alg, SIGALG,
               sizeof pubkey_struct->sig_alg) != 0) {
        exit_msg("Unsupported signature algorithm");
    }
    return pubkey_struct;
}

static PubkeyStruct *
pubkey_load_file(const char *pk_file)
{
    char          pk_comment[COMMENTMAXBYTES];
    PubkeyStruct *pubkey_struct;
    FILE         *fp;
    char         *pubkey_s = NULL;
    size_t        pubkey_s_size;

    if ((fp = fopen(pk_file, "r")) == NULL) {
        exit_err(pk_file);
    }
    if (fgets(pk_comment, (int) sizeof pk_comment, fp) == NULL) {
        exit_err(pk_file);
    }
    pubkey_s_size = B64_MAX_LEN_FROM_BIN_LEN(sizeof *pubkey_struct) + 2U;
    pubkey_s = xmalloc(pubkey_s_size);
    if (fgets(pubkey_s, (int) pubkey_s_size, fp) == NULL) {
        exit_err(pk_file);
    }
    trim(pubkey_s);
    xfclose(fp);
    pubkey_struct = pubkey_load_string(pubkey_s);
    free(pubkey_s);

    return pubkey_struct;
}

static PubkeyStruct *
pubkey_load(const char *pk_file, const char *pubkey_s)
{
    if (pubkey_s != NULL) {
        return pubkey_load_string(pubkey_s);
    } else {
        return pubkey_load_file(pk_file);
    }
}

static void
seckey_chk(unsigned char chk[crypto_generichash_BYTES],
           const SeckeyStruct *seckey_struct)
{
    crypto_generichash_state hs;

    crypto_generichash_init(&hs, NULL, 0U, sizeof seckey_struct->keynum_sk.chk);
    crypto_generichash_update(&hs, seckey_struct->sig_alg,
                              sizeof seckey_struct->sig_alg);
    crypto_generichash_update(&hs, seckey_struct->keynum_sk.keynum,
                              sizeof seckey_struct->keynum_sk.keynum);
    crypto_generichash_update(&hs, seckey_struct->keynum_sk.sk,
                              sizeof seckey_struct->keynum_sk.sk);
    crypto_generichash_final(&hs, chk, sizeof seckey_struct->keynum_sk.chk);
}

#ifndef VERIFY_ONLY
static SeckeyStruct *
seckey_load(const char *sk_file)
{
    char           sk_comment[COMMENTMAXBYTES];
    unsigned char  chk[crypto_generichash_BYTES];
    SeckeyStruct  *seckey_struct;
    FILE          *fp;
    char          *pwd = xsodium_malloc(PASSWORDMAXBYTES);
    char          *seckey_s;
    unsigned char *stream;
    size_t         seckey_s_size;
    size_t         seckey_struct_len;

    if ((fp = fopen(sk_file, "r")) == NULL) {
        exit_err(sk_file);
    }
    if (fgets(sk_comment, (int) sizeof sk_comment, fp) == NULL) {
        exit_err(sk_file);
    }
    sodium_memzero(sk_comment, sizeof sk_comment);
    seckey_s_size = B64_MAX_LEN_FROM_BIN_LEN(sizeof *seckey_struct) + 2U;
    seckey_s = xsodium_malloc(seckey_s_size);
    seckey_struct = xsodium_malloc(sizeof *seckey_struct);
    if (fgets(seckey_s, (int) seckey_s_size, fp) == NULL) {
        exit_err(sk_file);
    }
    trim(seckey_s);
    xfclose(fp);
    if (b64_to_bin((unsigned char *) (void *) seckey_struct, seckey_s,
                   sizeof *seckey_struct, strlen(seckey_s),
                   &seckey_struct_len) == NULL ||
        seckey_struct_len != sizeof *seckey_struct) {
        exit_msg("base64 conversion failed - was an actual secret key given?");
    }
    sodium_free(seckey_s);
    if (memcmp(seckey_struct->sig_alg, SIGALG,
               sizeof seckey_struct->sig_alg) != 0) {
        exit_msg("Unsupported signature algorithm");
    }
    if (memcmp(seckey_struct->kdf_alg, KDFALG,
               sizeof seckey_struct->kdf_alg) != 0) {
        exit_msg("Unsupported key derivation function");
    }
    if (memcmp(seckey_struct->chk_alg, CHKALG,
               sizeof seckey_struct->chk_alg) != 0) {
        exit_msg("Unsupported checksum function");
    }
    if (get_password(pwd, PASSWORDMAXBYTES, "Password: ") != 0) {
        exit_msg("get_password()");
    }
    printf("Deriving a key from the password and decrypting the secret key... ");
    fflush(stdout);
    stream = xsodium_malloc(sizeof seckey_struct->keynum_sk);
    if (crypto_pwhash_scryptsalsa208sha256
        (stream, sizeof seckey_struct->keynum_sk, pwd, strlen(pwd),
         seckey_struct->kdf_salt,
         le64_load(seckey_struct->kdf_opslimit_le),
         le64_load(seckey_struct->kdf_memlimit_le)) != 0) {
        abort();
    }
    sodium_free(pwd);
    xor_buf((unsigned char *) (void *) &seckey_struct->keynum_sk, stream,
            sizeof seckey_struct->keynum_sk);
    sodium_free(stream);
    puts("done\n");
    seckey_chk(chk, seckey_struct);
    if (memcmp(chk, seckey_struct->keynum_sk.chk, sizeof chk) != 0) {
        exit_msg("Wrong password for that key");
    }
    sodium_memzero(chk, sizeof chk);

    return seckey_struct;
}
#endif

static int
verify(PubkeyStruct *pubkey_struct, const char *message_file,
       const char *sig_file, int quiet, int output)
{
    char           trusted_comment[TRUSTEDCOMMENTMAXBYTES];
    unsigned char  global_sig[crypto_sign_BYTES];
    FILE          *info_fp = stdout;
    unsigned char *sig_and_trusted_comment;
    SigStruct     *sig_struct;
    unsigned char *message;
    size_t         message_len;
    size_t         trusted_comment_len;
    int            hashed;

    if (output != 0) {
        info_fp = stderr;
    }
    sig_struct = sig_load(sig_file, global_sig, &hashed,
                          trusted_comment, sizeof trusted_comment);
    message = message_load(&message_len, message_file, hashed);
    if (memcmp(sig_struct->keynum, pubkey_struct->keynum_pk.keynum,
               sizeof sig_struct->keynum) != 0) {
        fprintf(stderr, "Signature key id in %s is %" PRIX64 "\n"
                "but the key id in the public key is %" PRIX64 "\n",
                sig_file, le64_load(sig_struct->keynum),
                le64_load(pubkey_struct->keynum_pk.keynum));
        exit(1);
    }
    if (crypto_sign_verify_detached(sig_struct->sig, message, message_len,
                                    pubkey_struct->keynum_pk.pk) != 0) {
        if (quiet == 0) {
            fprintf(stderr, "Signature verification failed\n");
        }
        exit(1);
    }
    free(message);

    trusted_comment_len = strlen(trusted_comment);
    sig_and_trusted_comment = xmalloc((sizeof sig_struct->sig) +
                                      trusted_comment_len);
    memcpy(sig_and_trusted_comment, sig_struct->sig, sizeof sig_struct->sig);
    memcpy(sig_and_trusted_comment + sizeof sig_struct->sig, trusted_comment,
           trusted_comment_len);
    if (crypto_sign_verify_detached(global_sig, sig_and_trusted_comment,
                                    (sizeof sig_struct->sig) + trusted_comment_len,
                                    pubkey_struct->keynum_pk.pk) != 0) {
        if (quiet == 0) {
            fprintf(stderr, "Comment signature verification failed\n");
        }
        exit(1);
    }
    free(sig_and_trusted_comment);
    free(pubkey_struct);
    free(sig_struct);
    if (quiet == 0) {
        fprintf(info_fp, "Signature and comment signature verified\n"
                "Trusted comment: %s\n", trusted_comment);
    } else if (quiet == 2) {
        fprintf(info_fp, "%s\n", trusted_comment);
    }
    if (output != 0 && output_file(message_file) != 0) {
        exit(2);
    }
    return 0;
}

#ifndef VERIFY_ONLY
static int
sign(const char *sk_file, const char *message_file, const char *sig_file,
     const char *comment, const char *trusted_comment, int hashed)
{
    unsigned char  global_sig[crypto_sign_BYTES];
    SigStruct      sig_struct;
    FILE          *fp;
    SeckeyStruct  *seckey_struct;
    unsigned char *message;
    unsigned char *sig_and_trusted_comment;
    size_t         comment_len;
    size_t         trusted_comment_len;
    size_t         message_len;

    seckey_struct = seckey_load(sk_file);
    message = message_load(&message_len, message_file, hashed);
    if (hashed != 0) {
        memcpy(sig_struct.sig_alg, SIGALG_HASHED, sizeof sig_struct.sig_alg);
    } else {
        memcpy(sig_struct.sig_alg, SIGALG, sizeof sig_struct.sig_alg);
    }
    memcpy(sig_struct.keynum, seckey_struct->keynum_sk.keynum,
           sizeof sig_struct.keynum);
    crypto_sign_detached(sig_struct.sig, NULL, message, message_len,
                         seckey_struct->keynum_sk.sk);
    free(message);
    if ((fp = fopen(sig_file, "w")) == NULL) {
        exit_err(sig_file);
    }
    comment_len = strlen(comment);
    assert(strrchr(comment, '\r') == NULL && strrchr(comment, '\n') == NULL);
    assert(COMMENTMAXBYTES > sizeof COMMENT_PREFIX);
    if (comment_len >= COMMENTMAXBYTES - sizeof COMMENT_PREFIX) {
        fprintf(stderr, "Warning: comment too long. "
                "This breaks compatibility with signify.\n");
    }
    xfprintf(fp, "%s%s\n", COMMENT_PREFIX, comment);
    xfput_b64(fp, (unsigned char *) (void *) &sig_struct, sizeof sig_struct);

    xfprintf(fp, "%s%s\n", TRUSTED_COMMENT_PREFIX, trusted_comment);
    trusted_comment_len = strlen(trusted_comment);
    assert(strrchr(trusted_comment, '\r') == NULL &&
           strrchr(trusted_comment, '\n') == NULL);
    if (trusted_comment_len >=
        TRUSTEDCOMMENTMAXBYTES - sizeof TRUSTED_COMMENT_PREFIX) {
        exit_msg("Trusted comment too long");
    }
    sig_and_trusted_comment = xmalloc((sizeof sig_struct.sig) +
                                      trusted_comment_len);
    memcpy(sig_and_trusted_comment, sig_struct.sig, sizeof sig_struct.sig);
    memcpy(sig_and_trusted_comment + sizeof sig_struct.sig, trusted_comment,
           trusted_comment_len);
    crypto_sign_detached(global_sig, NULL, sig_and_trusted_comment,
                         (sizeof sig_struct.sig) + trusted_comment_len,
                         seckey_struct->keynum_sk.sk);
    sodium_free(seckey_struct);
    xfput_b64(fp, (unsigned char *) (void *) &global_sig, sizeof global_sig);
    free(sig_and_trusted_comment);
    xfclose(fp);

    return 0;
}

static int
generate(const char *pk_file, const char *sk_file, const char *comment)
{
    char          *pwd = xsodium_malloc(PASSWORDMAXBYTES);
    char          *pwd2 = xsodium_malloc(PASSWORDMAXBYTES);
    SeckeyStruct  *seckey_struct = xsodium_malloc(sizeof(SeckeyStruct));
    PubkeyStruct  *pubkey_struct = xsodium_malloc(sizeof(PubkeyStruct));
    unsigned char *stream ;
    FILE          *fp;

    randombytes_buf(seckey_struct->keynum_sk.keynum,
                    sizeof seckey_struct->keynum_sk.keynum);
    crypto_sign_keypair(pubkey_struct->keynum_pk.pk,
                        seckey_struct->keynum_sk.sk);
    memcpy(seckey_struct->sig_alg, SIGALG, sizeof seckey_struct->sig_alg);
    memcpy(seckey_struct->kdf_alg, KDFALG, sizeof seckey_struct->kdf_alg);
    memcpy(seckey_struct->chk_alg, CHKALG, sizeof seckey_struct->chk_alg);
    randombytes_buf(seckey_struct->kdf_salt, sizeof seckey_struct->kdf_salt);
    le64_store(seckey_struct->kdf_opslimit_le,
               crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE);
    le64_store(seckey_struct->kdf_memlimit_le,
               crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE);
    seckey_chk(seckey_struct->keynum_sk.chk, seckey_struct);
    memcpy(pubkey_struct->keynum_pk.keynum, seckey_struct->keynum_sk.keynum,
           sizeof pubkey_struct->keynum_pk.keynum);
    memcpy(pubkey_struct->sig_alg, SIGALG, sizeof pubkey_struct->sig_alg);

    puts("Please enter a password to protect the secret key.\n");
    if (get_password(pwd, PASSWORDMAXBYTES, "Password: ") != 0 ||
        get_password(pwd2, PASSWORDMAXBYTES, "Password (one more time): ") != 0) {
        exit_msg("get_password()");
    }
    if (strcmp(pwd, pwd2) != 0) {
        exit_msg("Passwords don't match");
    }
    printf("Deriving a key from the password in order to encrypt the secret key... ");
    fflush(stdout);
    stream = xsodium_malloc(sizeof seckey_struct->keynum_sk);
    if (crypto_pwhash_scryptsalsa208sha256
        (stream, sizeof seckey_struct->keynum_sk, pwd, strlen(pwd),
         seckey_struct->kdf_salt,
         le64_load(seckey_struct->kdf_opslimit_le),
         le64_load(seckey_struct->kdf_memlimit_le)) != 0) {
        abort();
    }
    sodium_free(pwd);
    sodium_free(pwd2);
    xor_buf((unsigned char *) (void *) &seckey_struct->keynum_sk, stream,
            sizeof seckey_struct->keynum_sk);
    sodium_free(stream);
    puts("done\n");

    if ((fp = fopen_create_useronly(sk_file)) == NULL) {
        exit_err(sk_file);
    }
    xfprintf(fp, "%s%s\n", COMMENT_PREFIX, comment);
    xfput_b64(fp, (unsigned char *) (void *) seckey_struct,
              sizeof *seckey_struct);
    xfclose(fp);
    sodium_free(seckey_struct);

    if ((fp = fopen(pk_file, "w")) == NULL) {
        exit_err(pk_file);
    }
    xfprintf(fp, COMMENT_PREFIX "minisign public key %" PRIX64 "\n",
             le64_load(pubkey_struct->keynum_pk.keynum));
    xfput_b64(fp, (unsigned char *) (void *) pubkey_struct,
              sizeof *pubkey_struct);
    xfclose(fp);

    printf("The secret key was saved as %s - Keep it secret!\n", sk_file);
    printf("The public key was saved as %s - That one can be public.\n\n", pk_file);
    puts("Files signed using this key pair can be verified with the following command:\n");
    printf("minisign -Vm <file> -P ");
    xfput_b64(stdout, (unsigned char *) (void *) pubkey_struct,
              sizeof *pubkey_struct);
    puts("");
    sodium_free(pubkey_struct);

    return 0;
}
#endif

static char *
append_sig_suffix(const char *message_file)
{
    char   *sig_file;
    size_t  message_file_len = strlen(message_file);

    sig_file = xmalloc(message_file_len + sizeof SIG_SUFFIX);
    memcpy(sig_file, message_file, message_file_len);
    memcpy(sig_file + message_file_len, SIG_SUFFIX, sizeof SIG_SUFFIX);

    return sig_file;
}

#ifndef VERIFY_ONLY
static char *
default_trusted_comment(const char *message_file)
{
    char   *ret;
    time_t  ts = time(NULL);

    if (asprintf(&ret, "timestamp:%lu\tfile:%s",
                 (unsigned long) ts, file_basename(message_file)) < 0 ||
        ret == NULL) {
        exit_err("asprintf()");
    }
    return ret;
}
#endif

int
main(int argc, char **argv)
{
    const char *pk_file = NULL;
    const char *sk_file = SIG_DEFAULT_SKFILE;
    const char *sig_file = NULL;
    const char *message_file = NULL;
    const char *comment = NULL;
    const char *pubkey_s = NULL;
    const char *trusted_comment = NULL;
    int         opt_flag;
    int         hashed = 0;
    int         quiet = 0;
    int         output = 0;
    Action      action = ACTION_NONE;

    while ((opt_flag = getopt(argc, argv, getopt_options)) != -1) {
        switch(opt_flag) {
        case 'G':
            if (action != ACTION_NONE && action != ACTION_GENERATE) {
                usage();
            }
            action = ACTION_GENERATE;
            break;
        case 'S':
            if (action != ACTION_NONE && action != ACTION_SIGN) {
                usage();
            }
            action = ACTION_SIGN;
            break;
        case 'V':
            if (action != ACTION_NONE && action != ACTION_VERIFY) {
                usage();
            }
            action = ACTION_VERIFY;
            break;
        case 'c':
            comment = optarg;
            break;
        case 'h':
            usage();
        case 'H':
            hashed = 1;
            break;
        case 'm':
            message_file = optarg;
            break;
        case 'o':
            output = 1;
            break;
        case 'p':
            pk_file = optarg;
            break;
        case 'P':
            pubkey_s = optarg;
            break;
        case 'q':
            quiet = 1;
            break;
        case 'Q':
            quiet = 2;
            break;
        case 's':
            sk_file = optarg;
            break;
        case 't':
            trusted_comment = optarg;
            break;
        case 'x':
            sig_file = optarg;
            break;
        case 'v':
            puts(VERSION_STRING);
            return 0;
        }
    }
    if (sodium_init() != 0) {
        fprintf(stderr, "Unable to initialize the Sodium library\n");
        return 2;
    }
    switch (action) {
#ifndef VERIFY_ONLY
    case ACTION_GENERATE:
        if (comment == NULL || *comment == 0) {
            comment = SECRETKEY_DEFAULT_COMMENT;
        }
        if (pk_file == NULL) {
            pk_file = SIG_DEFAULT_PKFILE;
        }
        return generate(pk_file, sk_file, comment) != 0;
    case ACTION_SIGN:
        if (message_file == NULL) {
            usage();
        }
        if (sig_file == NULL || *sig_file == 0) {
            sig_file = append_sig_suffix(message_file);
        }
        if (comment == NULL || *comment == 0) {
            comment = DEFAULT_COMMENT;
        }
        if (trusted_comment == NULL || *trusted_comment == 0) {
            trusted_comment = default_trusted_comment(message_file);
        }
        return sign(sk_file, message_file, sig_file, comment,
                    trusted_comment, hashed) != 0;
#endif
    case ACTION_VERIFY:
        if (message_file == NULL) {
            usage();
        }
        if (sig_file == NULL || *sig_file == 0) {
            sig_file = append_sig_suffix(message_file);
        }
        if (pk_file == NULL && pubkey_s == NULL) {
            pk_file = SIG_DEFAULT_PKFILE;
        } else if (pk_file != NULL && pubkey_s != NULL) {
            usage();
        }
        return verify(pubkey_load(pk_file, pubkey_s), message_file,
                      sig_file, quiet, output) != 0;
    default:
        usage();
    }
    return 0;
}
