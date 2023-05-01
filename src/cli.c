
#include <assert.h>
#include <stdint.h>
#include <unistd.h>

#include "get_line.h"
#include "helpers.h"
#include "minisign.h"

#ifndef VERIFY_ONLY
static const char *getopt_options = "CGSVRHhc:flm:oP:p:qQs:t:vWx:";
#else
static const char *getopt_options = "VhHm:oP:p:qQvx:";
#endif

static void usage(void) __attribute__((noreturn));

static void
usage(void)
{
    puts(
        "Usage:\n"
#ifndef VERIFY_ONLY
        "minisign -G [-f] [-p pubkey_file] [-s seckey_file] [-W]\n"
        "minisign -R [-s seckey_file] [-p pubkey_file]\n"
        "minisign -C [-s seckey_file] [-W]\n"
        "minisign -S [-l] [-x sig_file] [-s seckey_file] [-c untrusted_comment]\n"
        "            [-t trusted_comment] -m file [file ...]\n"
#endif
        "minisign -V [-H] [-x sig_file] [-p pubkey_file | -P pubkey] [-o] [-q] -m file\n"
        "\n"
#ifndef VERIFY_ONLY
        "-G                generate a new key pair\n"
        "-R                recreate a public key file from a secret key file\n"
        "-C                change/remove the password of the secret key\n"
        "-S                sign files\n"
#endif
        "-V                verify that a signature is valid for a given file\n"
        "-H                require input to be prehashed\n"
        "-l                sign using the legacy format\n"
        "-m <file>         file to sign/verify\n"
        "-o                combined with -V, output the file content after verification\n"
        "-p <pubkey_file>  public key file (default: ./minisign.pub)\n"
        "-P <pubkey>       public key, as a base64 string\n"
#ifndef VERIFY_ONLY
        "-s <seckey_file>  secret key file (default: ~/.minisign/minisign.key)\n"
        "-W                do not encrypt/decrypt the secret key with a password\n"
#endif
        "-x <sigfile>      signature file (default: <file>.minisig)\n"
#ifndef VERIFY_ONLY
        "-c <comment>      add a one-line untrusted comment\n"
        "-t <comment>      add a one-line trusted comment\n"
#endif
        "-q                quiet mode, suppress output\n"
        "-Q                pretty quiet mode, only print the trusted comment\n"
        "-f                force. Combined with -G, overwrite a previous key pair\n"
        "-v                display version number\n");
    exit(2);
}


int
main(int argc, char **argv)
{
    const char *pk_file = NULL;
#ifndef VERIFY_ONLY
    char *sk_file = sig_default_skfile();
#endif
    const char   *sig_file        = NULL;
    const char   *message_file    = NULL;
    const char   *comment         = NULL;
    const char   *pubkey_s        = NULL;
    const char   *trusted_comment = NULL;
    unsigned char opt_seen[16]    = { 0 };
    int           opt_flag;
    int           quiet           = 0;
    int           output          = 0;
    int           force           = 0;
    int           allow_legacy    = 1;
    int           sign_legacy     = 0;
    int           unencrypted_key = 0;
    Action        action          = ACTION_NONE;

    while ((opt_flag = getopt(argc, argv, getopt_options)) != -1) {
        switch (opt_flag) {
#ifndef VERIFY_ONLY
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
        case 'C':
            if (action != ACTION_NONE && action != ACTION_UPDATE_PASSWORD) {
                usage();
            }
            action = ACTION_UPDATE_PASSWORD;
            break;
        case 'R':
            if (action != ACTION_NONE && action != ACTION_RECREATE_PK) {
                usage();
            }
            action = ACTION_RECREATE_PK;
            break;
#endif
        case 'V':
            if (action != ACTION_NONE && action != ACTION_VERIFY) {
                usage();
            }
            action = ACTION_VERIFY;
            break;
#ifndef VERIFY_ONLY
        case 'c':
            comment = optarg;
            break;
        case 'f':
            force = 1;
            break;
#endif
        case 'h':
            usage();
        case 'H':
            allow_legacy = 0;
            break;
        case 'l':
            sign_legacy = 1;
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
#ifndef VERIFY_ONLY
        case 's':
            free(sk_file);
            sk_file = xstrdup(optarg);
            break;
        case 't':
            trusted_comment = optarg;
            break;
        case 'W':
            unencrypted_key = 1;
            break;
#endif
        case 'x':
            sig_file = optarg;
            break;
        case 'v':
            puts(VERSION_STRING);
            return 0;
        case '?':
            usage();
        }
        if (opt_flag > 0 && opt_flag <= (int) sizeof opt_seen / 8) {
            if ((opt_seen[opt_flag / 8] & (1U << (opt_flag & 7))) != 0) {
                fprintf(stderr, "Duplicate option: -- %c\n\n", opt_flag);
                usage();
            }
            opt_seen[opt_flag / 8] |= 1U << (opt_flag & 7);
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
        return generate(pk_file, sk_file, comment, force, unencrypted_key) != 0;
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
        return sign_all(
                   seckey_load(sk_file, NULL),
                   ((pk_file != NULL || pubkey_s != NULL) ? pubkey_load(pk_file, pubkey_s) : NULL),
                   message_file, (const char **) &argv[optind], argc - optind, sig_file, comment,
                   trusted_comment, sign_legacy) != 0;
    case ACTION_RECREATE_PK:
        if (pk_file == NULL) {
            pk_file = SIG_DEFAULT_PKFILE;
        }
        return recreate_pk(pk_file, sk_file, force) != 0;
    case ACTION_UPDATE_PASSWORD:
        return update_password(sk_file, unencrypted_key) != 0;
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
        }
        return verify(pubkey_load(pk_file, pubkey_s), message_file, sig_file, quiet, output,
                      allow_legacy);
    default:
        usage();
    }
    return 0;
}
