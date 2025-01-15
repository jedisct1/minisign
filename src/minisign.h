
#ifndef MINISIGN_H
#define MINISIGN_H 1

#define COMMENTMAXBYTES                1024
#define KEYNUMBYTES                    8
#define PASSWORDMAXBYTES               1024
#define TRUSTEDCOMMENTMAXBYTES         8192
#define SIGALG                         "Ed"
#define SIGALG_HASHED                  "ED"
#define KDFALG                         "Sc"
#define KDFNONE                        "\0\0"
#define CHKALG                         "B2"
#define COMMENT_PREFIX                 "untrusted comment: "
#define DEFAULT_COMMENT                "signature from minisign secret key"
#define SECRETKEY_DEFAULT_COMMENT      "minisign encrypted secret key"
#define TRUSTED_COMMENT_PREFIX         "trusted comment: "
#define SIG_DEFAULT_CONFIG_DIR         ".minisign"
#define SIG_DEFAULT_CONFIG_DIR_ENV_VAR "MINISIGN_CONFIG_DIR"
#define SIG_DEFAULT_PKFILE             "minisign.pub"
#define SIG_DEFAULT_SKFILE             "minisign.key"
#define SIG_SUFFIX                     ".minisig"
#define VERSION_STRING                 "minisign 0.12"

typedef struct KeynumSK_ {
    unsigned char keynum[KEYNUMBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    unsigned char chk[crypto_generichash_BYTES];
} KeynumSK;

typedef struct KeynumPK_ {
    unsigned char keynum[KEYNUMBYTES];
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
} KeynumPK;

typedef struct SeckeyStruct_ {
    unsigned char sig_alg[2];
    unsigned char kdf_alg[2];
    unsigned char chk_alg[2];
    unsigned char kdf_salt[crypto_pwhash_scryptsalsa208sha256_SALTBYTES];
    unsigned char kdf_opslimit_le[8];
    unsigned char kdf_memlimit_le[8];
    KeynumSK      keynum_sk;
} SeckeyStruct;

typedef struct PubkeyStruct_ {
    unsigned char sig_alg[2];
    KeynumPK      keynum_pk;
} PubkeyStruct;

typedef struct SigStruct_ {
    unsigned char sig_alg[2];
    unsigned char keynum[KEYNUMBYTES];
    unsigned char sig[crypto_sign_BYTES];
} SigStruct;

typedef enum Action_ {
    ACTION_NONE,
    ACTION_GENERATE,
    ACTION_SIGN,
    ACTION_VERIFY,
    ACTION_RECREATE_PK,
    ACTION_UPDATE_PASSWORD
} Action;

#endif
