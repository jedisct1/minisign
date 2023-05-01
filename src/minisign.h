#ifndef MINISIGN_H
#define MINISIGN_H 1

#include <sodium.h>

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
#define VERSION_STRING                 "minisign 0.11"


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

unsigned char * message_load_hashed(size_t *message_len, const char *message_file);
unsigned char * message_load(size_t *message_len, const char *message_file, int hashed);

int output_file(const char *message_file);
SigStruct * sig_load(const char *sig_file, unsigned char global_sig[crypto_sign_BYTES],
		int *hashed, char trusted_comment[TRUSTEDCOMMENTMAXBYTES], size_t trusted_comment_maxlen);

PubkeyStruct * pubkey_load_string(const char *pubkey_s);
PubkeyStruct * pubkey_load_file(const char *pk_file);
PubkeyStruct * pubkey_load(const char *pk_file, const char *pubkey_s);

void seckey_compute_chk(unsigned char chk[crypto_generichash_BYTES], const SeckeyStruct *seckey_struct);

int verify(PubkeyStruct *pubkey_struct, const char *message_file, const char *sig_file, int quiet,
		int output, int allow_legacy);
char * append_sig_suffix(const char *message_file);
char * default_trusted_comment(const char *message_file, int hashed);

#ifndef VERIFY_ONLY
void sign(SeckeyStruct *seckey_struct, PubkeyStruct *pubkey_struct, const char *message_file,
		const char *sig_file, const char *comment, const char *trusted_comment, int legacy);
int sign_all(SeckeyStruct *seckey_struct, PubkeyStruct *pubkey_struct, const char *message_file,
		const char *additional_files[], int additional_count, const char *sig_file,
		const char *comment, const char *trusted_comment, int legacy);

void abort_on_existing_key_file(const char *file);
void abort_on_existing_key_files(const char *pk_file, const char *sk_file, int force);

void write_pk_file(const char *pk_file, const PubkeyStruct *pubkey_struct);
int generate(const char *pk_file, const char *sk_file, const char *comment, int force,
		int unencrypted_key);
int recreate_pk(const char *pk_file, const char *sk_file, int force);
int update_password(const char *sk_file, int unencrypted_key);

void decrypt_key(SeckeyStruct *const seckey_struct, unsigned char chk[crypto_generichash_BYTES]);
void encrypt_key(SeckeyStruct *const seckey_struct);
SeckeyStruct * seckey_load(const char *sk_file, char *const sk_comment_line);
char * sig_config_dir(void);
char * sig_default_skfile(void);
#endif /* !VERIFY_ONLY */

#endif /* MINISIGN_H */
