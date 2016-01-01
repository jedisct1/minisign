<!---
This man page can be generated using ronn - http://rtomayko.github.com/ronn/
-->
minisign(1) -- A dead simple tool to sign files and verify signatures.
=============================================

## SYNOPSIS

`minisign` -G [-p pubkey] [-s seckey]
`minisign` -S [-H] [-x sigfile] [-s seckey] [-c untrusted_comment] [-t trusted_comment] -m &lt;file&gt;
`minisign` -V [-x sigfile] [-p pubkeyfile | -P pubkey] [-o] [-q] -m file

## DESCRIPTION

**Minisign** is a dead simple tool to sign files and verify signatures.

It is portable, lightweight, and uses the highly secure [Ed25519](http://ed25519.cr.yp.to/) public-key signature system.

## OPTIONS

These options control the actions of `minisign`.

  * `-G`:
    Generate a new key pair
  * `-S`:
    Sign a file
  * `-V`:
    Verify that a signature is valid for a given file
  * `-m <file>`:
    File to sign/verify
  * `-o`:
    Combined with -V, output the file content after verification
  * `-H`:
    Combined with -S, pre-hash in order to sign large files
  * `-p <pubkeyfile>`:
    Public key file (default: ./minisign.pub)
  * `-P <pubkey>`:
    Public key, as a base64 string
  * `-s <seckey>`:
    Secret key file (default: ./minisign.key)
  * `-x <sigfile>`:
    Signature file (default: &lt;file&gt;.minisig)
  * `-c <comment>`:
    Add a one-line untrusted comment
  * `-t <comment>`:
    Add a one-line trusted comment
  * `-q`:
    Quiet mode, suppress output
  * `-Q`:
    Pretty quiet mode, only print the trusted comment
  * `-v`:
    Display version number


## EXAMPLES

Creating a key pair

`minisign` -G

The public key is printed and put into the `minisign.pub` file. The secret key is encrypted and saved as a file named `minisign.key`.

Signing a file

$ `minisign` -Sm myfile.txt

Or to include a comment in the signature, that will be verified and displayed when verifying the file:

$ `minisign` -Sm myfile.txt -t 'This comment will be signed as well'

Verifying a file

$ `minisign` -Vm myfile.txt -p  &lt;pubkey&gt;

or

$ `minisign` -Vm myfile.txt -p signature.pub

This requires the signature `myfile.txt.minisig` to be present in the same directory.

The public key can either reside in a file (`./minisign.pub` by default) or be directly specified on the command line.

## Notes

**Trusted comments**

Signature files include an untrusted comment line that can be freely modified, even after signature creation.

They also include a second comment line, that cannot be modified without the secret key.

Trusted comments can be used to add instructions or application-specific metadata (intended file name, timestamps, resource identifiers, version numbers to prevent downgrade attacks).

**Compatibility with OpenBSD signify**

Signatures written by `minisign` can be verified using OpenBSD's `signify` tool: public key files and signature files are compatible.

However, `minisign` uses a slightly different format to store secret keys.

`Minisign` signatures include trusted comments in addition to untrusted comments. Trusted comments are signed, thus verified, before being displayed.

This adds two lines to the signature files, that signify silently ignores.

**Pre-hashing**

By default, signing and verification require as much memory as the size of the file.

Since `Minisign 0.6`, huge files can be signed and verified with very low memory requirements, by pre-hashing the content.

The -H command-line switch, in combination with -S, generates a pre-hashed signature (HashEdDSA):

$ `minisign` -SHm myfile.txt

Verification of such a signature doesn't require any specific switch: the appropriate algorithm will automatically be detected.

Signatures generated that way are not compatible with OpenBSD's `signify` tool and are not compatible with `Minisign` versions prior to 0.6

**Signature format**

untrusted comment: &lt;arbitrary text&gt;
base64(&lt;signature_algorithm&gt; || &lt;key_id&gt; || &lt;signature&gt;)
trusted_comment: &lt;arbitrary text&gt;
base64(&lt;global_signature&gt;)

   signature_algorithm: Ed
   key_id: 8 random bytes, matching the public key
   signature (PureEdDSA): ed25519(&lt;file data&gt;)
   signature (HashedEdDSA): ed25519(Blake2b-512(&lt;file data&gt;))
   global_signature: ed25519(&lt;signature&gt; || &lt;trusted_comment&gt;)

**Public key format**

untrusted comment: &lt;arbitrary text&gt;
base64(&lt;signature_algorithm&gt; || &lt;key_id&gt; || &lt;public_key&gt;)

   signature_algorithm: Ed
   key_id: 8 random bytes
   public_key: Ed25519 public key

**Secret key format**

untrusted comment: &lt;arbitrary text&gt;
base64(&lt;signature_algorithm&gt; || &lt;kdf_algorithm&gt; || &lt;cksum_algorithm&gt; ||
      &lt;kdf_salt&gt; || &lt;kdf_opslimit&gt; || &lt;kdf_memlimit&gt; || &lt;keynum_sk&gt;)

   signature_algorithm: Ed
   kdf_algorithm: Sc
   cksum_algorithm: B2
   kdf_salt: 32 random bytes
   kdf_opslimit:   crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE
   kdf_memlimit:   crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE
   keynum_sk: &lt;kdf_output&gt; ^ (&lt;key_id&gt; || &lt;secret_key&gt; ||   &lt;public_key&gt; || &lt;checksum&gt;), 104 bytes
   key_id: 8 random bytes
   secret_key: Ed25519 secret key
   public_key: Ed25519 public key
   checksum: Blake2b-256(&lt;signature_algorithm&gt; || &lt;key_id&gt; ||   &lt;secret_key&gt;), 32 bytes


## AUTHOR

Frank Denis (github [at] pureftpd [dot] org)
