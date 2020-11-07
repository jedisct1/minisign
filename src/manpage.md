<!---
This man page can be generated using ronn - http://rtomayko.github.com/ronn/
-->
minisign(1) -- A dead simple tool to sign files and verify signatures.
======================================================================

## SYNOPSIS

`minisign` -G [-p pubkey] [-s seckey]

`minisign` -S [-H] [-x sigfile] [-s seckey] [-c untrusted_comment] [-t trusted_comment] -m file [file ...]

`minisign` -V [-x sigfile] [-p pubkeyfile | -P pubkey] [-o] [-q] -m file

`minisign` -R -s seckey -p pubkeyfile

## DESCRIPTION

**Minisign** is a dead simple tool to sign files and verify signatures.

It is portable, lightweight, and uses the highly secure [Ed25519](http://ed25519.cr.yp.to/) public-key signature system.

## OPTIONS

These options control the actions of `minisign`.

  * `-G`:
    Generate a new key pair
  * `-S`:
    Sign files
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
    Secret key file (default: ~/.minisign/minisign.key)
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
  * `-R`:
    Recreate a public key file from a secret key file
  * `-f`:
    Force. Combined with -G, overwrite a previous key pair
  * `-v`:
    Display version number


## EXAMPLES

Creating a key pair

`minisign` -G

The public key is printed and put into the `minisign.pub` file. The secret key is encrypted and saved as a file named `~/.minisign/minisign.key`.

Signing files

$ `minisign` -Sm myfile.txt
$ `minisign` -Sm myfile.txt myfile2.txt *.c

Or to include a comment in the signature, that will be verified and displayed when verifying the file:

$ `minisign` -Sm myfile.txt -t 'This comment will be signed as well'

The secret key is loaded from `${MINISIGN_CONFIG_DIR}/minisign.key`, `~/.minisign/minisign.key`, or its path can be explicitly set with the `-s <path>` command-line switch.

Verifying a file

$ `minisign` -Vm myfile.txt -P  &lt;pubkey&gt;

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

Signatures generated that way are not compatible with OpenBSD's `signify` tool and are not compatible with `Minisign` versions prior to 0.6.

## AUTHOR

Frank Denis (github [at] pureftpd [dot] org)
