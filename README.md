# Minisign

![CodeQL scan](https://github.com/jedisct1/minisign/workflows/CodeQL%20scan/badge.svg)
![Release](https://img.shields.io/github/v/release/jedisct1/minisign)

A dead simple tool to sign files and verify signatures.

## Table of Contents

- [Minisign](#minisign)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Documentation](#documentation)
  - [Installation](#installation)
    - [Pre-built Packages](#pre-built-packages)
    - [Building with Zig](#building-with-zig)
    - [Building with cmake and gcc or clang](#building-with-cmake-and-gcc-or-clang)
  - [Usage](#usage)
    - [Generating a Key Pair](#generating-a-key-pair)
    - [Signing Files](#signing-files)
    - [Verifying Signatures](#verifying-signatures)
  - [Verification of Official Releases](#verification-of-official-releases)
  - [Docker](#docker)
  - [Compatibility with Signify](#compatibility-with-signify)
  - [Signature Determinism](#signature-determinism)
  - [Additional Tools, Libraries and Implementations](#additional-tools-libraries-and-implementations)

## Overview

Minisign is a tool to sign files and verify signatures. It's designed to be:

- Simple to use
- Secure (based on modern cryptography)
- Minimal (focused on doing one thing well)
- Cross-platform

Minisign uses the [Ed25519](https://ed25519.cr.yp.to/) public-key signature system with small and fast signatures.

## Documentation

For comprehensive documentation, please refer to the [Minisign documentation](https://jedisct1.github.io/minisign/) website or the included man page.

## Installation

### Prebuilt Packages

Minisign is available in various package managers:

| Platform             | Command                  |
| -------------------- | ------------------------ |
| macOS (Homebrew)     | `brew install minisign`  |
| Windows (Scoop)      | `scoop install minisign` |
| Windows (Chocolatey) | `choco install minisign` |

### Building with Zig

**Dependencies:**

- [libsodium](https://libsodium.org/) (optional)
- [zig](https://ziglang.org) (version 0.15.1 or later)

**Compilation options:**

1. With libsodium, dynamically linked:

```sh
zig build -Doptimize=ReleaseSmall
```

2. With libsodium, statically linked:

```sh
zig build -Doptimize=ReleaseSmall -Dstatic
```

3. Without libsodium (no dependencies required):

```sh
zig build -Doptimize=ReleaseSmall -Dwithout-libsodium
```

The resulting binary can be found in `zig-out/bin/minisign`.

For faster execution at the cost of larger binary size, you can replace `ReleaseSmall` with `ReleaseFast` in any of the above commands.

### Building with CMake and GCC or Clang

**Dependencies:**

- [libsodium](https://libsodium.org/) (required)
- CMake
- pkg-config
- GCC or Clang

**Compilation:**

```sh
mkdir build
cd build
cmake ..
make
make install  # with appropriate permissions
```

**Alternative configuration for static binaries:**

```sh
cmake -D STATIC_LIBSODIUM=1 ..
```

or:

```sh
cmake -D BUILD_STATIC_EXECUTABLES=1 ..
```

## Usage

### Generating a Key Pair

```sh
minisign -G
```

This creates:

- A public key (`minisign.pub` by default)
- A password-protected secret key (`minisign.key` by default)

### Signing Files

```sh
minisign -S -m file.txt
```

This creates a signature file named `file.txt.minisig`.

To add a trusted comment that will be verified:

```sh
minisign -S -m file.txt -t "Trusted comment here"
```

### Verifying Signatures

```sh
minisign -Vm file.txt -p minisign.pub
```

or with a public key directly:

```sh
minisign -Vm file.txt -P RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
```

## Verification of Official Releases

Tarballs and precompiled binaries from the project can be verified with the following public key:

```text
RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3
```

## Docker

Minisign is available as a Docker image:

```sh
docker run -i --rm jedisct1/minisign
```

Example of generating a key for the first time and then signing a local file:

```sh
docker run -i --rm -v .:/minisign jedisct1/minisign \
  -s minisign.key -G
```

```sh
docker run -i --rm -v .:/minisign jedisct1/minisign \
  -s minisign.key -S -m files_to_sign
```

`-s minisign.key` creates and uses the secret key; the public key will be named `minisign.pub`.

Important: create a backup and do not commit or share your generated private key file `minisign.key`.

Example of verifying a signature using the Docker image:

```sh
docker run -i --rm -v .:/minisign jedisct1/minisign \
  -Vm file_to_verify -p minisign.pub
```

`-p minisign.pub` may be omitted if the default name has been generated.

The image can be verified with the following cosign public key:

```text
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExjZWrlc6c58W7ZzmQnx6mugty99C
OQTDtJeciX9LF9hEbs1J1fzZHRdRhV4OTqcq0jTW9PXnrSSZlk1fbkE/5w==
-----END PUBLIC KEY-----
```

## Compatibility with Signify

Minisign is compatible with [signify](https://www.openbsd.org/papers/bsdcan-signify.html), the OpenBSD signing tool. Signatures created with signify can be verified with minisign, and vice versa.

## Signature Determinism

This implementation uses deterministic signatures, unless libsodium was compiled with the `ED25519_NONDETERMINISTIC` macro defined. This adds random noise to the computation of EdDSA nonces.

Other implementations can choose to use non-deterministic signatures by default. They will remain fully interoperable with implementations using deterministic signatures.

## Additional Tools, Libraries and Implementations

- [minizign](https://github.com/jedisct1/zig-minisign) - Compact implementation in Zig that can also use SSH-encoded keys
- [minisign-misc](https://github.com/JayBrown/minisign-misc) - Set of workflows and scripts for macOS to verify and sign files
- [go-minisign](https://github.com/jedisct1/go-minisign) - Go module to verify Minisign signatures
- [rust-minisign](https://github.com/jedisct1/rust-minisign) - Minisign library in pure Rust
- [rsign2](https://github.com/jedisct1/rsign2) - Reimplementation of the command-line tool in Rust
- [minisign (go)](https://github.com/aead/minisign) - Rewrite in Go language (CLI and library)
- [minisign-verify](https://github.com/jedisct1/rust-minisign-verify) - Small Rust crate to verify Minisign signatures
- [minisign-net](https://github.com/bitbeans/minisign-net) - .NET library for Minisign signatures
- [minisign](https://github.com/chm-diederichs/minisign) - JavaScript implementation
- WebAssembly implementations: [rsign2](https://wapm.io/package/jedisct1/rsign2) and [minisign-cli](https://wapm.io/package/jedisct1/minisign) on WAPM
- [minisign-php](https://github.com/soatok/minisign-php) - PHP implementation
- [py-minisign](https://github.com/x13a/py-minisign) - Python implementation
- [minisign](https://hexdocs.pm/minisign/Minisign.html) - Elixir implementation (verification only)
