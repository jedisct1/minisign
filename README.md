
Minisign
========

Minisign is a dead simple tool to sign files and verify signatures.

For more information, please refer to the
[Minisign documentation](https://jedisct1.github.io/minisign/)

Tarballs and pre-compiled binaries can be verified with the following
public key:

    RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3

Compilation / installation
--------------------------

Dependencies:

* [libsodium](https://libsodium.org/)
* cmake
* pkg-config

Compilation:

    $ mkdir build
    $ cd build
    $ cmake ..
    $ make
    # make install

Alternative configuration for static binaries:

    $ cmake .. -D STATIC_LIBSODIUM=1

or:

    $ cmake .. -D BUILD_STATIC_EXECUTABLES=1

Minisign is also available in Homebrew:

    $ brew install minisign

Minisign is also available in Scoop on Windows:

    $ scoop install minisign

Minisign is also available in chocolatey on Windows:

    $ choco install minisign

Additional tools, libraries and implementations
-----------------------------------------------

* [minisign-misc](https://github.com/JayBrown/minisign-misc) is a very
nice set of workflows and scripts for macOS to verify and sign files
with minisign.
* [go-minisign](https://github.com/jedisct1/go-minisign) is a small module
in Go to verify Minisign signatures.
* [rust-minisign](https://github.com/jedisct1/rust-minisign) is a Minisign
library written in pure Rust, that can be embedded in other applications.
* [rsign2](https://github.com/jedisct1/rsign2) is a reimplementation of
the command-line tool in Rust.
* [minisign-verify](https://github.com/jedisct1/rust-minisign-verify) is
a small Rust crate to verify Minisign signatures.
* [minisign-net](https://github.com/bitbeans/minisign-net) is a .NET library
to handle and create Minisign signatures.
* [minisign-py](https://github.com/HacKanCuBa/minisign-py) is a pure Python
port of Minisign.
* [minisign](https://github.com/chm-diederichs/minisign) a Javascript
implementation.
* WebAssembly implementations of [rsign2](https://wapm.io/package/jedisct1/rsign2)
and [minisign-cli](https://wapm.io/package/jedisct1/minisign) are available on
WAPM.

Faults injections
-----------------

Minisign uses the EdDSA signature system, and deterministic signature
schemes are fragile against fault attacks. However, conducting these requires
physical access or the attacker having access to the same physical host.

More importantly, this requires a significant amount of time, and messages
being signed endlessly while the attack is being conducted.

If such a scenario ever happens to be part of your threat model,
libsodium should be compiled with the `ED25519_NONDETERMINISTIC` macro
defined. This will add random noise to the computation of EdDSA
nonces.
