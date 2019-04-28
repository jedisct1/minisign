
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
* [libsodium](http://doc.libsodium.org/)
* cmake

Compilation:

    $ mkdir build
    $ cd build
    $ cmake ..
    $ make
    # make install

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
* [minisign-go](https://github.com/jedisct1/minisign-go) is a small module
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
