FROM alpine:latest as build

WORKDIR /usr/src/minisign

RUN apk add --no-cache build-base cmake curl pkgconfig gpgv1
RUN apk add --no-cache upx ||:
RUN export libsodiumVER="1.0.18"; curl -fsSLR https://download.libsodium.org/libsodium/releases/libsodium-$libsodiumVER.tar.gz -o libsodium.tar.gz \
  && curl -fsSLR https://download.libsodium.org/libsodium/releases/libsodium-$libsodiumVER.tar.gz.sig -o libsodium.tar.gz.sig \
  && curl -fsSLR https://download.libsodium.org/libsodium/releases/libsodium-$libsodiumVER.tar.gz.minisig -o libsodium.tar.gz.minisig \
  && curl -fsSLR https://download.libsodium.org/jedi.gpg.asc
  #&& curl -fsSLR https://download.libsodium.org/jedi.gpg.asc | gpg --import --verbose --no-default-keyring --keyring /tmp/keyring-gpgv.gpg
  #gpg --verbose --no-default-keyring --keyring | gpg --import --verbose --no-default-keyring --keyring /tmp/keyring-gpgv.gpg
#--verify --verbose --batch
#rm -fr /tmp/gpgv-tmp ; mkdir -p /tmp/gpgv-tmp ; chmod 700 /tmp/gpgv-tmp ; curl -fsSLR https://download.libsodium.org/jedi.gpg.asc | gpg --verbose --import --no-default-keyring --homedir /tmp/gpgv-tmp --keyring /tmp/gpgv-tmp/keyring-gpgv.gpg \
#curl -fsSLR https://download.libsodium.org/jedi.gpg.asc | gpg --import --verbose --fixed-list-mode --with-colons --with-fingerprint --with-fingerprint --no-default-keyring --keyring /tmp/gpgv-tmp/keyring-gpgv.gpg --homedir /tmp/gpgv-tmp/" && rm -fr /tmp/gpgv-tmp ; mkdir -p /tmp/gpgv-tmp ; chmod 700 /tmp/gpgv-tmp \

RUN export GPGDIR=/tmp/gpgv-tmp && export GPGOPS="--batch --fixed-list-mode --verbose --with-colons  --with-fingerprint --with-fingerprint --no-default-keyring --keyring ${GPGDIR}/keyring-gpgv.gpg --homedir ${GPGDIR}"; rm -fr ${GPGDIR} ; mkdir -p ${GPGDIR} ; chmod 700 ${GPGDIR} ; 
  && curl -fsSLR https://download.libsodium.org/jedi.gpg.asc | gpg --import $GPGOPS \
  && gpg --list-keys $GPGOPS 
  && echo '54A2B8892CC3D6A597B92B6C210627AABA709FE1:6:' | gpg --import-ownertrust $GPGOPS \
  && gpg $GPGOPS --verify libsodium.tar.gz.sig libsodium.tar.gz
RUN tar xzvf libsodium.tar.gz && cd libsodium-stable \
  && env CFLAGS="-Os" CPPFLAGS="-DED25519_NONDETERMINISTIC=1" ./configure --disable-dependency-tracking \
  && make -j$(nproc) check && make install && cd .. && rm -fr libsodium-stable

COPY ./ ./
RUN mkdir build && cd build && cmake -D BUILD_STATIC_EXECUTABLES=1 .. && make -j$(nproc)
RUN upx --lzma build/minisign ||:

FROM scratch
COPY --from=build /usr/src/minisign/build/minisign /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/minisign"]
