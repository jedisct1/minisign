FROM alpine:latest as build

WORKDIR /usr/src/minisign

RUN apk add --no-cache build-base cmake curl pkgconfig
RUN apk add --no-cache upx ||:
RUN curl https://download.libsodium.org/libsodium/releases/LATEST.tar.gz | tar xzvf - && cd libsodium-stable && env CFLAGS="-Os" CPPFLAGS="-DED25519_NONDETERMINISTIC=1" ./configure --disable-dependency-tracking && make -j$(nproc) check && make install && cd .. && rm -fr libsodium-stable

COPY ./ ./
RUN mkdir build && cd build && cmake -D BUILD_STATIC_EXECUTABLES=1 .. && make -j$(nproc)
RUN upx --lzma build/minisign ||:

FROM scratch
COPY --from=build /usr/src/minisign/build/minisign /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/minisign"]
