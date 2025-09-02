FROM alpine:latest AS build

WORKDIR /usr/src/minisign

RUN apk add --no-cache build-base cmake curl pkgconfig upx catatonit
RUN curl https://download.libsodium.org/libsodium/releases/LATEST.tar.gz | tar xzvf - && cd libsodium-stable && env CFLAGS="-Os" CPPFLAGS="-DED25519_NONDETERMINISTIC=1" ./configure --disable-dependency-tracking && make -j$(nproc) check && make install && cd .. && rm -fr libsodium-stable

COPY . .
RUN mkdir build && cd build && cmake -DCMAKE_BUILD_TYPE=MinSizeRel -DBUILD_STATIC_EXECUTABLES=1 .. && make -j$(nproc)
RUN upx --lzma build/minisign ||:

WORKDIR /copy/etc
RUN echo "nogroup:x:65534:" > group \
 && echo "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin" > passwd


FROM scratch
COPY --from=build /copy/ /
COPY --from=build /usr/src/minisign/build/minisign /usr/bin/catatonit /usr/bin/
USER 65534:65534
WORKDIR /host
ENTRYPOINT ["/usr/bin/catatonit", "--", "/usr/bin/minisign"]
