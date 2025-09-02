FROM alpine:latest AS build

WORKDIR /usr/src/minisign

RUN apk add --no-cache \
    build-base \
    cmake \
    curl \
    pkgconfig \
    catatonit \
    && apk add --no-cache upx || true

RUN set -eux; \
    curl -fsSL https://download.libsodium.org/libsodium/releases/LATEST.tar.gz | tar xzf -; \
    cd libsodium-stable; \
    env CPPFLAGS="-DED25519_NONDETERMINISTIC=1" \
        ./configure \
        --disable-dependency-tracking; \
    make -j"$(nproc)" check; \
    make install; \
    cd ..; \
    rm -rf libsodium-stable

COPY . .

RUN set -eux; \
    mkdir build; \
    cd build; \
    cmake \
        -DCMAKE_BUILD_TYPE=MinSizeRel \
        -DCMAKE_C_FLAGS="-fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE" \
        -DCMAKE_EXE_LINKER_FLAGS="-pie -Wl,-z,relro,-z,now" \
        -DBUILD_STATIC_EXECUTABLES=1 \
        ..; \
    make -j"$(nproc)"; \
    strip minisign

RUN upx --lzma build/minisign || true

WORKDIR /staging/etc
RUN set -eux; \
    echo "_minisign:x:65534:" > group; \
    echo "_minisign:x:65534:65534:minisign:/dev/null:/etc" > passwd

RUN mkdir -p /staging/tmp /staging/minisign

FROM scratch

COPY --from=build /staging/ /
COPY --from=build /usr/src/minisign/build/minisign /usr/bin/catatonit /usr/bin/

USER 65534:65534
WORKDIR /minisign
ENTRYPOINT ["/usr/bin/catatonit", "--", "/usr/bin/minisign"]
