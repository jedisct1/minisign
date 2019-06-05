FROM alpine:3.9 as build

WORKDIR /usr/src/minisign

RUN apk add --no-cache \
    g++==8.3.0-r0 \
    libsodium-dev==1.0.16-r0

COPY ./ ./

RUN gcc -static -Os -s -o minisign src/*.c -lsodium


FROM scratch

COPY --from=build /usr/src/minisign/minisign /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/minisign"]
