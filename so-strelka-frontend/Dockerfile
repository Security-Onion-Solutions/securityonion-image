FROM ghcr.io/security-onion-solutions/golang:1.21.5-alpine AS build
LABEL maintainer "Security Onion Solutions, LLC"
ARG STRELKA_RELEASE_VERSION=0.24.01.18

RUN apk add openssl-dev \
    bash \
    build-base \
    pkgconfig \
    librdkafka \
    librdkafka-dev && \
    CGO_ENABLED=1 go install -tags musl github.com/target/strelka/src/go/cmd/strelka-frontend@$STRELKA_RELEASE_VERSION

FROM ghcr.io/security-onion-solutions/alpine

COPY --from=build /go/bin/strelka-frontend /usr/local/bin/

RUN addgroup -g 939 strelka && \
    adduser -u 939 -G strelka strelka --disabled-password \
    -h /etc/strelka --no-create-home strelka && \
    mkdir /var/log/strelka/ && \
    touch /var/log/strelka/strelka.log && \
    chown -R 939:939 /var/log/strelka/

USER strelka
