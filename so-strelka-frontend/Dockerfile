FROM ghcr.io/security-onion-solutions/golang:1.25.1-alpine AS build
ARG STRELKA_RELEASE_VERSION=1.0.0

RUN apk add openssl-dev
RUN apk add bash
RUN apk add build-base
RUN apk add pkgconfig
RUN apk add librdkafka
RUN apk add librdkafka-dev
RUN CGO_ENABLED=1 go install -tags musl github.com/target/strelka/src/go/cmd/strelka-frontend@$STRELKA_RELEASE_VERSION

FROM ghcr.io/security-onion-solutions/alpine:3.22.1
LABEL maintainer="Security Onion Solutions, LLC"

COPY --from=build /go/bin/strelka-frontend /usr/local/bin/

RUN addgroup -g 939 strelka && \
    adduser -u 939 -G strelka strelka --disabled-password \
    -h /etc/strelka --no-create-home strelka && \
    mkdir /var/log/strelka/ && \
    touch /var/log/strelka/strelka.log && \
    chown -R 939:939 /var/log/strelka/

USER strelka
