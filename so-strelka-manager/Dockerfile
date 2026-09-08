FROM ghcr.io/security-onion-solutions/golang:1.26.4-alpine AS build
ARG STRELKA_RELEASE_VERSION=7d955e95e41c6fc578aa5204b857896d29040e7b

RUN CGO_ENABLED=0 go install github.com/target/strelka/src/go/cmd/strelka-manager@$STRELKA_RELEASE_VERSION && \
    CGO_ENABLED=0 go install github.com/target/strelka/src/go/cmd/strelka-filestream@$STRELKA_RELEASE_VERSION && \
    apk add openssl-dev bash build-base pkgconfig librdkafka librdkafka-dev && \
    CGO_ENABLED=1 go install -tags musl github.com/target/strelka/src/go/cmd/strelka-frontend@$STRELKA_RELEASE_VERSION


FROM ghcr.io/security-onion-solutions/alpine:3.24.1
LABEL maintainer="Security Onion Solutions, LLC"

COPY --from=build /go/bin/strelka-manager /usr/local/bin/
COPY --from=build /go/bin/strelka-filestream /usr/local/bin/
COPY --from=build /go/bin/strelka-frontend /usr/local/bin/

RUN addgroup -g 939 strelka && \
    adduser -u 939 -G strelka strelka --disabled-password \
    -h /etc/strelka --no-create-home strelka && \
    apk add --no-cache jq && \
    mkdir /var/log/strelka/ && \
    touch /var/log/strelka/strelka.log && \
    chown -R 939:939 /var/log/strelka/
USER strelka
