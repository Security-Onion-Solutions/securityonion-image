FROM ghcr.io/security-onion-solutions/golang:1.21.5-alpine AS build
LABEL maintainer "Security Onion Solutions, LLC"
ARG STRELKA_RELEASE_VERSION=0.24.01.18

RUN CGO_ENABLED=0 go install github.com/target/strelka/src/go/cmd/strelka-filestream@$STRELKA_RELEASE_VERSION

FROM ghcr.io/security-onion-solutions/alpine
COPY --from=build /go/bin/strelka-filestream /usr/local/bin/
RUN addgroup -g 939 strelka && \
    adduser -u 939 -G strelka strelka --disabled-password \
    -h /etc/strelka --no-create-home strelka
RUN apk add --no-cache jq
USER strelka

