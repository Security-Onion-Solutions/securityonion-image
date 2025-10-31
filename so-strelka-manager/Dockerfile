FROM ghcr.io/security-onion-solutions/golang:1.25.1-alpine AS build
ARG STRELKA_RELEASE_VERSION=1.0.1

RUN CGO_ENABLED=0 go install github.com/target/strelka/src/go/cmd/strelka-manager@$STRELKA_RELEASE_VERSION

FROM ghcr.io/security-onion-solutions/alpine:3.22.1
LABEL maintainer="Security Onion Solutions, LLC"

COPY --from=build /go/bin/strelka-manager /usr/local/bin/
RUN addgroup -g 939 strelka && \
    adduser -u 939 -G strelka strelka --disabled-password \
    -h /etc/strelka --no-create-home strelka
USER strelka
