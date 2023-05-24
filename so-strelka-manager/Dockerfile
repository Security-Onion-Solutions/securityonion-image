FROM ghcr.io/security-onion-solutions/golang AS build
LABEL maintainer "Security Onion Solutions, LLC"
ARG STRELKA_RELEASE_VERSION=0.23.05.22

RUN mkdir -p src/github.com/target/strelka && \
    git clone -b $STRELKA_RELEASE_VERSION https://github.com/target/strelka src/github.com/target/strelka && \
    cd src/github.com/target/strelka && \
    go mod init strelka && \
    CGO_ENABLED=0 go build -o /go/bin/strelka-manager src/go/cmd/strelka-manager/main.go

FROM ghcr.io/security-onion-solutions/alpine
COPY --from=build /go/bin/strelka-manager /usr/local/bin/
RUN addgroup -g 939 strelka && \
    adduser -u 939 -G strelka strelka --disabled-password \
    -h /etc/strelka --no-create-home strelka
USER strelka
