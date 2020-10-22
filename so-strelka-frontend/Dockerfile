FROM golang AS build
LABEL maintainer "Security Onion Solutions, LLC"

RUN mkdir -p src/github.com/target/strelka && \
    git clone https://github.com/target/strelka src/github.com/target/strelka && \
    cd src/github.com/target/strelka && \
    go mod init strelka && \
    sed -i 's/go-redis\/redis/go-redis\/redis\/v8/' src/go/cmd/strelka-frontend/main.go && \
    CGO_ENABLED=0 go build -o /go/bin/strelka-frontend src/go/cmd/strelka-frontend/main.go

FROM alpine
COPY --from=build /go/bin/strelka-frontend /usr/local/bin/
RUN addgroup -g 939 strelka && \
    adduser -u 939 -G strelka strelka --disabled-password \
    -h /etc/strelka --no-create-home strelka && \
    mkdir /var/log/strelka/ && \
    chown -R 939:939 /var/log/strelka/
USER strelka

