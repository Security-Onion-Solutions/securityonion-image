FROM golang AS build
LABEL maintainer "Security Onion Solutions, LLC"

RUN CGO_ENABLED=0 go get github.com/target/strelka/src/go/cmd/strelka-frontend

FROM alpine
COPY --from=build /go/bin/strelka-frontend /usr/local/bin/
RUN addgroup -g 939 strelka && \
    adduser -u 939 -G strelka strelka --disabled-password \
    -h /etc/strelka --no-create-home strelka && \
    mkdir /var/log/strelka/ && \
    chown -R 939:939 /var/log/strelka/
USER strelka

