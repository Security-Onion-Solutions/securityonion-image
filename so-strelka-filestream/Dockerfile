FROM golang AS build
LABEL maintainer "Security Onion Solutions, LLC"

RUN CGO_ENABLED=0 go get github.com/target/strelka/src/go/cmd/strelka-filestream

FROM alpine
COPY --from=build /go/bin/strelka-filestream /usr/local/bin/
RUN addgroup -g 939 strelka && \
    adduser -u 939 -G strelka strelka --disabled-password \
    -h /etc/strelka --no-create-home strelka
RUN apk add --no-cache jq
USER strelka

