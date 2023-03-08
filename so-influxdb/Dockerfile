ARG INFLUX_VERSION=2.6.1

FROM ghcr.io/security-onion-solutions/ubuntu:22.04 as builder

ARG INFLUX_VERSION
ARG NODE_VERSION=v18.14.0
ARG NODE_ARCH=linux-x64

RUN apt update -y && apt install -y git wget xz-utils 
RUN git clone https://github.com/influxdata/ui -b OSS-v$INFLUX_VERSION
RUN wget https://nodejs.org/dist/$NODE_VERSION/node-$NODE_VERSION-$NODE_ARCH.tar.xz -O /node.xz
RUN tar -xJf /node.xz

RUN export PATH=$PATH:/node-$NODE_VERSION-$NODE_ARCH/bin && npm i -g yarn

ENV BASE_PATH=/influxdb/
ENV API_BASE_PATH=/influxdb/
ENV NODE_OPTIONS=--openssl-legacy-provider

RUN export PATH=$PATH:/node-$NODE_VERSION-$NODE_ARCH/bin && cd ui && yarn build

FROM ghcr.io/security-onion-solutions/influxdb:$INFLUX_VERSION
LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="InfluxDB running in Docker container for use with Security Onion"

HEALTHCHECK --interval=1m --timeout=10s CMD nc -z localhost 8086 || exit 1
EXPOSE 8086
VOLUME /conf
VOLUME /log
VOLUME /var/lib/influxdb2

RUN mkdir -p /log
RUN mkdir -p /conf

COPY entrypoint.sh /redirect_to_file.sh
RUN chmod a+x /redirect_to_file.sh && groupmod -g 939 influxdb

COPY --from=builder /ui/build /ui

RUN apt update -y && apt install nc -y && apt clean -y

ENTRYPOINT ["/redirect_to_file.sh"]
CMD ["/entrypoint.sh", "influxd"]