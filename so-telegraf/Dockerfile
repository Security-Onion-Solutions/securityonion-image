FROM ghcr.io/security-onion-solutions/telegraf:1.27.2-alipne 
LABEL maintainer "Security Onion Solutions, LLC"
LABEL description="Telegraf running in Docker container for use with Security Onion"

USER root

RUN apk add --no-cache redis curl jq

ENTRYPOINT ["/entrypoint.sh"]
CMD ["telegraf"]
