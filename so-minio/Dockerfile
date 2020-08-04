FROM minio/minio:latest
LABEL maintainer "Security Onion Solutions, LLC"

ARG GID=939
ARG UID=939
ARG USERNAME=socore

RUN addgroup -g ${GID} ${USERNAME} && \
    adduser -D --uid ${UID} --ingroup ${USERNAME} \
      --home /opt/elastalert --no-create-home ${USERNAME}

ENV MINIO_UPDATE off
ENV MINIO_ACCESS_KEY_FILE=access_key \
    MINIO_SECRET_KEY_FILE=secret_key \
    MINIO_KMS_MASTER_KEY_FILE=kms_master_key \
    MINIO_SSE_MASTER_KEY_FILE=sse_master_key


ENTRYPOINT ["/usr/bin/docker-entrypoint.sh"]

VOLUME ["/data"]

CMD ["minio"]
