# Copyright Security Onion Solutions, LLC

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
ARG VERSION
ARG GID=948
ARG UID=948
ARG USERNAME=elastic-agent-pr

FROM docker.elastic.co/package-registry/distribution:$VERSION AS query_stage

ARG VERSION

USER root

RUN apk add --no-cache jq

# GET /search?kibana.version=$VERSION to collect only packages compatible with kibana $VERSION
RUN EPR_ADDRESS=127.0.0.1:18080 /package-registry/package-registry & \
    EPR_PID=$! && \
    echo "Waiting for EPR to become healthy..." && \
    until curl -sf http://127.0.0.1:18080/health; do sleep 2; done && \
    echo "Querying compatible packages for kibana.version=${VERSION}..." && \
    curl -sf "http://127.0.0.1:18080/search?kibana.version=${VERSION}" \
        | jq -r '.[].download | ltrimstr("/epr/") | split("/") | last' \
        > /compatible-packages.txt && \
    echo "Compatible packages found: $(wc -l < /compatible-packages.txt)" && \
    kill $EPR_PID

FROM docker.elastic.co/package-registry/distribution:$VERSION AS package_storage_stage

ARG GID
ARG UID
ARG USERNAME

USER root
# Add bash because it is not included in the new default base image of wolfi-base (default sh shell)
RUN apk add --no-cache bash shadow

# add elastic-agent-pr user / group with no login shell or created home dir
RUN groupadd -g ${GID} ${USERNAME} && \
    useradd -u ${UID} -g ${GID} ${USERNAME} -M -s /sbin/nologin

COPY --from=query_stage /compatible-packages.txt /compatible-packages.txt

# Remove unsupported packages
COPY scripts /scripts
COPY versions /versions
# Keep copy of integrations listed in ./versions/$VERSION. Helps avoid issues during the ES upgrade process.
# In the future this will also allow for downgrading integration versions.
RUN bash /scripts/maintained-versions.sh && \
    bash /scripts/unsupported-integrations.sh && \
    bash /scripts/latest-compatible.sh /compatible-packages.txt && \
    mv /packages/saved-packages/* /packages/package-storage/ && \
    rm -rf /scripts /packages/saved-packages

FROM package_storage_stage AS stripped_packages

ARG STRIP_ALL_SCREENSHOTS=false

USER root

# Keeping the latest version of each integration as-is. Screenshots intact / signature valid.

# Remove package screenshots and associated entries in package manifests, invalidating package signature.
# Installed latest package is complete
# Retained older versions remain "installable", in case of failed integration upgrade rollback can happen automatically
COPY scripts/strip-integration-screenshots.py /scripts/strip-integration-screenshots.py
COPY scripts/strip-integration-screenshots_test.py /tests/

RUN apk add --no-cache python3 py3-pip && \
    python3 -m pip install --no-cache-dir --break-system-packages flake8 pytest pytest-cov && \
    flake8 /scripts /tests --show-source --max-complexity=12 --doctests --max-line-length=200 --statistics && \
    STRIP_ALL_SCREENSHOTS= SCREENSHOT_SCRIPT=/scripts/strip-integration-screenshots.py PYTHONPATH=/scripts pytest /tests/strip-integration-screenshots_test.py --cov=/scripts --doctest-modules --cov-report=term --cov-fail-under=100 && \
    STRIP_ALL_SCREENSHOTS=${STRIP_ALL_SCREENSHOTS} python3 /scripts/strip-integration-screenshots.py && \
    rm -rf /scripts /tests /compatible-packages.txt

FROM package_storage_stage AS final_image

USER root

# Copy integrations from previous stage, so we can avoid having python in final image.
RUN rm -rf /packages/package-storage
COPY --from=stripped_packages /packages/package-storage /packages/package-storage

FROM scratch

ARG UID
ARG GID

USER ${UID}:${GID}

COPY --from=final_image / /
WORKDIR /package-registry

EXPOSE 8080
ENTRYPOINT ["./package-registry"]

ENV EPR_ADDRESS=0.0.0.0:8080 \
    EPR_REQUIRE_PACKAGE_SIGNATURES=false

HEALTHCHECK --interval=1m --retries=30 CMD curl --silent --fail localhost:8080/health || exit 1
