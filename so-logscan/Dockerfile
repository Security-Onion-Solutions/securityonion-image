FROM ghcr.io/security-onion-solutions/python:3-slim

LABEL maintainer="Security Onion Solutions, LLC"
LABEL description="Log scanning machine learning models running in Docker container for use with Security Onion"

# Set tensorflow log level
ENV TF_CPP_MIN_LOG_LEVEL 3

WORKDIR /logscan

# Install dependencies early to speed up subsequent build times
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Add --use-feature=in-tree-build flag until it becomes default in pip 21.3
RUN pip install --no-cache-dir --use-feature=in-tree-build .

VOLUME [ "/logscan/output", "/logscan/logs", "/logscan/data" ]

ENTRYPOINT ["so-logscan"]
