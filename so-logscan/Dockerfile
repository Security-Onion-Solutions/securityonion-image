FROM python:3-slim

LABEL maintainer="Security Onion Solutions, LLC"
LABEL description="Log scanning machine learning models running in Docker container for use with Security Onion"

VOLUME [ "/output", "/logs" ]

# Set tensorflow log level
ENV TF_CPP_MIN_LOG_LEVEL 3

RUN mkdir /output && \
    mkdir /logs

WORKDIR /logscan

# Install dependencies early to speed up subsequent build times
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

COPY . .

# Add --use-feature=in-tree-build flag until it becomes default in pip 21.3
RUN pip install --use-feature=in-tree-build .

ENTRYPOINT ["so-logscan"]
