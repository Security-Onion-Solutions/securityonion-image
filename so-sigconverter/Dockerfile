
# Use the specified Python version
FROM python:3.11.4-slim-buster

#Set build commit from known good commit
ENV BUILDCOMMIT=7f85149b24dd1d7d21c560b1d8fa4df798e2a169

WORKDIR /

# Install wget+unzip, download and unzip sigconverter.io and then remove wget+unzip
RUN apt-get update \
&& apt-get install -y --no-install-recommends wget unzip \
&& rm -rf /var/lib/apt/lists/*  \
&& wget https://github.com/magicsword-io/sigconverter.io/archive/${BUILDCOMMIT}.zip \
&& unzip ${BUILDCOMMIT}.zip \
&& mv sigconverter.io-${BUILDCOMMIT} sigconverter.io \
&& apt-get purge -y --auto-remove wget unzip

# Configure Poetry
ENV POETRY_VERSION=1.6.1
ENV POETRY_HOME=/opt/poetry
ENV POETRY_VENV=/opt/poetry-venv
ENV POETRY_CACHE_DIR=/opt/.cache

# Install poetry separated from system interpreter
RUN python3 -m venv $POETRY_VENV \
    && $POETRY_VENV/bin/pip install -U pip setuptools \
    && $POETRY_VENV/bin/pip install poetry==${POETRY_VERSION}

# Add `poetry` to PATH
ENV PATH="${PATH}:${POETRY_VENV}/bin"

# Set the working directory
WORKDIR /app

# Install dependencies
COPY pyproject.toml ./
RUN poetry install

# Copy the flask app to the working directory
RUN cp -r /sigconverter.io/. /app

# Run the application
EXPOSE 8000
CMD [ "poetry", "run", "python", "./run.py" ]


