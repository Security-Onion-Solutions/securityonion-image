# Not sure which python
FROM python:3

LABEL maintainer="Security Onion Solutions, LLC"
LABEL description="Log scanning machine learning models running in Docker container for use with Security Onion"

WORKDIR /logscan-workdir

COPY ./logscan ./logscan

ADD logscan/run.py /

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

CMD ["python", "logscan/run.py"]