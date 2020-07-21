FROM centos:7

LABEL maintainer="Security Onion Solutions, LLC"
LABEL description="API for automating SOC-related functions"

WORKDIR /SOCtopus

RUN apt-get update && apt-get install -y --no-install-recommends git libmagic1 gcc python3-dev && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/Security-Onion-Solutions/sigma.git

RUN mkdir -p /SOCtopus/templates
RUN mkdir -p /SOCtopus/playbook
RUN mkdir -p /var/log/SOCtopus

COPY ./so-soctopus/requirements.txt /SOCtopus/
RUN pip install -r requirements.txt 
RUN pip install gunicorn

COPY ./so-soctopus /SOCtopus

ENTRYPOINT ["gunicorn", "-b", "0.0.0.0:7000", "wsgi:app"]

