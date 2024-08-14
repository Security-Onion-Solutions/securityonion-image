FROM ghcr.io/security-onion-solutions/python:3.12.5-slim

WORKDIR /root/

RUN rm /bin/sh && ln -s /bin/bash /bin/sh

RUN apt update && apt-get install -y sudo supervisor && rm -rf /var/lib/apt/lists/*
RUN pip install opencanary

ADD supervise-opencanary.conf /etc/supervisor/conf.d/supervise-opencanary.conf

CMD ["/usr/bin/supervisord", "-n"]
