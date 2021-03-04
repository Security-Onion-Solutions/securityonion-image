# Copyright 2014-2020 Security Onion Solutions, LLC

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

FROM ghcr.io/security-onion-solutions/python:3-slim

LABEL maintainer="Security Onion Solutions, LLC"
LABEL description="API for automating SOC-related functions"

WORKDIR /SOCtopus

RUN apt-get update && apt-get install -y --no-install-recommends git libmagic1 gcc python3-dev && rm -rf /var/lib/apt/lists/* && \
    git clone https://github.com/Security-Onion-Solutions/sigma.git && \
    mkdir -p /SOCtopus/templates && \
    mkdir -p /SOCtopus/playbook && \
    mkdir -p /var/log/SOCtopus

COPY ./so-soctopus/requirements.txt /SOCtopus/

RUN pip install -r requirements.txt && \
    pip install gunicorn && \
    pip install bcrypt

COPY ./so-soctopus /SOCtopus

# Temp Patch for 2.3.30 - fixes Sigmac Playbook issues
COPY ./elasticsearch.py /usr/local/lib/python3.9/site-packages/sigma/backends/elasticsearch.py

ENTRYPOINT ["gunicorn", "-b", "0.0.0.0:7000", "wsgi:app", "--log-file", "/var/log/SOCtopus/soctopus.log"]