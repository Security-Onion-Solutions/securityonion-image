# Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
# or more contributor license agreements. Licensed under the Elastic License 2.0; you may not use
# this file except in compliance with the Elastic License 2.0.
   
FROM ghcr.io/security-onion-solutions/golang:1.22.6-alpine

RUN mkdir /workspace
ADD source /workspace
WORKDIR /workspace
RUN go get .