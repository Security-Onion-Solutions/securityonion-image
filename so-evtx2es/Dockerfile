FROM python:3.7-slim

WORKDIR /usr/src/app

ADD calculate_timestamp.sh /calculate_timestamp.sh
RUN chmod +x /calculate_timestamp.sh

RUN apt-get update && apt-get install -y --no-install-recommends git jq  && rm -rf /var/lib/apt/lists/*
RUN pip3 install evtx elasticsearch tqdm orjson evtx2es

ENTRYPOINT ["evtx2es"]