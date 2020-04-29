# Build stage

FROM node:alpine 

WORKDIR /nav-app/

# copy over needed files
RUN apk update && apk add curl
RUN curl -L https://github.com/Security-Onion-Solutions/securityonion-docker-rpm/releases/download/navigator-1.2.2/navigator.tar.gz -o /tmp/navigator.tgz
RUN tar xf /tmp/navigator.tgz 

# install packages and build 
RUN npm install --unsafe-perm

EXPOSE 4200

CMD npm start

# docker run --mount type=bind,source="$(pwd)/nav_layer_playbook.json",target=/nav-app/src/assets/playbook.json -dp 4200:4200 so-navigator:1.0
