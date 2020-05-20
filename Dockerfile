ARG BASEIMAGE=busybox
FROM $BASEIMAGE

ARG BINARY=configmap-reload
COPY out/$BINARY /configmap-reload
RUN mkdir /usr/bin && wget -O /usr/bin/jq  https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64 && chmod +x /usr/bin/jq

ENTRYPOINT ["/configmap-reload"]
