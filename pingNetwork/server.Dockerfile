FROM alpine:latest

WORKDIR /usr/src/app

# add python3
RUN apk add --no-cache python3
# add pip3
RUN apk add --no-cache py3-pip
# add tcpdump
RUN apk add --no-cache tcpdump
# add iproute2
RUN apk add --no-cache iproute2
# add iptables
RUN apk add --no-cache iptables
#tcpreplay (scuffed because apk should have it but it doesn't, so directly from the repo)
RUN apk add tcpreplay \
    --repository=https://dl-cdn.alpinelinux.org/alpine/edge/testing
# add python dependencies scapy
RUN pip3 install scapy
# copy server.py
COPY server.py ./