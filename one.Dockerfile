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
#tcpreplay
RUN apk add tcpreplay \
    --repository=https://dl-cdn.alpinelinux.org/alpine/edge/testing

# RUN iptables -I OUTPUT -p tcp --tcp-flags ALL RST,ACK -j DROP

# add python dependencies scapy
RUN pip3 install scapy

