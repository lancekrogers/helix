FROM node:24-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends iptables iproute2 dnsmasq \
 && update-alternatives --set iptables /usr/sbin/iptables-legacy \
 && update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy \
 && rm -rf /var/lib/apt/lists/*
