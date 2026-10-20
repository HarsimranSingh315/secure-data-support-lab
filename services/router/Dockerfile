# Lab router: FRRouting (real routing suite used in production networks) plus troubleshooting tools.
FROM quay.io/frrouting/frr:10.2.1
RUN apk add --no-cache nftables tcpdump iproute2 iputils traceroute bind-tools
COPY services/router/daemons services/router/vtysh.conf /etc/frr/
COPY services/router/router-init.sh /usr/local/bin/router-init.sh
RUN chmod +x /usr/local/bin/router-init.sh
ENTRYPOINT ["/usr/local/bin/router-init.sh"]
