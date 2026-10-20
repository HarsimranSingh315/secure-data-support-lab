# Support engineer's workstation in Site A: Rocky Linux 9 (RHEL-compatible) with the tools used
# to troubleshoot customer environments.
FROM rockylinux/rockylinux:9
RUN dnf -y module enable postgresql:16 && \
    dnf -y install iproute iputils traceroute mtr bind-utils nmap-ncat telnet tcpdump wireshark-cli \
        openldap-clients postgresql openssl jq vim less procps-ng python3 socat \
        softhsm opensc && \
    dnf clean all
COPY services/common/lab-route /usr/local/bin/lab-route
COPY services/toolbox/hsm-demo.sh /usr/local/bin/hsm-demo
COPY services/toolbox/bashrc-lab /root/.bashrc-lab
RUN chmod +x /usr/local/bin/lab-route /usr/local/bin/hsm-demo && \
    echo '[ -f ~/.bashrc-lab ] && . ~/.bashrc-lab' >> /root/.bashrc
WORKDIR /root
ENTRYPOINT ["/usr/local/bin/lab-route"]
# Jump-host port forward: a database GUI on the Mac connects to localhost:5433, and the connection
# reaches the database FROM this workstation (Site A), through the routers and the firewall.
CMD ["sh", "-c", "socat TCP-LISTEN:5433,fork,reuseaddr TCP:db.site-b.lab:5432 & exec sleep infinity"]
