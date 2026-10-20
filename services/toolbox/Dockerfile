# Support engineer's workstation in Site A: Rocky Linux 9 (RHEL-compatible) with the tools used
# to troubleshoot customer environments.
FROM rockylinux/rockylinux:9
RUN dnf -y module enable postgresql:16 && \
    dnf -y install iproute iputils traceroute mtr bind-utils nmap-ncat telnet tcpdump wireshark-cli \
        openldap-clients postgresql openssl jq vim less procps-ng python3 \
        softhsm opensc && \
    dnf clean all
COPY services/common/lab-route /usr/local/bin/lab-route
COPY services/toolbox/hsm-demo.sh /usr/local/bin/hsm-demo
COPY services/toolbox/bashrc-lab /root/.bashrc-lab
RUN chmod +x /usr/local/bin/lab-route /usr/local/bin/hsm-demo && \
    echo '[ -f ~/.bashrc-lab ] && . ~/.bashrc-lab' >> /root/.bashrc
WORKDIR /root
ENTRYPOINT ["/usr/local/bin/lab-route"]
CMD ["sleep", "infinity"]
