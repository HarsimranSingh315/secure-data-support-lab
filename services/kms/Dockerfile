FROM quay.io/openbao/openbao:2.1.0
USER root
RUN apk add --no-cache iproute2 jq curl
COPY services/kms/kms.hcl services/kms/app-cards.hcl /etc/lab/
COPY services/kms/kms-entrypoint.sh /usr/local/bin/kms-entrypoint.sh
COPY services/common/lab-route /usr/local/bin/lab-route
RUN chmod +x /usr/local/bin/kms-entrypoint.sh /usr/local/bin/lab-route
ENV BAO_ADDR=https://kms.site-b.lab:8200 BAO_CACERT=/openbao/certs/ca-chain.pem
EXPOSE 8200
ENTRYPOINT ["/usr/local/bin/lab-route", "/usr/local/bin/kms-entrypoint.sh"]
