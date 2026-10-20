FROM alpine:3.20
RUN apk add --no-cache openldap openldap-back-mdb openldap-clients iproute2
COPY services/ldap/slapd.conf services/ldap/seed.ldif /etc/lab/
COPY services/ldap/ldap-entrypoint.sh /usr/local/bin/ldap-entrypoint.sh
COPY services/common/lab-route /usr/local/bin/lab-route
RUN chmod +x /usr/local/bin/ldap-entrypoint.sh /usr/local/bin/lab-route
EXPOSE 389 636
ENTRYPOINT ["/usr/local/bin/lab-route", "/usr/local/bin/ldap-entrypoint.sh"]
