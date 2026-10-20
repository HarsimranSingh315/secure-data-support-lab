#!/bin/sh
# Start-up: copy certs with safe permissions, load seed data on first run, then run slapd
# in the foreground with connection/operation logging (-d stats) so `docker logs ldap` is useful.
set -eu
CONF=/etc/lab/slapd.conf
DATA=/var/lib/openldap/openldap-data

mkdir -p /etc/openldap/certs /run/openldap "$DATA"
cp /lab-certs/server.crt /lab-certs/server.key /lab-certs/ca-chain.pem /etc/openldap/certs/
chown -R ldap:ldap /etc/openldap/certs /run/openldap "$DATA"
chmod 600 /etc/openldap/certs/server.key

if [ ! -f "$DATA/data.mdb" ]; then
  echo "ldap: first start, loading seed directory"
  slapadd -f "$CONF" -l /etc/lab/seed.ldif
  chown -R ldap:ldap "$DATA"
fi

exec slapd -d stats -u ldap -g ldap -f "$CONF" -h "ldap:/// ldaps:///"
