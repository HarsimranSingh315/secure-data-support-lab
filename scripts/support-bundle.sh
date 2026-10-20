#!/usr/bin/env bash
# Collect a support bundle: the evidence a vendor support engineer asks a customer for.
# Versions, health, routing, firewall, recent logs and config - with secrets redacted.
# Output: bundles/support-bundle-<timestamp>.tar.gz
set -euo pipefail
cd "$(dirname "$0")/.."
dc() { ${LAB_COMPOSE:-docker compose} "$@"; }

ts=$(date -u +%Y%m%dT%H%M%SZ)
out="bundles/support-bundle-$ts"
mkdir -p "$out"

run() {  # run <file> <service> <command...>   (never fails the bundle)
  local file=$1 svc=$2; shift 2
  { echo "\$ $*"; dc exec -T "$svc" "$@" 2>&1 || echo "(command failed: exit $?)"; echo; } >> "$out/$file"
}

echo "collecting into $out ..."
{ date -u; docker version --format '{{.Server.Version}}' 2>&1 | sed 's/^/docker engine: /'; dc ps 2>&1; } > "$out/00-overview.txt"

for r in r1 r2 r3; do
  run "routing-$r.txt" "$r" vtysh -c "show ip ospf neighbor" -c "show ip route" -c "show ip ospf interface"
  run "routing-$r.txt" "$r" ip -br addr
done
run firewall-r3.txt r3 nft -a list ruleset
run db.txt db su postgres -c "psql -d appdb -c 'select version();' -c 'select usename, client_addr, ssl, backend_start from pg_stat_activity join pg_stat_ssl using (pid) where usename is not null;'"
run db.txt db tail -n 200 /var/log/postgresql/lab/postgresql.log
run kms.txt kms bao status
run ldap.txt ldap sh -c "ls -l /etc/openldap/certs; openssl x509 -in /etc/openldap/certs/server.crt -noout -subject -issuer -dates 2>/dev/null || true"
run toolbox.txt toolbox sh -c "ip route; getent hosts db.site-b.lab kms.site-b.lab app.site-b.lab ldap.site-a.lab"

for svc in $(dc ps --services); do dc logs --no-color --tail 300 "$svc" > "$out/logs-$svc.txt" 2>&1 || true; done
dc exec -T dam cat /dam/alerts.jsonl > "$out/dam-alerts.jsonl" 2>/dev/null || true

for c in db ldap kms app; do
  openssl x509 -in "certs/$c/leaf.crt" -noout -subject -dates -ext subjectAltName >> "$out/certificates.txt" 2>&1 || true
done

# Redact anything that looks like a secret before the bundle leaves the machine
find "$out" -type f -exec sed -i.bak -E \
  -e 's/(hvs|s)\.[A-Za-z0-9]{20,}/\1.<REDACTED>/g' \
  -e 's/(PGPASSWORD|[Pp]assword|PASSWORD|[Tt]oken|TOKEN)(=|: ?)("?)[^ ",]+/\1\2\3<REDACTED>/g' {} \;
find "$out" -name '*.bak' -delete

tar -czf "$out.tar.gz" -C bundles "support-bundle-$ts" && rm -rf "$out"
echo "support bundle: $out.tar.gz"
