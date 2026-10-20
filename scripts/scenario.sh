#!/usr/bin/env bash
# Incident simulator. `break` injects a fault and prints only what a customer would report;
# diagnosing it is your job. `hint` gives a nudge, `fix` restores the baseline.
#
#   ./scripts/scenario.sh list
#   ./scripts/scenario.sh break ospf-mtu
#   ./scripts/scenario.sh hint  ospf-mtu
#   ./scripts/scenario.sh fix   ospf-mtu
set -euo pipefail
cd "$(dirname "$0")/.."

dc() { ${LAB_COMPOSE:-docker compose} "$@"; }
# Certificate work runs inside the toolbox image (OpenSSL 3), not with the Mac's LibreSSL.
labssl() { docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/lab -w /lab --entrypoint "" "${LAB_TOOLBOX_IMAGE:-securedata-lab/toolbox:0.1}" "$@"; }

# Interface on <router> that owns an address starting with <prefix>
router_if() {
  dc exec -T "$1" sh -c "ip -o -4 addr show | awk -v p='$2' 'index(\$4, p) == 1 { print \$2; exit }'" | tr -d '\r'
}

ticket() {
  printf '\n  TICKET %s  (priority %s)\n  Customer: "%s"\n\n' "$1" "$2" "$3"
  echo "  Investigate from the toolbox (make toolbox) and the routers (docker compose exec r1 vtysh)."
  echo "  When you have a root cause, write it up: docs/postmortem-template.md"
}

SCENARIOS="ospf-mtu core-link-down firewall-drop cert-renewal ldap-cert-untrusted kms-sealed hba-change data-exfiltration brute-force"

describe() {
  case "$1" in
    ospf-mtu)            echo "Routing: OSPF neighbours stuck after a maintenance change; traffic takes the slow path" ;;
    core-link-down)      echo "Routing: a core link fails; watch OSPF re-route and recover" ;;
    firewall-drop)       echo "Firewall: a change ticket added a rule that blocks the database" ;;
    cert-renewal)        echo "TLS: the database certificate was renewed with the wrong name" ;;
    ldap-cert-untrusted) echo "LDAP + TLS: the directory got a self-signed certificate; directory logins fail" ;;
    kms-sealed)          echo "Key management: the KMS restarted and is sealed; the app cannot encrypt" ;;
    hba-change)          echo "Database access: an access rule was removed during a hardening change" ;;
    data-exfiltration)   echo "Security: an analyst exports the cardholder table; the DAM watcher should catch it" ;;
    brute-force)         echo "Security: repeated failed logins against one account" ;;
    *) return 1 ;;
  esac
}

do_break() {
  case "$1" in
    ospf-mtu)
      local ifc; ifc=$(router_if r2 10.0.23.)
      dc exec -T r2 ip link set dev "$ifc" mtu 1400
      dc exec -T r2 vtysh -c "clear ip ospf process" >/dev/null
      ticket INC-2101 P2 "Since last night's maintenance the app in Site B is slow from Site A, and our network monitoring shows an OSPF neighbour that never comes up." ;;
    core-link-down)
      local ifc; ifc=$(router_if r2 10.0.12.)
      dc exec -T r2 ip link set dev "$ifc" down
      ticket INC-2102 P3 "Latency between the sites jumped a few minutes ago. Nothing is down, it is just slower." ;;
    firewall-drop)
      dc exec -T r3 nft insert rule inet labfw to_site_b ip daddr 10.20.20.10 tcp dport 5432 drop comment '"CHG-1042 temporary block"'
      ticket INC-2103 P1 "Our analysts in Site A cannot connect to the database at all. psql just hangs. The app in Site B is fine." ;;
    cert-renewal)
      rm -rf certs/.db.backup && cp -r certs/db certs/.db.backup
      labssl ./scripts/pki.sh issue db db01.site-b.lab - >/dev/null
      dc restart db >/dev/null
      ticket INC-2104 P1 "We renewed the database certificate this morning as planned. Since then the cardholder app returns 503 and psql from Site A refuses to connect." ;;
    ldap-cert-untrusted)
      rm -rf certs/.ldap.backup && cp -r certs/ldap certs/.ldap.backup
      labssl openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=ldap.site-a.lab" \
        -addext "subjectAltName=DNS:ldap.site-a.lab,IP:10.10.10.20" \
        -keyout certs/ldap/server.key -out certs/ldap/server.crt 2>/dev/null
      labssl chmod 644 certs/ldap/server.crt
      dc restart ldap >/dev/null
      ticket INC-2105 P2 "After the directory server was rebuilt, nobody can log in to the database with their normal username and password. The app still works." ;;
    kms-sealed)
      dc restart kms >/dev/null
      ticket INC-2106 P1 "After the KMS host was patched and rebooted, creating new cardholders fails with 503 errors. Reading the database still works." ;;
    hba-change)
      dc exec -T db sh -c "sed -i 's/^hostssl  appdb     svc_app/#hostssl  appdb     svc_app/' /etc/postgresql/pg_hba.conf && su postgres -c 'pg_ctl reload -D \$PGDATA' >/dev/null"
      ticket INC-2107 P1 "The security team finished a database hardening change. Now the cardholder app health check fails." ;;
    data-exfiltration)
      dc exec -T toolbox bash -lc "export PGSSLMODE=verify-full PGSSLROOTCERT=/lab-certs/ca-chain.pem PGPASSWORD='Lab-bob-2026!';
        psql 'host=db.site-b.lab dbname=appdb user=bob' -c 'select * from cardholders' >/dev/null;
        psql 'host=db.site-b.lab dbname=appdb user=bob' -c 'copy cardholders to stdout' > /tmp/export.csv" || true
      ticket SEC-301 P1 "Our monitoring raised alerts about the cardholder table. Find out who did what, from where, and what we should change." ;;
    brute-force)
      dc exec -T toolbox bash -lc "export PGSSLMODE=verify-full PGSSLROOTCERT=/lab-certs/ca-chain.pem;
        for i in 1 2 3 4 5 6 7; do PGPASSWORD=guess\$i psql 'host=db.site-b.lab dbname=appdb user=carol' -c 'select 1' >/dev/null 2>&1; done" || true
      ticket SEC-302 P2 "Carol says her account feels 'locked' and she did not try to log in. Is someone attacking it?" ;;
    *) echo "unknown scenario: $1"; exit 1 ;;
  esac
}

do_hint() {
  case "$1" in
    ospf-mtu)            echo "Compare 'show ip ospf neighbor' on r2 and r3. What state is it stuck in? What must two neighbours agree on to exchange their databases?" ;;
    core-link-down)      echo "traceroute -n db.site-b.lab from the toolbox, then 'show ip route 10.20.20.0/24' on r1. Which link is it using now and why?" ;;
    firewall-drop)       echo "Does it hang or get refused? Capture on r3 (tcpdump -ni any port 5432), then read 'nft -a list ruleset' and the rule comments." ;;
    cert-renewal)        echo "Read the exact client error. Then: openssl s_client -connect db.site-b.lab:5432 -starttls postgres and look at the certificate names." ;;
    ldap-cert-untrusted) echo "The database authenticates people against LDAP over StartTLS. Check the db log, then openssl s_client -connect ldap.site-a.lab:389 -starttls ldap." ;;
    kms-sealed)          echo "curl the app /health. Then look at the KMS status (docker compose exec kms bao status)." ;;
    hba-change)          echo "The db log names the exact rule (or missing rule) for every rejected connection: docker compose exec db tail /var/log/postgresql/lab/postgresql.log" ;;
    data-exfiltration)   echo "make alerts. Then check what the analyst role is allowed to read, and whether it should be." ;;
    brute-force)         echo "make alerts, then look for 'authentication failed' in the db log. Same source? Same user? How fast?" ;;
    *) echo "unknown scenario: $1"; exit 1 ;;
  esac
}

do_fix() {
  case "$1" in
    ospf-mtu)
      local ifc; ifc=$(router_if r2 10.0.23.)
      dc exec -T r2 ip link set dev "$ifc" mtu 1500
      dc exec -T r2 vtysh -c "clear ip ospf process" >/dev/null ;;
    core-link-down)
      local ifc
      ifc=$(dc exec -T r2 sh -c "ip -o link show | awk -F': ' '/state DOWN/ {print \$2}' | cut -d@ -f1 | head -1" | tr -d '\r')
      [[ -n "$ifc" ]] && dc exec -T r2 ip link set dev "$ifc" up ;;
    firewall-drop)
      dc exec -T r3 nft -f /etc/lab/nftables.nft ;;
    cert-renewal)
      if [[ -d certs/.db.backup ]]; then rm -rf certs/db && mv certs/.db.backup certs/db; else labssl ./scripts/pki.sh issue db db.site-b.lab 10.20.20.10; fi
      dc restart db >/dev/null ;;
    ldap-cert-untrusted)
      if [[ -d certs/.ldap.backup ]]; then rm -rf certs/ldap && mv certs/.ldap.backup certs/ldap; else labssl ./scripts/pki.sh issue ldap ldap.site-a.lab 10.10.10.20; fi
      dc restart ldap >/dev/null ;;
    kms-sealed)
      ./scripts/kms.sh unseal ;;
    hba-change)
      dc exec -T db sh -c "sed -i 's/^#hostssl  appdb     svc_app/hostssl  appdb     svc_app/' /etc/postgresql/pg_hba.conf && su postgres -c 'pg_ctl reload -D \$PGDATA' >/dev/null" ;;
    data-exfiltration)
      echo "Remediation: remove the over-broad grant (analysts keep orders, lose cardholders)."
      dc exec -T db su postgres -c "psql -d appdb -c 'REVOKE SELECT ON cardholders FROM analyst;'" ;;
    brute-force)
      echo "Nothing to undo. Remediation ideas: lockout policy in the directory (OpenLDAP ppolicy), source restrictions in pg_hba.conf, alerting (already working)." ;;
    *) echo "unknown scenario: $1"; exit 1 ;;
  esac
  echo "fixed: $1"
}

action="${1:-list}"; name="${2:-}"
case "$action" in
  list)
    for s in $SCENARIOS; do printf '  %-20s %s\n' "$s" "$(describe "$s")"; done ;;
  break|hint|fix)
    if [[ -z "$name" ]] || ! describe "$name" >/dev/null; then
      echo "usage: $0 $action <scenario>  (see: $0 list)"; exit 1
    fi
    "do_$action" "$name" ;;
  *) echo "usage: $0 {list|break|hint|fix} [scenario]"; exit 1 ;;
esac
