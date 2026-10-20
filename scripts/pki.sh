#!/usr/bin/env bash
# Lab PKI: a two-tier certificate chain (offline-style root -> issuing intermediate -> server certs),
# the same shape real companies use. Everything lands in ./certs (git-ignored).
#
#   ./scripts/pki.sh init                          build root + intermediate + all lab server certs
#   ./scripts/pki.sh issue <name> <dns> <ip> [days] issue (or re-issue) one server cert
#   ./scripts/pki.sh show <name>                   print subject, SANs and validity of a cert
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CERTS="${CERTS_DIR:-$ROOT_DIR/certs}"
CA="$CERTS/ca"

die() { echo "pki: $*" >&2; exit 1; }

init_ca() {
  mkdir -p "$CA"
  if [[ -f "$CA/root.key" ]]; then
    echo "pki: CA already exists in $CA (run 'make reset' to start over)"
    return
  fi
  echo "pki: creating root CA (RSA 4096, 10 years)"
  openssl genrsa -out "$CA/root.key" 4096 2>/dev/null
  openssl req -x509 -new -key "$CA/root.key" -sha256 -days 3650 \
    -subj "/C=CA/O=SecureData Lab/CN=SecureData Lab Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$CA/root.crt"

  echo "pki: creating issuing intermediate CA (RSA 3072, 5 years, pathlen 0)"
  openssl genrsa -out "$CA/intermediate.key" 3072 2>/dev/null
  openssl req -new -key "$CA/intermediate.key" \
    -subj "/C=CA/O=SecureData Lab/CN=SecureData Lab Issuing CA 1" \
    -out "$CA/intermediate.csr"
  openssl x509 -req -in "$CA/intermediate.csr" -CA "$CA/root.crt" -CAkey "$CA/root.key" \
    -CAcreateserial -sha256 -days 1825 \
    -extfile <(printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n") \
    -out "$CA/intermediate.crt" 2>/dev/null
  rm -f "$CA/intermediate.csr"

  # What clients trust: root + intermediate.
  cat "$CA/intermediate.crt" "$CA/root.crt" > "$CERTS/ca-chain.pem"
  cp "$CA/root.crt" "$CERTS/root-ca.crt"
  chmod 600 "$CA"/*.key
}

# issue <name> <dns> <ip> [days]
issue() {
  local name="$1" dns="$2" ip="$3" days="${4:-397}"
  [[ -f "$CA/intermediate.key" ]] || die "no CA yet; run: $0 init"
  local out="$CERTS/$name"
  mkdir -p "$out"
  openssl genrsa -out "$out/server.key" 2048 2>/dev/null
  openssl req -new -key "$out/server.key" -subj "/C=CA/O=SecureData Lab/CN=$dns" -out "$out/server.csr"
  local san="DNS:$dns"
  [[ -n "$ip" && "$ip" != "-" ]] && san="$san,IP:$ip"
  openssl x509 -req -in "$out/server.csr" -CA "$CA/intermediate.crt" -CAkey "$CA/intermediate.key" \
    -CAcreateserial -sha256 -days "$days" \
    -extfile <(printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n" "$san") \
    -out "$out/leaf.crt" 2>/dev/null
  # Servers present leaf + intermediate so clients can build the chain to the root.
  cat "$out/leaf.crt" "$CA/intermediate.crt" > "$out/server.crt"
  cp "$CERTS/ca-chain.pem" "$out/ca-chain.pem"
  rm -f "$out/server.csr"
  chmod 600 "$out/server.key"
  chmod 644 "$out/server.crt" "$out/leaf.crt" "$out/ca-chain.pem"
  openssl verify -CAfile "$CERTS/ca-chain.pem" "$out/leaf.crt" >/dev/null || die "verification failed for $name"
  echo "pki: issued $name  ($san, ${days} days)"
}

show() {
  local f="$CERTS/$1/leaf.crt"
  [[ -f "$f" ]] || die "no cert at $f"
  openssl x509 -in "$f" -noout -subject -issuer -dates -ext subjectAltName
}

case "${1:-}" in
  init)
    init_ca
    issue ldap ldap.site-a.lab 10.10.10.20
    issue db   db.site-b.lab   10.20.20.10
    issue kms  kms.site-b.lab  10.20.20.20
    issue app  app.site-b.lab  10.20.20.30
    ;;
  issue) shift; [[ $# -ge 3 ]] || die "usage: $0 issue <name> <dns> <ip|-> [days]"; issue "$@" ;;
  show)  shift; show "$1" ;;
  *) echo "usage: $0 {init|issue|show}"; exit 1 ;;
esac
