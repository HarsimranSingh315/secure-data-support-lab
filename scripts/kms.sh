#!/usr/bin/env bash
# Key management lifecycle for the lab KMS (OpenBao):
#   init    first run only: initialise, unseal, turn on audit logging, create the 'cards' key,
#           a least-privilege policy and a token for the app (saved in ./secrets, git-ignored)
#   unseal  after any KMS restart (a key manager starts sealed, by design)
#   status  show seal status
# Real deployments split the unseal key between several people (Shamir shares) or use an HSM
# for auto-unseal; the lab uses a single share so one person can run it.
set -euo pipefail
cd "$(dirname "$0")/.."
dc() { ${LAB_COMPOSE:-docker compose} "$@"; }
INIT_FILE=secrets/kms-init.json

wait_for_kms() {
  for _ in $(seq 1 30); do
    # bao status: exit 0 = unsealed, 2 = sealed, 1 = error/unreachable
    set +e; dc exec -T kms bao status >/dev/null 2>&1; rc=$?; set -e
    [[ $rc -eq 0 || $rc -eq 2 ]] && return 0
    sleep 2
  done
  echo "kms: not reachable"; exit 1
}

field() { dc exec -T kms jq -r "$1" < "$INIT_FILE" | tr -d '\r'; }

unseal() {
  [[ -f $INIT_FILE ]] || { echo "kms: not initialised yet, run: make kms-init"; exit 1; }
  wait_for_kms
  dc exec -T kms bao operator unseal "$(field '.unseal_keys_b64[0]')" >/dev/null
  echo "kms: unsealed"
}

# Labs first set up with OpenBao 2.1 created the audit device through the API at "file/".
# It is now declared in kms.hcl as "lab-audit/", so remove the old duplicate once.
migrate_audit() {
  local root; root=$(field '.root_token')
  if dc exec -T -e BAO_TOKEN="$root" kms bao audit list 2>/dev/null | grep -q '^file/'; then
    dc exec -T -e BAO_TOKEN="$root" kms bao audit disable file >/dev/null
    echo "kms: removed old API audit device file/ (now configured in kms.hcl as lab-audit/)"
  fi
}

init() {
  wait_for_kms
  if [[ -f $INIT_FILE ]]; then
    echo "kms: already initialised, unsealing"; unseal; migrate_audit; return
  fi
  dc exec -T kms bao operator init -key-shares=1 -key-threshold=1 -format=json > "$INIT_FILE"
  chmod 600 "$INIT_FILE"
  unseal
  local root; root=$(field '.root_token')
  b() { dc exec -T -e BAO_TOKEN="$root" kms bao "$@"; }
  b secrets enable transit >/dev/null
  b write -f transit/keys/cards >/dev/null
  b policy write app-cards /etc/lab/app-cards.hcl >/dev/null
  b token create -policy=app-cards -period=768h -orphan -field=token | tr -d '\r' > secrets/app-kms-token
  chmod 600 secrets/app-kms-token
  dc restart app >/dev/null   # the app copies its token in at start-up
  echo "kms: initialised; transit key 'cards' created; app token saved to secrets/app-kms-token"
  echo "kms: unseal key and root token are in $INIT_FILE (lab only - in production these never sit on disk)"
}

case "${1:-status}" in
  init) init ;;
  unseal) unseal ;;
  status) dc exec -T kms bao status || true ;;
  *) echo "usage: $0 {init|unseal|status}"; exit 1 ;;
esac
