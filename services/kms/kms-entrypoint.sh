#!/bin/sh
# Copy TLS material, then run the OpenBao server. After every start the KMS is SEALED until
# someone unseals it (make kms-unseal) - exactly like a production key manager after a restart.
set -eu
mkdir -p /openbao/certs /openbao/file
cp /lab-certs/server.crt /lab-certs/server.key /lab-certs/ca-chain.pem /openbao/certs/
chmod 600 /openbao/certs/server.key
exec bao server -config=/etc/lab/kms.hcl
