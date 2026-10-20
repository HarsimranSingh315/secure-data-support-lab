#!/usr/bin/env bash
# HSM demo with SoftHSM (a software HSM that speaks PKCS#11, the same API Thales Luna HSMs use):
# create a token, generate a key pair INSIDE the token, sign with it, verify outside, and show the
# private key cannot be exported. Usage: hsm-demo [workdir]
set -euo pipefail
WORK="${1:-$HOME/hsm-demo}"
PIN="${HSM_PIN:-123456}"
SO_PIN="${HSM_SO_PIN:-12345678}"
LABEL="lab-token"

for m in /usr/lib64/pkcs11/libsofthsm2.so /usr/lib/softhsm/libsofthsm2.so /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so; do
  [[ -f "$m" ]] && MODULE="$m" && break
done
[[ -n "${MODULE:-}" ]] || { echo "SoftHSM module not found"; exit 1; }

mkdir -p "$WORK/tokens"
export SOFTHSM2_CONF="$WORK/softhsm2.conf"
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$WORK" > "$SOFTHSM2_CONF"
P11=(pkcs11-tool --module "$MODULE" --token-label "$LABEL")

step() { printf '\n== %s\n' "$*"; }

step "1. Initialise an HSM token (slot) with a security officer PIN and a user PIN"
softhsm2-util --init-token --free --label "$LABEL" --pin "$PIN" --so-pin "$SO_PIN" | tail -1

step "2. Generate an RSA-2048 key pair inside the token (the private key is created non-extractable)"
"${P11[@]}" --login --pin "$PIN" --keypairgen --key-type rsa:2048 --label signing-key --id 01 >/dev/null
"${P11[@]}" --login --pin "$PIN" --list-objects | grep -E "Private Key|Public Key|label|Access" || true

step "3. Sign a document with the key, inside the HSM"
echo "Invoice 2026-10-20: amount 1500.00 CAD" > "$WORK/document.txt"
"${P11[@]}" --login --pin "$PIN" --sign --id 01 --mechanism SHA256-RSA-PKCS \
  --input-file "$WORK/document.txt" --output-file "$WORK/document.sig" >/dev/null 2>&1
ls -l "$WORK/document.sig"

step "4. Export the PUBLIC key and verify the signature with plain OpenSSL (no HSM needed)"
"${P11[@]}" --read-object --type pubkey --id 01 --output-file "$WORK/public.der" >/dev/null
openssl pkey -pubin -inform DER -in "$WORK/public.der" -out "$WORK/public.pem"
openssl dgst -sha256 -verify "$WORK/public.pem" -signature "$WORK/document.sig" "$WORK/document.txt"

step "5. Tamper with the document: verification must fail"
echo "Invoice 2026-10-20: amount 9500.00 CAD" > "$WORK/tampered.txt"
openssl dgst -sha256 -verify "$WORK/public.pem" -signature "$WORK/document.sig" "$WORK/tampered.txt" || true

step "6. Check the PRIVATE key cannot be exported"
rm -f "$WORK/private.der"
"${P11[@]}" --login --pin "$PIN" --read-object --type privkey --id 01 --output-file "$WORK/private.der" 2>&1 | sed 's/^/   pkcs11-tool: /' || true
if [[ -s "$WORK/private.der" ]]; then
  echo "UNEXPECTED: private key material was exported"
  exit 1
fi
echo "No private key file was produced. The key is marked: $("${P11[@]}" --login --pin "$PIN" --list-objects --type privkey | grep -o 'sensitive.*')"
echo "It can be used inside the HSM, but it never leaves it. That is the point of an HSM."
