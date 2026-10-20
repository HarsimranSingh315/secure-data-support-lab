# OpenBao (open-source fork of HashiCorp Vault) acting as the lab's key manager:
# the app never sees the encryption key, it asks the KMS to encrypt/decrypt card numbers.
ui            = true
disable_mlock = true
api_addr      = "https://kms.site-b.lab:8200"

storage "file" {
  path = "/openbao/file"
}

listener "tcp" {
  address         = "0.0.0.0:8200"
  tls_cert_file   = "/openbao/certs/server.crt"
  tls_key_file    = "/openbao/certs/server.key"
  tls_min_version = "tls12"
}
