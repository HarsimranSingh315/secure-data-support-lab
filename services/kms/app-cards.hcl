# Least privilege for the application: encrypt and decrypt with the "cards" key, nothing else.
path "transit/encrypt/cards" {
  capabilities = ["update"]
}
path "transit/decrypt/cards" {
  capabilities = ["update"]
}
