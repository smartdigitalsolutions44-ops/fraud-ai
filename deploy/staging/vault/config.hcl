# STAGING Vault server (Stage 12): the KMS for the trust-chain signing keys (transit engine).
# File storage on a named volume; one unseal key (see stack.sh): staging custody only.
# Production: TLS listener, auto-unseal (cloud KMS/HSM), Shamir shares held by different
# people, audit device enabled, no root token kept.
storage "file" {
  path = "/vault/file"
}
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true # internal Docker network + loopback port only (staging)
}
disable_mlock = true
ui            = false
api_addr      = "http://vault:8200"
