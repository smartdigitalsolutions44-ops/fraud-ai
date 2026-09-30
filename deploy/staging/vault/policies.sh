#!/bin/sh
# One Vault policy per signing purpose: a token can sign with exactly one key and read
# only that key's public half. Nothing can export, delete, rotate or reconfigure keys
# except the security admin's token.
set -eu
for purpose in model audit release image; do
  vault policy write "fraud-ai-sign-$purpose" - <<POLICY
path "transit/sign/fraud-ai-$purpose" { capabilities = ["update"] }
path "transit/sign/fraud-ai-$purpose/*" { capabilities = ["update"] }
path "transit/keys/fraud-ai-$purpose" { capabilities = ["read"] }
POLICY
done
# The security admin creates and rotates keys, and can never make them exportable,
# export, back up or delete them. (Vault's "+" wildcard matches whole segments only, so
# every key is named.)
admin=""
for purpose in model audit release image; do
  admin="$admin
path \"transit/keys/fraud-ai-$purpose\" { capabilities = [\"create\", \"read\", \"update\"] }
path \"transit/keys/fraud-ai-$purpose/rotate\" { capabilities = [\"update\"] }
path \"transit/keys/fraud-ai-$purpose/config\" { capabilities = [\"deny\"] }"
done
printf '%s\n%s\n%s\n' "$admin" \
  'path "transit/export/*" { capabilities = ["deny"] }' \
  'path "transit/backup/*" { capabilities = ["deny"] }' | vault policy write fraud-ai-key-admin -
