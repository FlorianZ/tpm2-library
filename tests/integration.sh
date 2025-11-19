#!/usr/bin/env bash

set -e

tpm2sh delete 'vtpm:*'

primary_handle=$(tpm2sh create-primary -H owner ecc-nist-p256:sha256)
>&2 echo "primary handle: $primary_handle"

sealed_handle=$( \
  tpm2sh create "$primary_handle" \
         keyedhash:sha256 \
         --data deadbeef \
         --policy 'secret(tpm:81000001)' | \
  tpm2sh load)

>&2 echo "sealed handle: $sealed_handle"
tpm2sh unseal "$sealed_handle"

sealed_handle=$( \
  tpm2sh create "$primary_handle" \
         keyedhash:sha256 \
         --data deadbeef \
         --policy 'pcr(sha256:7) or pcr(sha256:15)' | \
  tpm2sh load)

>&2 echo "sealed handle: $sealed_handle"
tpm2sh unseal "$sealed_handle"

openssl ecparam -name prime256v1 -genkey -noout -out ecc.pem
tpm2sh convert -I ecc.pem "$primary_handle" | tpm2sh load

openssl genrsa -out rsa.pem 2048
tpm2sh convert -I rsa.pem "$primary_handle" | tpm2sh load
