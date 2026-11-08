#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="/mnt/f/Smile-Net"
CERT_DIR="${BASE_DIR}/certs"
CONF_FILE="${BASE_DIR}/config/openssl_pqc.cnf"

export OPENSSL_CONF="${CONF_FILE}"

mkdir -p "${CERT_DIR}"
cd "${CERT_DIR}"

echo "=== [1/5] Generating PQC Root CA (ML-DSA-65 / Dilithium3) ==="
openssl req -x509 -new -newkey mldsa65 -nodes \
    -keyout ca_pqc.key \
    -out ca_pqc.crt \
    -days 365 \
    -subj "/C=VN/ST=HaNoi/L=HaNoi/O=SmileNet-PQC-RootCA/OU=Security/CN=SmileNet-PQC-RootCA" \
    -config "${CONF_FILE}" -extensions v3_ca

echo "=== [2/5] Generating Native PQC Server Key & Certificate (ML-DSA-65 / Dilithium3) ==="
openssl req -new -newkey mldsa65 -nodes \
    -keyout server_pqc.key \
    -out server_pqc.csr \
    -subj "/C=VN/ST=HaNoi/L=HaNoi/O=SmileNet-PQC-Server/OU=PQC-Node1/CN=10.0.0.1" \
    -config "${CONF_FILE}"

openssl x509 -req \
    -in server_pqc.csr \
    -out server_pqc.crt \
    -CA ca_pqc.crt \
    -CAkey ca_pqc.key \
    -CAcreateserial \
    -days 365 \
    -extfile "${CONF_FILE}" -extensions v3_server

echo "=== [3/5] Generating Classical Root CA (ECDSA P-256) ==="
openssl ecparam -name prime256v1 -genkey -noout -out ca_classic.key
openssl req -x509 -new -nodes \
    -key ca_classic.key \
    -out ca_classic.crt \
    -days 365 \
    -subj "/C=VN/ST=HaNoi/L=HaNoi/O=SmileNet-Classic-RootCA/OU=Security/CN=SmileNet-Classic-RootCA" \
    -config "${CONF_FILE}" -extensions v3_ca

echo "=== [4/5] Generating Classical Server Certificate (ECDSA P-256) ==="
openssl ecparam -name prime256v1 -genkey -noout -out server_classic.key
openssl req -new \
    -key server_classic.key \
    -out server_classic.csr \
    -subj "/C=VN/ST=HaNoi/L=HaNoi/O=SmileNet-Classic-Server/OU=Classic-Node1/CN=10.0.0.1" \
    -config "${CONF_FILE}"

openssl x509 -req \
    -in server_classic.csr \
    -out server_classic.crt \
    -CA ca_classic.crt \
    -CAkey ca_classic.key \
    -CAcreateserial \
    -days 365 \
    -extfile "${CONF_FILE}" -extensions v3_server

echo "=== [5/5] Generating ITU-T X.509 Catalyst Hybrid PQC Server Certificate (ECDSA + ML-DSA-65) ==="
# Extract DER of native ML-DSA-65 cert to embed as X.509 Catalyst extensions (OID 2.5.29.72 / 2.5.29.74)
PQC_DER_HEX=$(openssl x509 -in server_pqc.crt -outform DER | xxd -p -c 100000)
# Split into SubjectAltPublicKeyInfo (~1952B = 3904 hex chars) and AltSignatureValue (~3309B = 6618 hex chars)
ALT_PUBKEY_HEX="${PQC_DER_HEX:0:3904}"
ALT_SIG_HEX="${PQC_DER_HEX:3904:6618}"

cat > "${CERT_DIR}/catalyst_ext.cnf" <<EOF
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
basicConstraints = CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = IP:10.0.0.1, DNS:pqc.smilenet.local, DNS:localhost
2.5.29.72 = DER:${ALT_PUBKEY_HEX}
2.5.29.74 = DER:${ALT_SIG_HEX}
EOF

openssl x509 -req \
    -in server_classic.csr \
    -out server_hybrid_pqc.crt \
    -CA ca_classic.crt \
    -CAkey ca_classic.key \
    -CAcreateserial \
    -days 365 \
    -extfile "${CERT_DIR}/catalyst_ext.cnf"

echo "=== Certificate Generation Complete! ==="
ls -lh "${CERT_DIR}"
