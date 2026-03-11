#!/bin/bash
#
# Certificate Generation Script - ioguard
#
# Copyright (C) 2025 ioguard Contributors
#
# Generates test certificates for TLS PoC server and client
#

set -euo pipefail

CERT_DIR="$(pwd)/tests/bench/certs"

echo "Generating test certificates in ${CERT_DIR}..."

# Create directory
mkdir -p "${CERT_DIR}"

# Generate CA key and certificate
echo "  [1/5] Generating CA private key (4096 bits)..."
openssl genrsa -out "${CERT_DIR}/ca-key.pem" 4096 2>/dev/null

echo "  [2/5] Generating CA certificate (10 year validity)..."
openssl req -new -x509 -days 3650 -key "${CERT_DIR}/ca-key.pem" \
    -out "${CERT_DIR}/ca-cert.pem" \
    -subj "/C=US/ST=Test/L=Test/O=ioguard/OU=Testing/CN=Test CA" \
    2>/dev/null

# Generate server key and CSR
echo "  [3/5] Generating server private key (2048 bits)..."
openssl genrsa -out "${CERT_DIR}/server-key.pem" 2048 2>/dev/null

echo "  [4/5] Generating server certificate signing request..."
openssl req -new -key "${CERT_DIR}/server-key.pem" \
    -out "${CERT_DIR}/server-csr.pem" \
    -subj "/C=US/ST=Test/L=Test/O=ioguard/OU=Testing/CN=localhost" \
    2>/dev/null

# Create extension file for Subject Alternative Names
cat > "${CERT_DIR}/san.cnf" <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
x509_extensions = v3_ca

[req_distinguished_name]

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[v3_ca]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Sign server certificate
echo "  [5/5] Signing server certificate..."
openssl x509 -req -days 365 \
    -in "${CERT_DIR}/server-csr.pem" \
    -CA "${CERT_DIR}/ca-cert.pem" \
    -CAkey "${CERT_DIR}/ca-key.pem" \
    -CAcreateserial \
    -out "${CERT_DIR}/server-cert.pem" \
    -extensions v3_ca \
    -extfile "${CERT_DIR}/san.cnf" \
    2>/dev/null

# Set proper permissions
chmod 600 "${CERT_DIR}"/*.pem
chmod 644 "${CERT_DIR}"/ca-cert.pem "${CERT_DIR}"/server-cert.pem

echo ""
echo "Certificates generated successfully!"
echo ""
echo "Files:"
echo "  CA Certificate:     ${CERT_DIR}/ca-cert.pem"
echo "  CA Private Key:     ${CERT_DIR}/ca-key.pem"
echo "  Server Certificate: ${CERT_DIR}/server-cert.pem"
echo "  Server Private Key: ${CERT_DIR}/server-key.pem"
echo ""
echo "Certificate details:"
openssl x509 -in "${CERT_DIR}/server-cert.pem" -noout -subject -issuer -dates -ext subjectAltName
