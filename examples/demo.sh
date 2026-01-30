#!/bin/bash
set -ex

cleanup() {
    echo "Cleaning up..."
    [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null || true
    [ -n "$SOCAT_PID" ] && kill "$SOCAT_PID" 2>/dev/null || true

    rm -f server-cert.pem server-key.pem \
        client-ssh client-ssh.pub \
        client-cert.pem client-key.pem \
        proxy.sock
}
trap cleanup EXIT

echo "=== Generating server certificate ==="
openssl req -x509 -newkey ed25519 -keyout server-key.pem -out server-cert.pem \
    -days 365 -nodes -subj "/CN=localhost" 2>/dev/null

echo "=== Generating client SSH key ==="
ssh-keygen -t ed25519 -f client-ssh -N "" -q

echo "=== Converting client SSH key to PEM ==="
go run ../ssh2cert/ client-ssh client-key.pem client-cert.pem

SOCKET_PATH="proxy.sock"

echo "=== Starting proxy ==="
go run ../ \
    -cert server-cert.pem \
    -key server-key.pem \
    -client-key client-ssh.pub \
    -listen 127.0.0.1:8443 \
    -socket "$SOCKET_PATH" \
    -v &
PROXY_PID=$!
sleep 0.5

echo "=== Starting socat on UDS ==="
socat -v -v -u UNIX-LISTEN:"$SOCKET_PATH",fork /dev/null &
SOCAT_PID=$!
sleep 0.5

# Send data through the proxy using openssl s_client
echo "=== Sending data through TLS connection ==="
echo "Hello world" | openssl s_client \
    -connect 127.0.0.1:8443 \
    -cert client-cert.pem \
    -key client-key.pem \
    -quiet \
    2>/dev/null || true &
sleep 0.1
kill $! || true # openssl doesn't alays close connection after EOF for some reason

echo "Press any key to continue..."
read
