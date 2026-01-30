# input-only-proxy

A TLS proxy that accepts input-only data from clients authenticated via SSH ed25519 keys.

## Use Case

You have a server where clients already have trusted SSH key. You want to accept input-only data from those same identity over TLS, without giving them shell access or any output channel.

## How It Works

1. Client's SSH ed25519 key is converted to a TLS certificate using `ssh2cert`
2. Proxy accepts TLS connections, verifying client cert matches the trusted SSH public key
3. Data flows one-way: TLS client -> Unix domain socket (no data flows back)
4. Only one connection allowed at a time; new connections close previous ones

## Timing Side-Channel Resistance

The proxy uses a buffered channel between TLS reads and UDS writes. If the UDS consumer is slow (buffer fills), the client is immediately disconnected rather than blocking TLS reads. This prevents timing information about the UDS consumer from leaking back to the external TLS client.

## Usage

### 1. Convert SSH key to TLS certificate

```bash
# Generate client SSH key (if you don't have one)
ssh-keygen -t ed25519 -f client-ssh -N ""

# Convert to TLS cert/key pair
go run ./ssh2cert/ client-ssh client-key.pem client-cert.pem
```

### 2. Start the proxy

```bash
# Generate server certificate
openssl req -x509 -newkey ed25519 -keyout server-key.pem -out server-cert.pem \
    -days 365 -nodes -subj "/CN=localhost"

# Run proxy
go run . \
    -cert server-cert.pem \
    -key server-key.pem \
    -client-key client-ssh.pub \
    -listen 127.0.0.1:8443 \
    -socket /path/to/app.sock
```

### 3. Connect with openssl s_client

```bash
echo "Hello world" | openssl s_client \
    -connect 127.0.0.1:8443 \
    -cert client-cert.pem \
    -key client-key.pem \
    -quiet
```

## Flags

| Flag | Description |
|------|-------------|
| `-cert` | Server TLS certificate file |
| `-key` | Server TLS private key file |
| `-client-key` | Client SSH ed25519 public key file |
| `-listen` | Address to listen on (default `:8443`) |
| `-socket` | Unix domain socket path |
| `-buffer` | Buffer size in messages (default 1024) |
| `-v` | Verbose logging |
