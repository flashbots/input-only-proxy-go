package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <ssh-private-key> [key.pem] [cert.pem]\n", os.Args[0])
		os.Exit(1)
	}

	sshKeyPath := os.Args[1]
	keyPemPath := "key.pem"
	certPemPath := "cert.pem"

	if len(os.Args) >= 3 {
		keyPemPath = os.Args[2]
	}
	if len(os.Args) >= 4 {
		certPemPath = os.Args[3]
	}

	data, err := os.ReadFile(sshKeyPath)
	if err != nil {
		log.Fatalf("Failed to read SSH private key: %v", err)
	}

	if !strings.HasPrefix(string(data), "-----BEGIN OPENSSH PRIVATE KEY-----") {
		log.Fatal("File does not appear to be an OpenSSH private key")
	}

	rawKey, err := ssh.ParseRawPrivateKey(data)
	if errors.Is(err, &ssh.PassphraseMissingError{}) {
		var passphrase []byte
		fmt.Print("Enter passphrase: ")
		passphrase, err = term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			log.Fatalf("Failed to read passphrase: %v", err)
		}

		rawKey, err = ssh.ParseRawPrivateKeyWithPassphrase(data, passphrase)
	}
	if err != nil {
		log.Fatalf("Failed to parse SSH private key: %v", err)
	}

	privKey, ok := rawKey.(*ed25519.PrivateKey)
	if !ok {
		log.Fatalf("SSH key is not ed25519 (got %T)", rawKey)
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(*privKey)
	if err != nil {
		log.Fatalf("Failed to marshal private key to PKCS8: %v", err)
	}

	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	})

	if err := os.WriteFile(keyPemPath, keyPem, 0600); err != nil {
		log.Fatalf("Failed to write %s: %v", keyPemPath, err)
	}

	// Create self-signed certificate
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "ssh2cert",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	pubKey := privKey.Public()
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, *privKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	if err := os.WriteFile(certPemPath, certPem, 0644); err != nil {
		log.Fatalf("Failed to write %s: %v", certPemPath, err)
	}

	fmt.Printf("Written: %s, %s\n", keyPemPath, certPemPath)
}
