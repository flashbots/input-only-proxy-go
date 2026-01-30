package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"golang.org/x/crypto/ssh"
)

var verbose bool

func parseSSHPubKey(path string) (ed25519.PublicKey, error) {
	type sshPubKey struct {
		Algo string
		Data []byte
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, err
	}

	var key sshPubKey
	if err := ssh.Unmarshal(pub.Marshal(), &key); err != nil {
		return nil, err
	}

	if key.Algo != "ssh-ed25519" {
		return nil, errors.New("not ed25519")
	}

	return ed25519.PublicKey(key.Data), nil
}

var (
	activeConn   net.Conn
	activeConnMu sync.Mutex
)

func main() {
	certFile := flag.String("cert", "", "Server TLS certificate file")
	keyFile := flag.String("key", "", "Server TLS private key file")
	clientKeyFile := flag.String("client-key", "", "Client SSH ed25519 public key file")
	listenAddr := flag.String("listen", ":8443", "Address to listen on (host:port)")
	socketPath := flag.String("socket", "", "Unix domain socket path")
	bufferSize := flag.Int("buffer", 1024, "Buffer size in messages")
	flag.BoolVar(&verbose, "v", false, "Verbose logging")
	flag.Parse()

	if *certFile == "" || *keyFile == "" || *clientKeyFile == "" || *socketPath == "" {
		log.Fatal("Required flags: -cert, -key, -client-key, -socket")
	}

	serverCert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("Failed to load server certificate: %v", err)
	}

	expectedKey, err := parseSSHPubKey(*clientKeyFile)
	if err != nil {
		log.Fatalf("Failed to parse client SSH public key: %v", err)
	}
	log.Printf("Loaded client public key from %s", *clientKeyFile)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			if ed, ok := cert.PublicKey.(ed25519.PublicKey); ok && bytes.Equal(ed, expectedKey) {
				return nil
			}
			return errors.New("key mismatch")
		},
	}

	listener, err := tls.Listen("tcp", *listenAddr, tlsConfig)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", *listenAddr, err)
	}
	defer listener.Close()

	log.Printf("Listening on %s, forwarding to %s", *listenAddr, *socketPath)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("TLS handshake failed: %v", err)
			conn.Close()
			continue
		}

		activeConnMu.Lock()
		if activeConn != nil {
			log.Printf("Closing previous connection from %s", activeConn.RemoteAddr())
			activeConn.Close()
		}
		activeConn = conn
		activeConnMu.Unlock()

		log.Printf("Connection accepted from %s", conn.RemoteAddr())
		go handleConnection(conn, *socketPath, *bufferSize)
	}
}

func handleConnection(conn net.Conn, socketPath string, bufferSize int) {
	defer conn.Close()
	defer func() {
		activeConnMu.Lock()
		if activeConn == conn {
			activeConn = nil
		}
		activeConnMu.Unlock()
	}()

	udsConn, err := net.Dial("unix", socketPath)
	if err != nil {
		log.Printf("Failed to connect to UDS %s: %v", socketPath, err)
		return
	}
	defer udsConn.Close()

	ch := make(chan []byte, bufferSize)

	// Writer goroutine: reads from channel and writes to UDS
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for data := range ch {
			if verbose {
				log.Printf("Writing %d bytes to UDS: %q", len(data), string(data))
			}
			if _, err := udsConn.Write(data); err != nil {
				log.Printf("UDS write error: %v", err)
				return
			}
		}
	}()

	// Reader: reads from TLS conn and sends to channel (non-blocking)
	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("Read error: %v", err)
			}
			break
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		select {
		case ch <- data:
		default:
			log.Printf("Buffer full, disconnecting client")
			conn.Close()
			break
		}
	}

	close(ch)
	wg.Wait()
	log.Printf("Connection closed from %s", conn.RemoteAddr())
}
