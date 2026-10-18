package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/violetaini/chitanda/pkg/auth"
	"github.com/violetaini/chitanda/pkg/client"
	"github.com/violetaini/chitanda/pkg/server"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRealH2H3AndSNICertificate(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("private-CA integration runs on the target Linux platform")
	}
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Transit Test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "root.pem")
	os.WriteFile(root, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600)
	t.Setenv("SSL_CERT_FILE", root)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "control.chitanda.net"}, DNSNames: []string{"control.chitanda.net", "custom.chitanda.net"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leafPrivate, _ := x509.MarshalECPrivateKey(leafKey)
	certificate, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafPrivate}))
	if err != nil {
		t.Fatal(err)
	}
	e := testEngine(t)
	psk := []byte(strings.Repeat("s", 32))
	replays, err := auth.OpenReplayCache(filepath.Join(dir, "replays"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer replays.Close()
	app := server.NewServer("/api/v1/transit-test", psk, replays, http.NotFoundHandler(), 0)
	app.SetDialTargetForTest(e.brokerConnection)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	h2 := &http.Server{Handler: app, TLSConfig: tlsConfig.Clone()}
	go h2.ServeTLS(ln, "", "")
	defer h2.Close()
	udp, err := net.ListenPacket("udp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	h3 := server.NewHTTP3Server(app, tlsConfig.Clone(), 1252)
	go h3.Serve(udp)
	defer h3.Close()
	for _, protocol := range []string{"h2", "h3"} {
		for _, sni := range []string{"control.chitanda.net", "custom.chitanda.net"} {
			t.Run(protocol+"/"+sni, func(t *testing.T) {
				e.mu.Lock()
				e.cfg.Routes = []Route{{ID: "test-route", Source: "mainland", Target: "international", Enabled: true, Transport: protocol, ServerName: sni}}
				e.mu.Unlock()
				cli, err := client.New(client.Config{Server: ln.Addr().String(), ServerName: sni, Path: "/api/v1/transit-test", PSK: psk, TCPTransport: protocol, TCPPoolSize: 1, UDPPoolSize: 1, QUICInitialPacketSize: 1252})
				if err != nil {
					t.Fatal(err)
				}
				defer cli.Close()
				// The controller credential is deliberately different from the broker credential.
				probe := &Engine{cfg: Config{ID: "mainland", Token: strings.Repeat("c", 64)}}
				good, err := probe.dial(cli, Hello{Kind: "ping", Token: strings.Repeat("a", 64), Transport: protocol, ServerName: sni})
				if err != nil {
					t.Fatal(err)
				}
				acknowledged, err := receive(good)
				good.Close()
				if err != nil || !acknowledged.OK {
					t.Fatal("scoped broker credential rejected", err)
				}
				bad, err := probe.dial(cli, Hello{Kind: "ping", Token: strings.Repeat("c", 64), Transport: protocol, ServerName: sni})
				if err != nil {
					t.Fatal(err)
				}
				bad.SetReadDeadline(time.Now().Add(3 * time.Second))
				_, err = receive(bad)
				bad.Close()
				if err == nil {
					t.Fatal("controller credential accepted by broker")
				}
				open := func(h Hello) net.Conn {
					ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
					defer cancel()
					c, err := cli.DialContext(ctx, "tcp", "bridge.internal:1")
					if err != nil {
						t.Fatal(err)
					}
					c.SetDeadline(time.Now().Add(10 * time.Second))
					h.Transport = protocol
					h.ServerName = sni
					if err = send(c, h); err != nil {
						t.Fatal(err)
					}
					return c
				}
				dest := open(Hello{Kind: "accept", Node: "international", Token: strings.Repeat("b", 64)})
				defer dest.Close()
				result := make(chan error, 1)
				go func() {
					h, err := receive(dest)
					if err != nil {
						result <- err
						return
					}
					if h.Route != "test-route" {
						result <- fmt.Errorf("unexpected route")
						return
					}
					send(dest, Hello{OK: true})
					raw, err := io.ReadAll(dest)
					if err != nil {
						result <- err
						return
					}
					sum := sha256.Sum256(raw)
					_, err = dest.Write([]byte(hex.EncodeToString(sum[:])))
					halfClose(dest)
					result <- err
				}()
				source := open(Hello{Kind: "dial", Node: "mainland", Token: strings.Repeat("a", 64), Route: "test-route"})
				defer source.Close()
				ack, err := receive(source)
				if err != nil || !ack.OK {
					t.Fatal(ack, err)
				}
				payload := []byte(strings.Repeat("TLS-QUIC-Transit-", 131072))
				sum := sha256.Sum256(payload)
				if _, err = source.Write(payload); err != nil {
					t.Fatal(err)
				}
				halfClose(source)
				reply, err := io.ReadAll(source)
				if err != nil || string(reply) != hex.EncodeToString(sum[:]) {
					t.Fatal("full TLS stream transfer failed", err)
				}
				if err = <-result; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
	bad, err := client.New(client.Config{Server: ln.Addr().String(), ServerName: "wrong.chitanda.net", Path: "/api/v1/transit-test", PSK: psk, TCPTransport: "h2", TCPPoolSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if c, err := bad.DialContext(ctx, "tcp", "bridge.internal:1"); err == nil {
		c.Close()
		t.Fatal("incorrect SNI accepted")
	}
}
