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
	"sync/atomic"
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
	mux := gatewayMux(&DataGatewayConfig{Domain: "control.chitanda.net"}, "/api/v1/transit-test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "business path", 403) }), app)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var served atomic.Pointer[tls.Certificate]
	served.Store(&certificate)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return served.Load(), nil }}
	h2 := &http.Server{Handler: mux, TLSConfig: tlsConfig.Clone()}
	go h2.ServeTLS(ln, "", "")
	defer h2.Close()
	udp, err := net.ListenPacket("udp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	h3 := server.NewHTTP3Server(mux, tlsConfig.Clone(), 1252)
	go h3.Serve(udp)
	defer h3.Close()
	for _, protocol := range []string{"h2", "h3"} {
		for _, sni := range []string{"control.chitanda.net", "custom.chitanda.net"} {
			t.Run(protocol+"/"+sni, func(t *testing.T) {
				e.mu.Lock()
				e.cfg.Routes = []Route{{ID: "test-route", Source: "mainland", Target: "international", Enabled: true, Transport: protocol, ServerName: sni}}
				e.mu.Unlock()
				observed := make(chan TLSInfo, 4)
				link := &Link{relay: Relay{ID: "test-peer"}, transport: protocol, serverName: sni}
				cli, err := client.New(client.Config{Server: ln.Addr().String(), ServerName: sni, Path: "/api/v1/transit-test", PSK: psk, TCPTransport: protocol, TCPPoolSize: 1, UDPPoolSize: 1, QUICInitialPacketSize: 1252, TLSObserver: func(cs tls.ConnectionState) {
					link.observeTLS(cs)
					link.mu.RLock()
					info := link.tlsObservation
					link.mu.RUnlock()
					if info != nil {
						select {
						case observed <- *info:
						default:
						}
					}
				}})
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
				select {
				case info := <-observed:
					if !info.Verified || info.ServerName != sni || info.ALPN != protocol || info.Version != tls.VersionName(tls.VersionTLS13) || info.Certificate.Fingerprint != publicCertificate(certificate.Leaf).Fingerprint {
						t.Fatal("handshake observation mismatch", info)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("real TLS handshake was not observed")
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
				exerciseRealRouteChecks(t, e, cli, ln.Addr().String(), psk, protocol, sni)
			})
		}
	}

	leafTemplate.SerialNumber = big.NewInt(3)
	leafTemplate.NotAfter = time.Now().Add(2 * time.Hour)
	renewedDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: renewedDER}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafPrivate}))
	if err != nil {
		t.Fatal(err)
	}
	served.Store(&renewed)
	for _, protocol := range []string{"h2", "h3"} {
		observed := make(chan tls.ConnectionState, 4)
		cli, err := client.New(client.Config{Server: ln.Addr().String(), ServerName: "custom.chitanda.net", Path: "/api/v1/transit-test", PSK: psk, TCPTransport: protocol, TCPPoolSize: 1, UDPPoolSize: 1, TLSObserver: func(cs tls.ConnectionState) {
			select {
			case observed <- cs:
			default:
			}
		}})
		if err != nil {
			t.Fatal(err)
		}
		probe := &Engine{cfg: Config{ID: "mainland"}}
		c, err := probe.dial(cli, Hello{Kind: "ping", Token: strings.Repeat("a", 64), Transport: protocol, ServerName: "custom.chitanda.net"})
		if err != nil {
			cli.Close()
			t.Fatal(err)
		}
		_, err = receive(c)
		c.Close()
		cli.Close()
		if err != nil {
			t.Fatal(err)
		}
		select {
		case cs := <-observed:
			if publicCertificate(cs.PeerCertificates[0]).Fingerprint != publicCertificate(renewed.Leaf).Fingerprint {
				t.Fatal("renewed certificate observation was not refreshed")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("renewal handshake was not observed")
		}
	}
	var rejectedObservations atomic.Int64
	bad, err := client.New(client.Config{Server: ln.Addr().String(), ServerName: "wrong.chitanda.net", TLSObserver: func(tls.ConnectionState) { rejectedObservations.Add(1) }, Path: "/api/v1/transit-test", PSK: psk, TCPTransport: "h2", TCPPoolSize: 1})
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
	if rejectedObservations.Load() != 0 {
		t.Fatal("rejected SNI generated a successful TLS observation")
	}
}
