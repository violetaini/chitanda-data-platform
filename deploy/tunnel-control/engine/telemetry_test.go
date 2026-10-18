package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

func telemetryCertificate(t *testing.T, serial int64, expiry time.Time) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "arbitrary-node.example"}, DNSNames: []string{"arbitrary-node.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: expiry, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, Leaf: leaf, PrivateKey: key}
}
func TestTLSReportUsesLoadedCertificateAndRefreshesAfterRotation(t *testing.T) {
	e := testEngine(t)
	e.cfg.ID = "arbitrary-optimizer"
	e.cfg.Role = "relay"
	e.serverTLS.Store(&tls.Config{MinVersion: tls.VersionTLS13})
	first := telemetryCertificate(t, 11, time.Now().Add(time.Hour))
	e.cert.Store(first)
	report := e.report()["tls"].(TLSReport)
	if len(report.Entries) != 1 || report.Entries[0].Certificate.NotAfter != first.Leaf.NotAfter.UTC().Format(time.RFC3339) || report.Entries[0].Verified {
		t.Fatal("loaded certificate metadata is incorrect", report)
	}
	next := telemetryCertificate(t, 12, time.Now().Add(5*time.Hour))
	e.cert.Store(next)
	changed := e.report()["tls"].(TLSReport)
	if changed.Entries[0].Certificate.Fingerprint == report.Entries[0].Certificate.Fingerprint || changed.Entries[0].Certificate.NotAfter != next.Leaf.NotAfter.UTC().Format(time.RFC3339) {
		t.Fatal("certificate rotation did not change observations")
	}
	raw, _ := json.Marshal(changed)
	if strings.Contains(string(raw), "PRIVATE KEY") || strings.Contains(string(raw), "certPEM") || strings.Contains(string(raw), "keyPEM") {
		t.Fatal("private certificate data leaked")
	}
}
func TestTLSObservationRequiresVerifiedHandshakeAndRemainsPeerScoped(t *testing.T) {
	pair := telemetryCertificate(t, 13, time.Now().Add(time.Hour))
	l := &Link{relay: Relay{ID: "arbitrary-peer"}, transport: "h3", serverName: "arbitrary-node.example"}
	state := tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256, ServerName: l.serverName, NegotiatedProtocol: "h3", PeerCertificates: []*x509.Certificate{pair.Leaf}}
	l.observeTLS(state)
	if l.tlsObservation != nil {
		t.Fatal("unverified certificate was marked verified")
	}
	state.VerifiedChains = [][]*x509.Certificate{{pair.Leaf}}
	l.observeTLS(state)
	if l.tlsObservation == nil || !l.tlsObservation.Verified || l.tlsObservation.ServerName != state.ServerName || l.tlsObservation.ALPN != "h3" || l.tlsObservation.Certificate.Fingerprint != publicCertificate(pair.Leaf).Fingerprint {
		t.Fatal("actual handshake metadata missing")
	}
	e := testEngine(t)
	e.links = map[string]*Link{"arbitrary-peer|h3|arbitrary-node.example": l}
	info := e.report()["tls"].(TLSReport).Entries[0]
	if info.Active || !info.Verified || info.ObservedAt == "" {
		t.Fatal("historical handshake must not imply a current active link")
	}
}
