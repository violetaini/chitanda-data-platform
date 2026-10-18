package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHTTPSCertificateRotationAndAutomaticSource(t *testing.T) {
	e := testEngine(t)
	dir := t.TempDir()
	e.cfg.HTTPSIngress = &HTTPSIngressConfig{Domain: "arbitrary-node.example", Certificate: filepath.Join(dir, "bootstrap.crt"), Key: filepath.Join(dir, "bootstrap.key"), ManagedDirectory: filepath.Join(dir, "managed")}
	makePair := func(serial int64) *ManagedCertificate {
		pair := telemetryCertificate(t, serial, time.Now().Add(time.Hour))
		key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		return &ManagedCertificate{CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]})), KeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))}
	}
	a, b := makePair(41), makePair(42)
	os.WriteFile(e.cfg.HTTPSIngress.Certificate, []byte(a.CertPEM), 0600)
	os.WriteFile(e.cfg.HTTPSIngress.Key, []byte(a.KeyPEM), 0600)
	if err := e.applyHTTPSCertificate(nil); err != nil {
		t.Fatal(err)
	}
	first := loadedCertificate(e.publicCert.Load()).Fingerprint
	if err := e.applyHTTPSCertificate(b); err != nil {
		t.Fatal(err)
	}
	if loadedCertificate(e.publicCert.Load()).Fingerprint == first {
		t.Fatal("managed cert did not rotate")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "managed", "bundle.pem"))
	if err != nil || !strings.Contains(string(raw), b.KeyPEM) {
		t.Fatal("atomic bundle missing")
	}
	if _, err = os.Stat(filepath.Join(dir, "managed", "bundle.pem.tmp")); !os.IsNotExist(err) {
		t.Fatal("temporary private file retained")
	}
	invalid := *b
	invalid.KeyPEM = a.KeyPEM
	if e.applyHTTPSCertificate(&invalid) == nil {
		t.Fatal("mismatched key accepted")
	}
	if err = e.applyHTTPSCertificate(nil); err != nil || loadedCertificate(e.publicCert.Load()).Fingerprint != first {
		t.Fatal("automatic certificate source not restored", err)
	}
}
