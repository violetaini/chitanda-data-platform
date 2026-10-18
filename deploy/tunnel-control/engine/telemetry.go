package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"sort"
	"time"
)

// Public certificate metadata only. Never include PEM, keys or node credentials.
type CertificateInfo struct {
	Fingerprint string   `json:"fingerprint"`
	Subject     string   `json:"subject"`
	Issuer      string   `json:"issuer"`
	DNSNames    []string `json:"dnsNames"`
	NotBefore   string   `json:"notBefore"`
	NotAfter    string   `json:"notAfter"`
}
type TLSInfo struct {
	Side           string           `json:"side"`
	Usage          string           `json:"usage"`
	RelayID        string           `json:"relayId,omitempty"`
	Transport      string           `json:"transport,omitempty"`
	ServerName     string           `json:"serverName,omitempty"`
	Active         bool             `json:"active"`
	Verified       bool             `json:"verified"`
	ObservedAt     string           `json:"observedAt,omitempty"`
	Version        string           `json:"version,omitempty"`
	MinimumVersion string           `json:"minimumVersion,omitempty"`
	ALPN           string           `json:"alpn,omitempty"`
	Cipher         string           `json:"cipher,omitempty"`
	Certificate    *CertificateInfo `json:"certificate,omitempty"`
}
type TLSReport struct {
	Schema      int       `json:"schema"`
	CollectedAt string    `json:"collectedAt"`
	Entries     []TLSInfo `json:"entries"`
}

func publicCertificate(cert *x509.Certificate) *CertificateInfo {
	if cert == nil {
		return nil
	}
	fingerprint := sha256.Sum256(cert.Raw)
	return &CertificateInfo{Fingerprint: hex.EncodeToString(fingerprint[:]), Subject: cert.Subject.String(), Issuer: cert.Issuer.String(), DNSNames: append([]string{}, cert.DNSNames...), NotBefore: cert.NotBefore.UTC().Format(time.RFC3339), NotAfter: cert.NotAfter.UTC().Format(time.RFC3339)}
}
func loadedCertificate(pair *tls.Certificate) *CertificateInfo {
	if pair == nil || len(pair.Certificate) == 0 {
		return nil
	}
	leaf := pair.Leaf
	if leaf == nil {
		leaf, _ = x509.ParseCertificate(pair.Certificate[0])
	}
	return publicCertificate(leaf)
}
func (l *Link) observeTLS(state tls.ConnectionState) {
	// An insecure or unverified handshake must never become a verified observation.
	if !state.HandshakeComplete || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return
	}
	observation := TLSInfo{Side: "client", Usage: "channel", RelayID: l.relay.ID, Transport: l.transport, ServerName: state.ServerName, Verified: true, ObservedAt: time.Now().UTC().Format(time.RFC3339), Version: tls.VersionName(state.Version), ALPN: state.NegotiatedProtocol, Cipher: tls.CipherSuiteName(state.CipherSuite), Certificate: publicCertificate(state.PeerCertificates[0])}
	l.mu.Lock()
	l.tlsObservation = &observation
	l.mu.Unlock()
}

// Caller holds e.mu; each link observation is copied under its own lock.
func (e *Engine) tlsReportLocked() TLSReport {
	report := TLSReport{Schema: 1, CollectedAt: time.Now().UTC().Format(time.RFC3339), Entries: []TLSInfo{}}
	if policy := e.serverTLS.Load(); policy != nil {
		for _, entry := range []struct {
			usage string
			pair  *tls.Certificate
		}{{"channel", e.cert.Load()}, {"https-ingress", e.publicCert.Load()}} {
			if cert := loadedCertificate(entry.pair); cert != nil {
				report.Entries = append(report.Entries, TLSInfo{Side: "server", Usage: entry.usage, RelayID: e.cfg.ID, Active: true, MinimumVersion: tls.VersionName(policy.MinVersion), Certificate: cert})
			}
		}
	}
	if e.serverTLS.Load() == nil && e.cfg.HTTPSIngress != nil {
		if cert := loadedCertificate(e.publicCert.Load()); cert != nil {
			report.Entries = append(report.Entries, TLSInfo{Side: "server", Usage: "https-ingress", RelayID: e.cfg.ID, Active: true, MinimumVersion: "TLS 1.3", Certificate: cert})
		}
	}
	keys := make([]string, 0, len(e.links))
	for key := range e.links {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		l := e.links[key]
		if l.transport == "stream" {
			continue
		}
		l.mu.RLock()
		entry := TLSInfo{Side: "client", Usage: "channel", RelayID: l.relay.ID, Transport: l.transport, ServerName: l.serverName, Active: l.connected}
		if l.tlsObservation != nil {
			entry = *l.tlsObservation
			entry.Active = l.connected
		}
		l.mu.RUnlock()
		report.Entries = append(report.Entries, entry)
	}
	return report
}
