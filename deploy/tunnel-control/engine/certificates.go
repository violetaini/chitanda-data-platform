package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
)

type ManagedCertificate struct {
	CertPEM string `json:"certPEM"`
	KeyPEM  string `json:"keyPEM"`
}

// Bootstrap paths are installed locally by the administrator; the controller cannot select paths.
type HTTPSIngressConfig struct {
	Domain           string `json:"domain"`
	Certificate      string `json:"certificate"`
	Key              string `json:"key"`
	ManagedDirectory string `json:"managedDirectory,omitempty"`
}

func (e *Engine) ingressReportLocked() any {
	if e.cfg.HTTPSIngress != nil {
		return map[string]any{"domain": e.cfg.HTTPSIngress.Domain, "port": 443}
	}
	if e.cfg.DataGateway != nil {
		return map[string]any{"domain": e.cfg.DataGateway.Domain, "port": 443}
	}
	return nil
}
func (e *Engine) applyHTTPSCertificate(managed *ManagedCertificate) error {
	cfg := e.config()
	domain, certPath, keyPath, dir := "", "", "", ""
	if cfg.HTTPSIngress != nil {
		g := cfg.HTTPSIngress
		domain, certPath, keyPath, dir = g.Domain, g.Certificate, g.Key, g.ManagedDirectory
	} else if cfg.DataGateway != nil {
		g := cfg.DataGateway
		domain, certPath, keyPath = g.Domain, g.Certificate, g.Key
	} else {
		return nil
	}
	var certPEM, keyPEM []byte
	var err error
	if managed != nil {
		certPEM, keyPEM = []byte(managed.CertPEM), []byte(managed.KeyPEM)
	} else {
		certPEM, err = os.ReadFile(certPath)
		if err != nil {
			return err
		}
		keyPEM, err = os.ReadFile(keyPath)
		if err != nil {
			return err
		}
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return errors.New("invalid HTTPS key pair")
	}
	if pair.Leaf == nil || pair.Leaf.VerifyHostname(domain) != nil {
		return errors.New("HTTPS certificate hostname mismatch")
	}
	if dir != "" {
		// A single combined PEM makes certificate/key rotation atomic for external Nginx.
		bundle := append(append([]byte{}, certPEM...), keyPEM...)
		path := filepath.Join(dir, "bundle.pem")
		old, _ := os.ReadFile(path)
		if !bytes.Equal(old, bundle) {
			if err = os.MkdirAll(dir, 0700); err != nil {
				return err
			}
			if err = os.WriteFile(path+".tmp", bundle, 0600); err != nil {
				return err
			}
			if err = os.Rename(path+".tmp", path); err != nil {
				return err
			}
		}
	}
	e.publicCert.Store(&pair)
	return nil
}
