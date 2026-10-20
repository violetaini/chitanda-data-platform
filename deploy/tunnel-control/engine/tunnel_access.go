package main

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
)

type TunnelAccess struct {
	TunnelID   string `json:"tunnelId"`
	RouteID    string `json:"routeId"`
	Domain     string `json:"domain"`
	ListenPort int    `json:"listenPort"`
	Token      string `json:"token"`
}

func tunnelAccessAllowed(r *http.Request, grants []TunnelAccess, port int) bool {
	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	for _, g := range grants {
		if g.Domain == host && g.ListenPort == port && len(g.Token) == 64 && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+g.Token)) == 1 {
			return true
		}
	}
	return false
}
func readTunnelAccess(file string) []TunnelAccess {
	f, err := os.Open(file)
	if err != nil {
		return nil
	}
	defer f.Close()
	var grants []TunnelAccess
	// A dedicated file contains only business grants, never node credentials.
	if json.NewDecoder(io.LimitReader(f, 131073)).Decode(&grants) != nil {
		return nil
	}
	return grants
}

func writeTunnelAccess(file string, grants []TunnelAccess) error {
	if file == "" {
		return nil
	}
	if grants == nil {
		grants = []TunnelAccess{}
	}
	raw, err := json.Marshal(grants)
	if err != nil {
		return err
	}
	if err = os.WriteFile(file+".tmp", raw, 0640); err != nil {
		return err
	}
	if err = os.Chmod(file+".tmp", 0640); err != nil {
		return err
	}
	return os.Rename(file+".tmp", file)
}
