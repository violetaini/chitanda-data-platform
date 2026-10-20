package main

import (
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type PortInventory struct {
	TCP        []int  `json:"tcp"`
	Complete   bool   `json:"complete"`
	ObservedAt string `json:"observedAt"`
}

func parseListeningPorts(raw []byte, ports map[int]bool) {
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[3] != "0A" {
			continue
		}
		local := strings.Split(fields[1], ":")
		if len(local) != 2 {
			continue
		}
		p, err := strconv.ParseUint(local[1], 16, 16)
		if err == nil && p > 0 {
			ports[int(p)] = true
		}
	}
}
func collectPorts() PortInventory {
	out := PortInventory{TCP: []int{}, Complete: true, ObservedAt: time.Now().UTC().Format(time.RFC3339)}
	ports := map[int]bool{}
	for i, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			if i == 0 || !os.IsNotExist(err) {
				out.Complete = false
			}
			continue
		}
		parseListeningPorts(raw, ports)
	}
	for port := range ports {
		out.TCP = append(out.TCP, port)
	}
	sort.Ints(out.TCP)
	if len(out.TCP) > 4096 {
		out.TCP = out.TCP[:4096]
		out.Complete = false
	}
	return out
}
