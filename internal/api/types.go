package api

import "github.com/mrkhachaturov/docker-external-dns/transport-rfc2136/internal/dnsop"

type RecordsRequest struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	Zone string `json:"zone"`
}

type ApplyRequest struct {
	Host          string         `json:"host"`
	Port          int            `json:"port"`
	Zone          string         `json:"zone"`
	Prerequisites []dnsop.Prereq `json:"prerequisites"`
	Changes       []dnsop.Change `json:"changes"`
}

type HealthResponse struct {
	OK       bool   `json:"ok"`
	Kerberos string `json:"kerberos"`
	Detail   string `json:"detail"`
}
