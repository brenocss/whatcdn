package main

import (
	"net/http"

	"github.com/projectdiscovery/retryabledns"
)

type Result struct {
	Input              string                `json:"input,omitempty"`
	InputType          string                `json:"input_type,omitempty"`
	HttpResponse       *http.Response        `json:"-"`
	WappalyzerResponse map[string]struct{}   `json:"-"`
	DnsResponse        *retryabledns.DNSData `json:"-"`
	IPs                []string              `json:"ips,omitempty"`
	CNAMEs             []string              `json:"cnames,omitempty"`
	PTRs               []string              `json:"ptrs,omitempty"`
	HasInternalIps     bool                  `json:"hasInternalIps"`
	InternalIPs        []string              `json:"internal_ips,omitempty"`
	HasCDN             bool                  `json:"hasCDN"`
	DetectedCDNs       []DetectedCDN         `json:"detectedCDNs,omitempty"`
	HasWaf             bool                  `json:"hasWaf"`
	DetectedWaFs       []DetectedWaf         `json:"detectedWAFs,omitempty"`
	HasCloud           bool                  `json:"hasCloud"`
	DetectedCloud      []DetectedCloud       `json:"detectedClouds,omitempty"`
}

type DetectedCDN struct {
	Name                 string   `json:"name,omitempty"`
	DetectionMethod      string   `json:"DetectionMethod,omitempty"`
	DetectedIps          []string `json:"DetectedIps,omitempty"`
	DetectedCNames       []string `json:"DetectedCNames,omitempty"`
	DetectedPTRDomains   []string `json:"DetectedPTRDomains,omitempty"`
	DetectedTechnologies []string `json:"DetectedTechnologies,omitempty"`
}

type DetectedCloud struct {
	Name                 string   `json:"name,omitempty"`
	DetectionMethod      string   `json:"DetectionMethod,omitempty"`
	DetectedIps          []string `json:"DetectedIps,omitempty"`
	DetectedCNames       []string `json:"DetectedCNames,omitempty"`
	DetectedPTRDomains   []string `json:"DetectedPTRDomains,omitempty"`
	DetectedTechnologies []string `json:"DetectedTechnologies,omitempty"`
}

type DetectedWaf struct {
	Name                 string   `json:"name,omitempty"`
	DetectionMethod      string   `json:"DetectionMethod,omitempty"`
	DetectedIps          []string `json:"DetectedIps,omitempty"`
	DetectedCNames       []string `json:"DetectedCNames,omitempty"`
	DetectedPTRDomains   []string `json:"DetectedPTRDomains,omitempty"`
	DetectedTechnologies []string `json:"DetectedTechnologies,omitempty"`
}
