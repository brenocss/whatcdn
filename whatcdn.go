package main

import (
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/projectdiscovery/retryabledns"
)

var CDN_CNAME_DOMAINS = map[string]string{
	"cloudfront.net":         "amazon",
	"amazonaws.com":          "amazon",
	"edgekey.net":            "akamai",
	"akamaiedge.net":         "akamai",
	"akamaitechnologies.com": "akamai",
	"akamaihd.net":           "akamai",
	"cloudflare.com":         "cloudflare",
	"fastly.net":             "fastly",
	"edgecastcdn.net":        "edgecast",
	"impervadns.net":         "incapsula",
}

var CDN_WAPPALYZER_TECHNOLOGIES = map[string]string{
	"imperva":    "incapsula",
	"incapsula":  "incapsula",
	"cloudflare": "cloudflare",
	"cloudfront": "amazon",
	"akamai":     "akamai",
}

func check_cdn_url(input string, result *Result) (isCDN bool, CDNName string, detectionType string, err error) {
	var response *http.Response
	url_parsed, err := url.Parse(input)
	if err != nil {
		return
	}
	url_domain := url_parsed.Hostname()
	isCDN, CDNName, detectionType, err = check_cdn_domain(url_domain, result)

	if !isCDN {
		if result.HttpResponse == nil {
			response, err = whatcdn.httpClient.Get(input)
			if err != nil {
				return
			}
			result.HttpResponse = response
		}
		isCDN, CDNName, detectionType, err = check_cdn_with_http_response(result.HttpResponse, result)
	}

	return isCDN, CDNName, detectionType, err
}
func check_cdn_domain(input string, result *Result) (isCDN bool, CDNName string, detectionType string, err error) {
	var response *http.Response
	var dnsresponse *retryabledns.DNSData
	if result.DnsResponse == nil {
		dnsresponse, err = whatcdn.dnsClient.Resolve(input)
		if err != nil {
			return
		}
		result.DnsResponse = dnsresponse
	}

	isCDN, CDNName, detectionType, err = check_cdn_with_dns(result.DnsResponse, result)

	if !isCDN && whatcdn.http_fallback {
		if result.HttpResponse == nil {
			response, err = whatcdn.httpClient.Get("https://" + input)
			if err != nil {
				return
			}
			result.HttpResponse = response
		}
		isCDN, CDNName, detectionType, err = check_cdn_with_http_response(result.HttpResponse, result)
	}

	return isCDN, CDNName, detectionType, err
}

func check_cdn_ip(input string, result *Result) (isCDN bool, CDNName string, detectionType string, err error) {
	return ip_list_cdn_check([]string{input}, result)
}

func ip_list_cdn_check(ips []string, result *Result) (isCDN bool, CDNName string, detectionType string, err error) {
	if result.InputType != "ip" && result.IPs == nil {
		result.IPs = ips
	}
	var (
		dns_response *retryabledns.DNSData
		internalIPs  []string
	)
	for _, ip := range ips {
		ip_parsed := net.ParseIP(ip)
		if ip_parsed == nil {
			log.Printf("invalid IP: %s", ip)
			continue
		}
		/* change here to check for internal ip */
		if ip_parsed.IsPrivate() {
			log.Printf("[*] private IP: %s", ip)
			internalIPs = append(internalIPs, ip)
			continue
		}
		// check if this ip is a CDN
		isCDN, CDNName, err = whatcdn.cdncheckClient.Check(ip_parsed)
		if err != nil {
			return
		}
		if isCDN {
			detectionType = "ip"
			result.HasCDN = true
			detectedCDN := DetectedCDN{
				Name:            CDNName,
				DetectionMethod: detectionType,
				DetectedIps:     []string{ip},
			}
			result.DetectedCDNs = append(result.DetectedCDNs, detectedCDN)
			break
		} else {
			dns_response, err = whatcdn.dnsClient.PTR(ip)
			if err != nil {
				return
			}
			isCDN, CDNName, detectionType, err = check_cdn_with_dns(dns_response, result)
			if err != nil {
				return
			}
		}
	}
	if len(internalIPs) > 0 && result.InputType != "ip" {
		result.HasInternalIps = true
		result.InternalIPs = internalIPs
	}
	return isCDN, CDNName, detectionType, err
}

func cname_list_cdn_check(cname_list []string, result *Result) (isCDN bool, CDNName string, detectionType string) {
	for _, cname := range cname_list {
		// check if this cname ends with a CDN domain
		for cdn_domain, cdn_name_iter := range CDN_CNAME_DOMAINS {
			if strings.HasSuffix(cname, cdn_domain) {
				isCDN = true
				CDNName = cdn_name_iter
				detectionType = "cname"
				result.HasCDN = true
				detectedCDN := DetectedCDN{
					Name:               CDNName,
					DetectionMethod:    detectionType,
					DetectedPTRDomains: []string{cname},
				}
				result.DetectedCDNs = append(result.DetectedCDNs, detectedCDN)
				return
			}
		}
	}
	return isCDN, CDNName, detectionType
}

func ptr_list_cdn_check(ptr_list []string, result *Result) (isCDN bool, CDNName string, detectionType string) {
	// var cdn_detected_ptr []string
	for _, ptr_domain := range ptr_list {
		// check if this ptr ends with a CDN domain
		for cdn_domain, cdn_name_iter := range CDN_CNAME_DOMAINS {
			if strings.HasSuffix(ptr_domain, cdn_domain) {
				isCDN = true
				CDNName = cdn_name_iter
				detectionType = "ptr"
				result.HasCDN = true
				detectedCDN := DetectedCDN{
					Name:               CDNName,
					DetectionMethod:    detectionType,
					DetectedPTRDomains: []string{ptr_domain},
				}
				result.DetectedCDNs = append(result.DetectedCDNs, detectedCDN)
				return
			}
		}
	}
	return isCDN, CDNName, detectionType
}

func check_cdn_with_dns(dnsResponse *retryabledns.DNSData, result *Result) (isCDN bool, CDNName string, detectionType string, err error) {
	if result.DnsResponse == nil {
		result.DnsResponse = dnsResponse
	}

	if dnsResponse.PTR != nil {
		if result.PTRs == nil {
			result.PTRs = dnsResponse.PTR
		}
		if !isCDN {
			isCDN, CDNName, detectionType = ptr_list_cdn_check(result.PTRs, result)
		}
	}

	if dnsResponse.CNAME != nil {
		if result.CNAMEs == nil {
			result.CNAMEs = dnsResponse.CNAME
		}
		if !isCDN {
			isCDN, CDNName, detectionType = cname_list_cdn_check(result.CNAMEs, result)
		}
	}

	if dnsResponse.A != nil {
		if result.IPs == nil {
			result.IPs = dnsResponse.A
		}
		if !isCDN {
			isCDN, CDNName, detectionType, err = ip_list_cdn_check(result.IPs, result)
		}
	}

	// if in_ipv6_list(dnsResponse.AAAA) {
	// 	return true
	// }
	return isCDN, CDNName, detectionType, err
}

func check_cdn_with_wappalyzerResponse(wappalyzerResponse map[string]struct{}, result *Result) (isCDN bool, CDNName string, detectionType string) {
	// matches := wappalyzerClient.Fingerprint(httpResponse.Header, body)
	for technology := range wappalyzerResponse {
		for cdn_tech, cdn_name_iter := range CDN_WAPPALYZER_TECHNOLOGIES {
			// check if technology.lower contains a CDN technology
			if strings.Contains(strings.ToLower(technology), cdn_tech) {
				isCDN = true
				CDNName = cdn_name_iter
				detectionType = "http"
				result.HasCDN = true
				detectedCDN := DetectedCDN{
					Name:                 CDNName,
					DetectionMethod:      detectionType,
					DetectedTechnologies: []string{technology},
				}
				result.DetectedCDNs = append(result.DetectedCDNs, detectedCDN)
				return
			}
		}
	}
	return isCDN, CDNName, detectionType
}

func check_cdn_with_http_response(httpResponse *http.Response, result *Result) (isCDN bool, CDNName string, detectionType string, err error) {
	body, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return
	}

	if result.WappalyzerResponse == nil {
		result.WappalyzerResponse = whatcdn.wappalyzerClient.Fingerprint(httpResponse.Header, body)
	}

	isCDN, CDNName, detectionType = check_cdn_with_wappalyzerResponse(result.WappalyzerResponse, result)

	return isCDN, CDNName, detectionType, err
}
