package main

import (
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/99designs/clouddetect"
	"github.com/projectdiscovery/retryabledns"
	"golang.org/x/exp/slices"
)

var cloudNames = []string{
	"azure",
	"amazon",
	"google",
	"oracle",
}

var CLOUD_CNAME_DOMAINS = map[string]string{
	"cloudfront.net": "amazon",
	"amazonaws.com":  "amazon",
}

var CLOUD_WAPPALYZER_TECHNOLOGIES = map[string]string{
	"cloudfront": "amazon",
}

func check_cloud_url(input string, result *Result) (isCloud bool, cloudName string, detectionType string, err error) {
	var response *http.Response
	url_parsed, err := url.Parse(input)
	if err != nil {
		return
	}
	url_domain := url_parsed.Hostname()
	isCloud, cloudName, detectionType, err = check_cloud_domain(url_domain, result)

	if !isCloud {
		if result.HttpResponse == nil {
			response, err = whatcdn.httpClient.Get(input)
			if err != nil {
				return
			}
			result.HttpResponse = response
		}
		isCloud, cloudName, detectionType, err = check_cloud_with_http_response(result.HttpResponse, result)
	}

	return isCloud, cloudName, detectionType, err
}
func check_cloud_domain(input string, result *Result) (isCloud bool, cloudName string, detectionType string, err error) {
	var response *http.Response
	var dnsresponse *retryabledns.DNSData
	if result.DnsResponse == nil {
		dnsresponse, err = whatcdn.dnsClient.Resolve(input)
		if err != nil {
			return
		}
		result.DnsResponse = dnsresponse
	}

	isCloud, cloudName, detectionType, err = check_cloud_with_dns(result.DnsResponse, result)

	if !isCloud && whatcdn.http_fallback {
		if result.HttpResponse == nil {
			response, err = whatcdn.httpClient.Get("https://" + input)
			if err != nil {
				return
			}
			result.HttpResponse = response
		}
		isCloud, cloudName, detectionType, err = check_cloud_with_http_response(result.HttpResponse, result)
	}

	return isCloud, cloudName, detectionType, err
}

func check_cloud_ip(input string, result *Result) (isCloud bool, cloudName string, detectionType string, err error) {
	return ip_list_cloud_check([]string{input}, result)
}

func ip_list_cloud_check(ips []string, result *Result) (isCloud bool, cloudName string, detectionType string, err error) {
	if result.InputType != "ip" && result.IPs == nil {
		result.IPs = ips
	}
	var (
		dns_response *retryabledns.DNSData
		internalIPs  []string
		cloud        *clouddetect.Response
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
		// check if this ip is a CLOUD
		isCloud, cloudName, err = whatcdn.cdncheckClient.Check(ip_parsed)
		if err != nil {
			return
		}
		if isCloud && slices.Contains(cloudNames, cloudName) {
			detectionType = "ip"
			result.HasCloud = true
			detectedCloud := DetectedCloud{
				Name:            cloudName,
				DetectionMethod: detectionType,
				DetectedIps:     []string{ip},
			}
			result.DetectedCloud = append(result.DetectedCloud, detectedCloud)
			break
		} else {
			cloud, err = clouddetect.Resolve(ip_parsed)
			if err != nil {
				return
			}
			if cloud.ProviderName != "" {
				cloudName = cloud.ProviderName
				isCloud = true
				detectionType = "ip"
				result.HasCloud = true
				detectedCloud := DetectedCloud{
					Name:            cloud.ProviderName,
					DetectionMethod: detectionType,
					DetectedIps:     []string{ip},
				}
				result.DetectedCloud = append(result.DetectedCloud, detectedCloud)
				break
			} else {
				dns_response, err = whatcdn.dnsClient.PTR(ip)
				if err != nil {
					return
				}
				isCloud, cloudName, detectionType, err = check_cloud_with_dns(dns_response, result)
				if err != nil {
					return
				}
			}
		}
	}
	if len(internalIPs) > 0 && result.InputType != "ip" {
		result.HasInternalIps = true
		result.InternalIPs = internalIPs
	}
	return isCloud, cloudName, detectionType, err
}

func cname_list_cloud_check(cname_list []string, result *Result) (isCloud bool, cloudName string, detectionType string) {
	for _, cname := range cname_list {
		// check if this cname ends with a CLOUD domain
		for cloud_domain, cloud_name_iter := range CLOUD_CNAME_DOMAINS {
			if strings.HasSuffix(cname, cloud_domain) {
				isCloud = true
				cloudName = cloud_name_iter
				detectionType = "cname"
				result.HasCloud = true
				detectedCloud := DetectedCloud{
					Name:               cloudName,
					DetectionMethod:    detectionType,
					DetectedPTRDomains: []string{cname},
				}
				result.DetectedCloud = append(result.DetectedCloud, detectedCloud)
				return
			}
		}
	}
	return isCloud, cloudName, detectionType
}

func ptr_list_cloud_check(ptr_list []string, result *Result) (isCloud bool, cloudName string, detectionType string) {
	// var cloud_detected_ptr []string
	for _, ptr_domain := range ptr_list {
		// check if this ptr ends with a Cloud domain
		for cloud_domain, cloud_name_iter := range CLOUD_CNAME_DOMAINS {
			if strings.HasSuffix(ptr_domain, cloud_domain) {
				isCloud = true
				cloudName = cloud_name_iter
				detectionType = "ptr"
				result.HasCloud = true
				detectedCloud := DetectedCloud{
					Name:               cloudName,
					DetectionMethod:    detectionType,
					DetectedPTRDomains: []string{ptr_domain},
				}
				result.DetectedCloud = append(result.DetectedCloud, detectedCloud)
				return
			}
		}
	}
	return isCloud, cloudName, detectionType
}

func check_cloud_with_dns(dnsResponse *retryabledns.DNSData, result *Result) (isCloud bool, cloudName string, detectionType string, err error) {
	if result.DnsResponse == nil {
		result.DnsResponse = dnsResponse
	}

	if dnsResponse.PTR != nil {
		if result.PTRs == nil {
			result.PTRs = dnsResponse.PTR
		}
		if !isCloud {
			isCloud, cloudName, detectionType = ptr_list_cloud_check(result.PTRs, result)
		}
	}

	if dnsResponse.CNAME != nil {
		if result.CNAMEs == nil {
			result.CNAMEs = dnsResponse.CNAME
		}
		if !isCloud {
			isCloud, cloudName, detectionType = cname_list_cloud_check(result.CNAMEs, result)
		}
	}

	if dnsResponse.A != nil {
		if result.IPs == nil {
			result.IPs = dnsResponse.A
		}
		if !isCloud {
			isCloud, cloudName, detectionType, err = ip_list_cloud_check(result.IPs, result)
		}
	}

	// if in_ipv6_list(dnsResponse.AAAA) {
	// 	return true
	// }
	return isCloud, cloudName, detectionType, err
}

func check_cloud_with_wappalyzerResponse(wappalyzerResponse map[string]struct{}, result *Result) (isCloud bool, cloudName string, detectionType string) {
	// matches := wappalyzerClient.Fingerprint(httpResponse.Header, body)
	for technology := range wappalyzerResponse {
		for cloud_tech, cloud_name_iter := range CLOUD_WAPPALYZER_TECHNOLOGIES {
			// check if technology.lower contains a CDN technology
			if strings.Contains(strings.ToLower(technology), cloud_tech) {
				isCloud = true
				cloudName = cloud_name_iter
				detectionType = "http"
				result.HasCloud = true
				detectedCloud := DetectedCloud{
					Name:                 cloudName,
					DetectionMethod:      detectionType,
					DetectedTechnologies: []string{technology},
				}
				result.DetectedCloud = append(result.DetectedCloud, detectedCloud)
				return
			}
		}
	}
	return isCloud, cloudName, detectionType
}

func check_cloud_with_http_response(httpResponse *http.Response, result *Result) (isCloud bool, cloudName string, detectionType string, err error) {
	body, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return
	}

	if result.WappalyzerResponse == nil {
		result.WappalyzerResponse = whatcdn.wappalyzerClient.Fingerprint(httpResponse.Header, body)
	}

	isCloud, cloudName, detectionType = check_cloud_with_wappalyzerResponse(result.WappalyzerResponse, result)

	return isCloud, cloudName, detectionType, err
}
