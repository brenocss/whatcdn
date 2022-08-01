package main

var WAF_CNAME_DOMAINS = map[string]string{
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

var WAF_WAPPALYZER_TECHNOLOGIES = map[string]string{
	"imperva":    "incapsula",
	"incapsula":  "incapsula",
	"cloudflare": "cloudflare",
	"cloudfront": "amazon",
	"akamai":     "akamai",
}
