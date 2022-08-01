# whatcdn
Whatcdn is a tool that tries to detect if an IP/domain/URL uses a CDN or Cloud. 
- The type of detection of this tool does only simple HTTP and DNS requests(A,CNAME,PTR) or using a CIDR list
- This repository is mainly a laboratory to implement and give suggestions to https://github.com/projectdiscovery/cdncheck
- "I've read the code and have concluded that you're a noob. It is the shittiest program ever.
Sorry. - http://1u.ms/"

Heavily inspired by:
- https://github.com/projectdiscovery/cdncheck 
- https://github.com/99designs/clouddetect

## Install
```bash
go install github.com/brenocss/whatcdn@latest
```

## Usage
```bash
echo cloudflare.com | ./whatcdn -t 20 -json
```
