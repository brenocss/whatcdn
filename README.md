# whatcdn
Whatcdn is a tool that tries to detect if an IP/domain/URL uses a CDN or Cloud. 
- This tool only makes use of simple HTTP/DNS (A,CNAME,PTR) requests and CIDR lists as its detection method.
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
echo cloudflare.com | whatcdn -t 20 -json
cat tests/input.txt | whatcdn -t 20 -json | jq
```
## Contributors
Special thanks to [@clapbr](https://github.com/clapbr) and [@caueobici](https://github.com/caueobici)
