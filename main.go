package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/iputil"
	"github.com/projectdiscovery/retryabledns"
	"github.com/projectdiscovery/retryablehttp-go"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

var wg sync.WaitGroup

var DEFAULT_RESOLVERS = []string{"8.8.8.8:53", "8.8.4.4:53"}

type WHATCDN struct {
	dnsClient        *retryabledns.Client
	httpClient       *retryablehttp.Client
	wappalyzerClient *wappalyzer.Wappalyze
	cdncheckClient   *cdncheck.Client
	resolvers        []string
	retries          int
	http_fallback    bool
	json_output      bool
}

var whatcdn WHATCDN

func main() {
	// usage ./whatcdn -i <192.168.0.1-> <-json>
	// usage cat inputs | ./whatcdn  <-t 100> <-json>

	var (
		input         string
		max_threads   int
		json_output   bool
		max_retries   int
		http_fallback bool
	)

	flag.StringVar(&input, "i", "", "input to resolve/check")
	flag.IntVar(&max_threads, "t", 10, "number of threads")
	flag.BoolVar(&json_output, "json", false, "print json output")
	flag.BoolVar(&http_fallback, "http-fallback", false, "print json output")
	flag.IntVar(&max_retries, "retries", 3, "number of retries")
	// receber uma lista de resolvers
	flag.Parse()

	HTTPOpts := retryablehttp.Options{
		RetryWaitMin:  1 * time.Second,
		RetryWaitMax:  30 * time.Second,
		Timeout:       30 * time.Second,
		RetryMax:      max_retries,
		RespReadLimit: 4096 * 5,
		KillIdleConn:  true,
	}

	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		log.Fatal(err)
	}

	cdncheckClient, err := cdncheck.NewWithCache()
	if err != nil {
		log.Fatal(err)
	}

	dnsClient, err := retryabledns.New(DEFAULT_RESOLVERS, max_retries)
	if err != nil {
		log.Fatal(err)
	}

	whatcdn = WHATCDN{
		resolvers:        DEFAULT_RESOLVERS,
		retries:          max_retries,
		dnsClient:        dnsClient,
		httpClient:       retryablehttp.NewClient(HTTPOpts),
		wappalyzerClient: wappalyzerClient,
		cdncheckClient:   cdncheckClient,
		http_fallback:    http_fallback,
		json_output:      json_output,
	}

	goroutines := make(chan struct{}, max_threads)
	if input != "" {
		goroutines <- struct{}{}
		wg.Add(1)
		go worker(input, goroutines)
	} else {
		stdin := os.Stdin
		scanner := bufio.NewScanner(stdin)
		for scanner.Scan() {
			// check if input is a comment
			line := scanner.Text()
			if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
				continue
			}
			goroutines <- struct{}{}
			wg.Add(1)
			go worker(line, goroutines)
		}
	}
	wg.Wait()
	close(goroutines)
}

func worker(input string, goroutines <-chan struct{}) {

	result := new(Result)
	result.Input = input

	defer wg.Done()
	// global variables
	var (
		input_type string
		err        error
	)

	input_type = detect_input_type(input)
	result.InputType = input_type

	switch input_type {
	case "ip":
		_, _, _, err = check_cdn_ip(input, result)
		_, _, _, _ = check_cloud_ip(input, result)
	case "domain":
		_, _, _, err = check_cdn_domain(input, result)
		_, _, _, _ = check_cloud_domain(input, result)
	case "url":
		_, _, _, err = check_cdn_url(input, result)
		_, _, _, _ = check_cloud_url(input, result)
	case "":
		err = fmt.Errorf("invalid input: %s", input)
	}

	if err != nil {
		log.Printf("[ERROR] %s", err)
		<-goroutines
		return
	}

	if whatcdn.json_output {
		output_bytes, err := json.Marshal(result)
		if err != nil {
			log.Printf("[ERROR] %s", err)
			<-goroutines
			return
		}
		fmt.Println(string(output_bytes))
	} else {
		format_txt_output(result)
	}

	<-goroutines
}

/* hackerone.com domain cloudflare ip*/
func format_txt_output(result *Result) {
	if !result.HasCDN {
		fmt.Printf("%s cdn not detected\n", result.Input)
	}
	if !result.HasCloud {
		fmt.Printf("%s cloud not detected\n", result.Input)
	}
	if result.HasCDN {
		for _, cdn := range result.DetectedCDNs {
			fmt.Printf("%s cdnName: %s detectionMethod: %s\n", result.Input, cdn.Name, cdn.DetectionMethod)
		}
	}
	if result.HasCloud {
		for _, cloud := range result.DetectedCloud {
			fmt.Printf("%s cloudName: %s detectionMethod: %s\n", result.Input, cloud.Name, cloud.DetectionMethod)
		}
	}
}

func detect_input_type(input string) string {
	if iputil.IsIP(input) {
		return "ip"
	}
	if strings.HasPrefix(input, "https://") || strings.HasPrefix(input, "http://") {
		return "url"
	}
	if govalidator.IsDNSName(input) {
		return "domain"
	}
	return ""
}
