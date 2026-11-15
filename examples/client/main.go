package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/miekg/dns"
	odoh "github.com/nam348tnh3gp/odoh-go"
)

func main() {
	proxyURL := flag.String("proxy", "https://odoh-proxy.example.com/dns-query", "ODoH proxy URL")
	domain := flag.String("domain", "example.com", "domain to query")
	qtype := flag.String("type", "A", "DNS query type")
	insecure := flag.Bool("insecure", false, "skip TLS verify")
	flag.Parse()

	qtypeCode, ok := dns.StringToType[*qtype]
	if !ok {
		log.Fatalf("invalid qtype: %s", *qtype)
	}
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(*domain), qtypeCode)
	wire, err := q.Pack()
	if err != nil {
		log.Fatalf("pack query: %v", err)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecure},
		},
	}

	// Fetch ODoH configs
	cfgURL := *proxyURL
	for i := len(cfgURL) - 1; i >= 0; i-- {
		if cfgURL[i] == '/' {
			cfgURL = cfgURL[:i]
			break
		}
	}
	cfgURL += "/.well-known/odohconfigs"

	resp, err := client.Get(cfgURL)
	if err != nil {
		log.Fatalf("fetch configs: %v", err)
	}
	defer resp.Body.Close()
	cfgBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		log.Fatalf("read configs: %v", err)
	}
	configs, err := odoh.UnmarshalObliviousDoHConfigs(cfgBody)
	if err != nil || len(configs.Configs) == 0 {
		log.Fatalf("parse configs: %v", err)
	}

	// Encrypt query
	odohQuery := odoh.CreateObliviousDNSQuery(wire, 0)
	msg, ctx, err := configs.Configs[0].Contents.EncryptQuery(odohQuery)
	if err != nil {
		log.Fatalf("encrypt query: %v", err)
	}

	// POST to proxy
	req, err := http.NewRequest(http.MethodPost, *proxyURL, bytes.NewReader(msg.Marshal()))
	if err != nil {
		log.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/oblivious-dns-message")
	req.Header.Set("Accept", "application/oblivious-dns-message")

	resp2, err := client.Do(req)
	if err != nil {
		log.Fatalf("do request: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp2.Body, 512))
		log.Fatalf("proxy HTTP %d: %s", resp2.StatusCode, body)
	}
	respBody, err := io.ReadAll(io.LimitReader(resp2.Body, 1<<16))
	if err != nil {
		log.Fatalf("read resp: %v", err)
	}

	// Decrypt response
	odohResp, err := odoh.UnmarshalDNSMessage(respBody)
	if err != nil {
		log.Fatalf("parse ODoH response: %v", err)
	}
	plain, err := ctx.DecryptResponse(odohResp)
	if err != nil {
		log.Fatalf("decrypt response: %v", err)
	}
	// Remove 2-byte length prefix
	if len(plain) < 2 {
		log.Fatal("plaintext too short")
	}
	declared := int(plain[0])<<8 | int(plain[1])
	if 2+declared > len(plain) {
		log.Fatalf("declared length %d + 2 > plaintext %d", declared, len(plain))
	}
	dnsWire := plain[2 : 2+declared]

	r := new(dns.Msg)
	if err := r.Unpack(dnsWire); err != nil {
		log.Fatalf("unpack DNS: %v", err)
	}
	fmt.Printf("RCODE: %s | Answers: %d\n", dns.RcodeToString[r.Rcode], len(r.Answer))
	for _, rr := range r.Answer {
		fmt.Printf("  %s\n", rr.String())
	}
}
