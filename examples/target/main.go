package main

import (
	"crypto/subtle"
	"encoding/hex"
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
	port := flag.String("port", "8080", "listen port")
	seedHex := flag.String("seed", "", "32-byte ODoH seed (64 hex chars)")
	flag.Parse()

	if *seedHex == "" {
		log.Fatal("missing -seed (generate with: openssl rand -hex 32)")
	}
	seed, err := hex.DecodeString(*seedHex)
	if err != nil || len(seed) != 32 {
		log.Fatal("seed must be 64 hex chars (32 bytes)")
	}
	kp, err := odoh.CreateDefaultKeyPairFromSeed(seed)
	if err != nil {
		log.Fatalf("create key pair: %v", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/odohconfigs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Write(odoh.CreateObliviousDoHConfigs([]odoh.ObliviousDoHConfig{kp.Config}).Marshal())
	})

	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 65535))
		if err != nil {
			http.Error(w, "invalid body", http.StatusBadRequest)
			return
		}
		msg, err := odoh.UnmarshalDNSMessage(raw)
		if err != nil {
			http.Error(w, "invalid ODoH message", http.StatusBadRequest)
			return
		}
		kid := kp.Config.Contents.KeyID()
		if subtle.ConstantTimeCompare(msg.KeyID, kid) != 1 {
			http.Error(w, "unknown key id", http.StatusBadRequest)
			return
		}
		qb, ctx, err := kp.DecryptQuery(msg)
		if err != nil {
			http.Error(w, "decrypt failed", http.StatusBadRequest)
			return
		}
		q := new(dns.Msg)
		if err := q.Unpack(qb.DnsMessage); err != nil {
			http.Error(w, "invalid DNS query", http.StatusBadRequest)
			return
		}
		// Mock answer: return NXDOMAIN
		reply := new(dns.Msg)
		reply.SetReply(q)
		reply.Rcode = dns.RcodeNameError
		answer, _ := reply.Pack()

		out, err := ctx.EncryptResponse(odoh.CreateObliviousDNSResponse(answer, 0))
		if err != nil {
			http.Error(w, "encrypt response failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/oblivious-dns-message")
		w.Write(out.Marshal())
	})

	srv := &http.Server{
		Addr:              ":" + *port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      12 * time.Second,
	}
	fmt.Printf("ODoH target listening on :%s\n", *port)
	log.Fatal(srv.ListenAndServe())
}
