package odoh_test

import (
	"fmt"
	"log"

	odoh "github.com/nam348tnh3gp/odoh-go"
)

// ExampleCreateDefaultKeyPair minh họa cách tạo key pair.
func ExampleCreateDefaultKeyPair() {
	seed := make([]byte, 32)
	kp, err := odoh.CreateDefaultKeyPairFromSeed(seed)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("KEM=%04x KDF=%04x AEAD=%04x\n",
		kp.Config.Contents.KemID,
		kp.Config.Contents.KdfID,
		kp.Config.Contents.AeadID)
	// Output: KEM=0020 KDF=0001 AEAD=0001
}

// ExampleSealQuery minh họa encrypt query.
func ExampleSealQuery() {
	kp, _ := odoh.CreateDefaultKeyPairFromSeed(make([]byte, 32))
	msg, _, err := odoh.SealQuery([]byte("dns-query-bytes"), kp.Config.Contents)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("encrypted=%d keyID=%d\n", len(msg.EncryptedMessage), len(msg.KeyID))
}

// ExampleCreateObliviousDNSQuery minh họa tạo query body.
func ExampleCreateObliviousDNSQuery() {
	q := odoh.CreateObliviousDNSQuery([]byte("dns"), 0)
	fmt.Printf("dns=%d padding=%d\n", len(q.DnsMessage), len(q.Padding))
	// Output: dns=3 padding=0
}
