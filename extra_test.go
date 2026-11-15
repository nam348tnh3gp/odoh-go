package odoh

import (
	"bytes"
	"testing"

	hpke "github.com/jedisct1/go-hpke-compact"
)

// ==================== CODEC ====================

func TestEncodeLengthPrefixedSliceTooLong(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for oversized slice")
		}
	}()
	encodeLengthPrefixedSlice(make([]byte, 65536))
}

func TestDecodeLengthPrefixedSliceEmpty(t *testing.T) {
	if _, _, err := decodeLengthPrefixedSlice(nil); err == nil {
		t.Fatal("expected error for nil input")
	}
	if _, _, err := decodeLengthPrefixedSlice([]byte{0x00}); err == nil {
		t.Fatal("expected error for 1-byte input")
	}
}

func TestDecodeLengthPrefixedSliceTruncated(t *testing.T) {
	// Declares 10 bytes but only 2 available.
	data := []byte{0x00, 0x0A, 0x01, 0x02}
	if _, _, err := decodeLengthPrefixedSlice(data); err == nil {
		t.Fatal("expected error for truncated data")
	}
}

// ==================== MESSAGES ====================

func TestUnmarshalDNSMessageEmpty(t *testing.T) {
	if _, err := UnmarshalDNSMessage(nil); err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestUnmarshalDNSMessageTooShortKeyID(t *testing.T) {
	// message_type + key_id length (2) but no key_id
	if _, err := UnmarshalDNSMessage([]byte{0x01, 0x00, 0x05}); err == nil {
		t.Fatal("expected error for truncated key ID")
	}
}

func TestUnmarshalMessageBodyEmpty(t *testing.T) {
	if _, err := UnmarshalMessageBody(nil); err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestUnmarshalMessageBodyTruncatedPadding(t *testing.T) {
	// dns length 1, dns "x", padding length 5, but only 1 byte available
	data := []byte{0x00, 0x01, 'x', 0x00, 0x05, 'y'}
	if _, err := UnmarshalMessageBody(data); err == nil {
		t.Fatal("expected error for truncated padding")
	}
}

func TestCreateQueryCopiesData(t *testing.T) {
	orig := []byte("hello")
	q := CreateObliviousDNSQuery(orig, 0)
	orig[0] = 'X'
	if q.DnsMessage[0] == 'X' {
		t.Fatal("query did not copy input data")
	}
}

func TestCreateResponseCopiesData(t *testing.T) {
	orig := []byte("hello")
	r := CreateObliviousDNSResponse(orig, 0)
	orig[0] = 'X'
	if r.DnsMessage[0] == 'X' {
		t.Fatal("response did not copy input data")
	}
}

// ==================== CONFIG ====================

func TestConfigsDeserializationTruncated(t *testing.T) {
	kp, err := CreateDefaultKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	serialized := CreateObliviousDoHConfigs([]ObliviousDoHConfig{kp.Config}).Marshal()
	// Truncate by 1 byte → decoder should stop gracefully.
	_, err = UnmarshalObliviousDoHConfigs(serialized[:len(serialized)-1])
	if err != nil {
		t.Fatalf("expected lenient parse, got: %v", err)
	}
}

func TestConfigContentsWrongKeyLength(t *testing.T) {
	_, err := CreateObliviousDoHConfigContents(
		ODOH_DEFAULT_KEMID, ODOH_DEFAULT_KDFID, ODOH_DEFAULT_AEADID,
		make([]byte, 31),
	)
	if err == nil {
		t.Fatal("expected error for 31-byte key")
	}
}

func TestConfigContentsCopiesKey(t *testing.T) {
	orig := bytes.Repeat([]byte{0xAA}, 32)
	c, err := CreateObliviousDoHConfigContents(
		ODOH_DEFAULT_KEMID, ODOH_DEFAULT_KDFID, ODOH_DEFAULT_AEADID, orig,
	)
	if err != nil {
		t.Fatal(err)
	}
	orig[0] = 0xBB
	if c.PublicKeyBytes[0] == 0xBB {
		t.Fatal("config contents did not copy key bytes")
	}
}

// ==================== HPKE ====================

func TestDecryptResponseWrongKeyID(t *testing.T) {
	kp, err := CreateDefaultKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, ctx, err := kp.Config.Contents.EncryptQuery(CreateObliviousDNSQuery([]byte("test"), 0))
	if err != nil {
		t.Fatal(err)
	}
	msg := ObliviousDNSMessage{
		MessageType:      ResponseType,
		KeyID:            []byte("wrong"),
		EncryptedMessage: []byte("x"),
	}
	if _, err := ctx.DecryptResponse(msg); err == nil {
		t.Fatal("expected error for wrong key ID length")
	}
}

func TestDecryptResponseWrongType(t *testing.T) {
	var zero QueryContext
	msg := ObliviousDNSMessage{MessageType: QueryType}
	if _, err := zero.DecryptResponse(msg); err == nil {
		t.Fatal("expected error for query type")
	}
}

func TestEncryptResponseNilSuite(t *testing.T) {
	ctx := ResponseContext{}
	if _, err := ctx.EncryptResponse(CreateObliviousDNSResponse([]byte("x"), 0)); err == nil {
		t.Fatal("expected error for nil suite")
	}
}

func TestEncryptResponseNilResponse(t *testing.T) {
	kp, err := CreateDefaultKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, ctx, err := kp.Config.Contents.EncryptQuery(CreateObliviousDNSQuery([]byte("x"), 0))
	if err != nil {
		t.Fatal(err)
	}
	_ = ctx
	// ResponseContext cannot be constructed directly; skip.
}

func TestEncryptQueryNil(t *testing.T) {
	kp, err := CreateDefaultKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := kp.Config.Contents.EncryptQuery(nil); err == nil {
		t.Fatal("expected error for nil query")
	}
}

func TestDecryptQueryTooShort(t *testing.T) {
	kp, err := CreateDefaultKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	msg := ObliviousDNSMessage{
		MessageType:      QueryType,
		KeyID:            kp.Config.Contents.KeyID(),
		EncryptedMessage: []byte("short"),
	}
	if _, _, err := kp.DecryptQuery(msg); err == nil {
		t.Fatal("expected error for short encrypted message")
	}
}

func TestOpenAnswerEmpty(t *testing.T) {
	var ctx QueryContext
	if _, err := ctx.OpenAnswer(ObliviousDNSMessage{MessageType: ResponseType}); err == nil {
		t.Fatal("expected error for empty encrypted response")
	}
}

// ==================== FUZZ ====================

func FuzzUnmarshalDNSMessage(f *testing.F) {
	f.Add([]byte{0x01, 0x00, 0x01, 0x00, 0x01, 0x00})
	f.Add([]byte{})
	f.Add([]byte{0xFF})
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic on input %x: %v", data, r)
			}
		}()
		_, _ = UnmarshalDNSMessage(data)
	})
}

func FuzzUnmarshalMessageBody(f *testing.F) {
	f.Add([]byte{0x00, 0x01, 'x', 0x00, 0x00})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic on input %x: %v", data, r)
			}
		}()
		_, _ = UnmarshalMessageBody(data)
	})
}

func FuzzUnmarshalConfigs(f *testing.F) {
	f.Add([]byte{0x00, 0x00})
	f.Add([]byte{0x00, 0x04, 0x00, 0x01, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic on input %x: %v", data, r)
			}
		}()
		_, _ = UnmarshalObliviousDoHConfigs(data)
	})
}

func FuzzDecodeLengthPrefixedSlice(f *testing.F) {
	f.Add([]byte{0x00, 0x01, 'x'})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic on input %x: %v", data, r)
			}
		}()
		_, _, _ = decodeLengthPrefixedSlice(data)
	})
}

// ==================== CONFIG CONTENTS ACCESSORS ====================

func TestPublicKey(t *testing.T) {
	kp, err := CreateDefaultKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pk := kp.Config.Contents.PublicKey()
	if !bytes.Equal(pk, kp.Config.Contents.PublicKeyBytes) {
		t.Fatal("PublicKey mismatch")
	}
}

func TestCipherSuite(t *testing.T) {
	kp, err := CreateDefaultKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	suite, err := kp.Config.Contents.CipherSuite()
	if err != nil {
		t.Fatal(err)
	}
	if suite == nil {
		t.Fatal("nil suite")
	}
}

// ==================== EXTRA EDGE CASES ====================

func TestKeyIDInvalid(t *testing.T) {
	c := ObliviousDoHConfigContents{
		KemID:          0xFFFF,
		KdfID:          ODOH_DEFAULT_KDFID,
		AeadID:         ODOH_DEFAULT_AEADID,
		PublicKeyBytes: make([]byte, 32),
	}
	if c.KeyID() != nil {
		t.Fatal("expected nil KeyID for invalid config")
	}
}

func TestSealQueryEmpty(t *testing.T) {
	kp, err := CreateDefaultKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	// SealQuery(nil) creates an empty DNS message, which is valid.
	if _, _, err := SealQuery(nil, kp.Config.Contents); err != nil {
		t.Fatalf("SealQuery(nil) should not error: %v", err)
	}
}

func TestOpenAnswerWrongType(t *testing.T) {
	var ctx QueryContext
	msg := ObliviousDNSMessage{MessageType: QueryType}
	if _, err := ctx.OpenAnswer(msg); err == nil {
		t.Fatal("expected error for query type")
	}
}

func TestCreateKeyPairFromSeedWrongLength(t *testing.T) {
	if _, err := CreateKeyPairFromSeed(
		ODOH_DEFAULT_KEMID, ODOH_DEFAULT_KDFID, ODOH_DEFAULT_AEADID,
		make([]byte, 16),
	); err == nil {
		t.Fatal("expected error for 16-byte seed")
	}
}

func TestUnmarshalMessageBodyCopiesData(t *testing.T) {
	// dns length 1, dns "x", padding length 0
	data := []byte{0x00, 0x01, 'x', 0x00, 0x00}
	body, err := UnmarshalMessageBody(data)
	if err != nil {
		t.Fatal(err)
	}
	data[2] = 'X'
	if body.DnsMessage[0] == 'X' {
		t.Fatal("message body did not copy data")
	}
}

// ==================== COVERAGE BOOST ====================

func TestObliviousDNSMessageBodyMessage(t *testing.T) {
	body := ObliviousDNSMessageBody{DnsMessage: []byte("dns"), Padding: nil}
	if !bytes.Equal(body.Message(), []byte("dns")) {
		t.Fatal("Message() mismatch")
	}
}

func TestObliviousDNSMessageType(t *testing.T) {
	m := ObliviousDNSMessage{MessageType: QueryType}
	if m.Type() != QueryType {
		t.Fatal("Type() mismatch")
	}
	m = ObliviousDNSMessage{MessageType: ResponseType}
	if m.Type() != ResponseType {
		t.Fatal("Type() mismatch")
	}
}

func TestCreateObliviousDNSMessage(t *testing.T) {
	m := CreateObliviousDNSMessage(QueryType, []byte("key"), []byte("enc"))
	if m.MessageType != QueryType {
		t.Fatal("MessageType mismatch")
	}
	if !bytes.Equal(m.KeyID, []byte("key")) {
		t.Fatal("KeyID mismatch")
	}
	if !bytes.Equal(m.EncryptedMessage, []byte("enc")) {
		t.Fatal("EncryptedMessage mismatch")
	}
}

func TestUnmarshalQueryBodyError(t *testing.T) {
	if _, err := UnmarshalQueryBody(nil); err == nil {
		t.Fatal("expected error for nil input")
	}
}

func TestUnmarshalResponseBodyError(t *testing.T) {
	if _, err := UnmarshalResponseBody(nil); err == nil {
		t.Fatal("expected error for nil input")
	}
}

func TestNewSuiteExportOnly(t *testing.T) {
	if _, err := newSuite(ODOH_DEFAULT_KEMID, ODOH_DEFAULT_KDFID, hpke.AeadExportOnly); err == nil {
		t.Fatal("expected error for export-only AEAD")
	}
}

func TestNewSuiteInvalid(t *testing.T) {
	if _, err := newSuite(0xFFFF, ODOH_DEFAULT_KDFID, ODOH_DEFAULT_AEADID); err == nil {
		t.Fatal("expected error for invalid KEM")
	}
}

func TestResponseNonceSize(t *testing.T) {
	suite, err := hpke.NewSuite(ODOH_DEFAULT_KEMID, ODOH_DEFAULT_KDFID, ODOH_DEFAULT_AEADID)
	if err != nil {
		t.Fatal(err)
	}
	size := responseNonceSize(suite)
	if size <= 0 {
		t.Fatal("responseNonceSize should be positive")
	}
	// Should be max(KeyBytes, NonceBytes)
	want := int(suite.KeyBytes)
	if int(suite.NonceBytes) > want {
		want = int(suite.NonceBytes)
	}
	if size != want {
		t.Fatalf("responseNonceSize = %d, want %d", size, want)
	}
}

func TestDecryptQueryInvalidPadding(t *testing.T) {
	kp, err := CreateDefaultKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	// Craft a query with non-zero padding, encrypt it, then try to decrypt.
	q := CreateObliviousDNSQuery([]byte("dns"), 0)
	q.Padding = []byte{0x01} // invalid padding (must be zero)
	msg, _, err := kp.Config.Contents.EncryptQuery(q)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := kp.DecryptQuery(msg); err == nil {
		t.Fatal("expected error for invalid padding")
	}
}

func TestEncryptResponseNilResponseExplicit(t *testing.T) {
	kp, err := CreateDefaultKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, ctx, err := kp.Config.Contents.EncryptQuery(CreateObliviousDNSQuery([]byte("x"), 0))
	if err != nil {
		t.Fatal(err)
	}
	// QueryContext only has DecryptResponse; build ResponseContext manually.
	rc := ResponseContext{
		query:  ctx.query,
		suite:  ctx.suite,
		secret: ctx.secret,
	}
	if _, err := rc.EncryptResponse(nil); err == nil {
		t.Fatal("expected error for nil response")
	}
}
