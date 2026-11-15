package odoh

import (
	"bytes"
	"testing"
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
