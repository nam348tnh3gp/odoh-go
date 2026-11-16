package odoh

import (
	"encoding/binary"
	"testing"
	"time"
)

// A >64 KiB config body whose entry length is 0xFFFC used to make
// UnmarshalObliviousDoHConfigs spin forever (uint16 offset wrapped to itself).
func TestUnmarshalConfigsNoInfiniteLoop(t *testing.T) {
	buf := make([]byte, 65538)
	binary.BigEndian.PutUint16(buf[0:], 1)      // outer length
	binary.BigEndian.PutUint16(buf[2:], 0x0000) // unsupported version
	binary.BigEndian.PutUint16(buf[4:], 0xFFFC) // entry length

	done := make(chan struct{})
	go func() {
		_, _ = UnmarshalObliviousDoHConfigs(buf)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("UnmarshalObliviousDoHConfigs did not terminate")
	}
}

func newTargetContext(t *testing.T) (ObliviousDoHKeyPair, ResponseContext) {
	t.Helper()
	kp, err := CreateDefaultKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	msg, _, err := kp.Config.Contents.EncryptQuery(CreateObliviousDNSQuery([]byte("q"), 0))
	if err != nil {
		t.Fatal(err)
	}
	in, err := UnmarshalDNSMessage(msg.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	_, rctx, err := kp.DecryptQuery(in)
	if err != nil {
		t.Fatal(err)
	}
	return kp, rctx
}

// Oversized answers must return an error, not make Marshal() panic later.
func TestEncryptResponseTooLarge(t *testing.T) {
	_, rctx := newTargetContext(t)

	if _, err := rctx.EncryptResponse(CreateObliviousDNSResponse(make([]byte, 65530), 0)); err == nil {
		t.Fatal("expected error for oversized response")
	}

	out, err := rctx.EncryptResponse(CreateObliviousDNSResponse(make([]byte, 65000), 0))
	if err != nil {
		t.Fatalf("unexpected error for response that fits: %v", err)
	}
	_ = out.Marshal() // must not panic
}

func TestEncryptQueryTooLarge(t *testing.T) {
	kp, err := CreateDefaultKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := kp.Config.Contents.EncryptQuery(CreateObliviousDNSQuery(make([]byte, 65520), 0)); err == nil {
		t.Fatal("expected error for oversized query")
	}
}
