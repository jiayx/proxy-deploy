package secrets

import (
	"regexp"
	"testing"
)

func TestUUID(t *testing.T) {
	if u := UUID(); !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(u) {
		t.Fatalf("not a v4 UUID: %s", u)
	}
}

func TestRealityKeyPair(t *testing.T) {
	priv, pub := RealityKeyPair()
	if len(priv) != 43 || len(pub) != 43 {
		t.Fatalf("keys should be 43-char base64url: %q %q", priv, pub)
	}
	got, err := RealityPublicKey(priv)
	if err != nil || got != pub {
		t.Fatalf("derived public key %q, want %q (%v)", got, pub, err)
	}
	if _, err := RealityPublicKey("not-a-key"); err == nil {
		t.Fatal("invalid private key should be rejected")
	}
}

func TestShortID(t *testing.T) {
	if s := ShortID(); !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(s) {
		t.Fatalf("unexpected short id %q", s)
	}
}
