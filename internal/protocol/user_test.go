package protocol

import (
	"encoding/base64"
	"regexp"
	"testing"
)

func TestUserCredentials(t *testing.T) {
	alice := User{Name: "alice", Secret: "alice-secret-0123456789"}
	bob := User{Name: "bob", Secret: "bob-secret-0123456789"}

	if alice.Password("anytls") != alice.Password("anytls") {
		t.Fatal("credentials must be deterministic")
	}
	if alice.Password("anytls") == alice.Password("hysteria2") || alice.Password("anytls") == bob.Password("anytls") {
		t.Fatal("credentials must differ per protocol and per user")
	}
	if len(alice.Password("x")) != 24 {
		t.Fatalf("password length: %q", alice.Password("x"))
	}
	if u := alice.UUID("tuic"); !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(u) {
		t.Fatalf("not a v4 UUID: %s", u)
	}
	for _, n := range []int{16, 32} {
		raw, err := base64.StdEncoding.DecodeString(alice.Key("ss2022", n))
		if err != nil || len(raw) != n {
			t.Fatalf("key of %d bytes: %v %d", n, err, len(raw))
		}
	}
	if alice.Key("ss2022", 16) == alice.Key("ss2022", 32)[:24] {
		t.Fatal("keys of different lengths should be derived independently")
	}
}
