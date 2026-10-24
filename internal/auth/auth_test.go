package auth

import (
	"strings"
	"testing"
)

func TestVerifierRoundTrip(t *testing.T) {
	verifier, err := Verifier("proof-derived-from-a-master-password", "pepper-secret-at-least-32-characters")
	if err != nil {
		t.Fatal(err)
	}
	if !Verify("proof-derived-from-a-master-password", verifier, "pepper-secret-at-least-32-characters") {
		t.Fatal("expected verifier to accept the original proof")
	}
	if Verify("wrong-proof-derived-from-password", verifier, "pepper-secret-at-least-32-characters") {
		t.Fatal("expected verifier to reject a different proof")
	}
	// Ensure Base64 case tampering is rejected (regression test for strings.EqualFold bug).
	parts := strings.Split(verifier, "$")
	lastChar := parts[4][len(parts[4])-1]
	var flipped byte
	if lastChar >= 'a' && lastChar <= 'z' {
		flipped = lastChar - 32
	} else if lastChar >= 'A' && lastChar <= 'Z' {
		flipped = lastChar + 32
	}
	if flipped != 0 {
		parts[4] = parts[4][:len(parts[4])-1] + string(flipped)
		tampered := strings.Join(parts, "$")
		if Verify("proof-derived-from-a-master-password", tampered, "pepper-secret-at-least-32-characters") {
			t.Fatal("expected case-tampered base64 verifier to be rejected")
		}
	}
}

func TestProofLengthBounds(t *testing.T) {
	if _, err := Verifier("too-short", "pepper"); err == nil {
		t.Fatal("expected short proof to fail")
	}
	oversized := strings.Repeat("a", 300)
	if _, err := Verifier(oversized, "pepper"); err == nil {
		t.Fatal("expected oversized proof to fail")
	}
}

func TestTokenIsRandomAndHashable(t *testing.T) {
	plain, hash, err := Token()
	if err != nil {
		t.Fatal(err)
	}
	if plain == "" || len(hash) != 32 {
		t.Fatalf("unexpected token output: %q %d", plain, len(hash))
	}
}
