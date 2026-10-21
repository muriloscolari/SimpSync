package auth

import "testing"

func TestVerifierRoundTrip(t *testing.T) {
	verifier, err := Verifier("proof-derived-from-a-master-password", "pepper")
	if err != nil {
		t.Fatal(err)
	}
	if !Verify("proof-derived-from-a-master-password", verifier, "pepper") {
		t.Fatal("expected verifier to accept the original proof")
	}
	if Verify("wrong-proof-derived-from-password", verifier, "pepper") {
		t.Fatal("expected verifier to reject a different proof")
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
