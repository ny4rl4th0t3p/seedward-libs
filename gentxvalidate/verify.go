package gentxvalidate

import (
	"crypto/sha256"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

const (
	secp256k1PubKeyTypeURL = "/cosmos.crypto.secp256k1.PubKey"

	compressedPubKeyLen = 33 // secp256k1 compressed public key
	compactSigLen       = 64 // r||s, 32 bytes each
)

// VerifyDirect reconstructs the SIGN_MODE_DIRECT sign bytes and verifies the
// gentx's signature against the account pubkey in auth_info (the secp256k1
// key — not the ed25519 consensus key inside the message).
//
// A false return with nil error means the signature simply does not verify;
// an error means the input couldn't be processed at all.
func VerifyDirect(g *ParsedGentx, chainID string, accountNumber uint64) (bool, error) {
	if g.Signer.PubKeyTypeURL != secp256k1PubKeyTypeURL {
		return false, fmt.Errorf("gentxvalidate: unsupported account key type %q", g.Signer.PubKeyTypeURL)
	}
	if len(g.Signer.PubKey) != compressedPubKeyLen {
		return false, fmt.Errorf("gentxvalidate: account pubkey must be %d bytes (compressed), got %d", compressedPubKeyLen, len(g.Signer.PubKey))
	}
	if len(g.Signature) != compactSigLen {
		return false, fmt.Errorf("gentxvalidate: signature must be %d bytes (r||s compact), got %d", compactSigLen, len(g.Signature))
	}

	signBytes, err := DirectSignBytes(g, chainID, accountNumber)
	if err != nil {
		return false, err
	}

	pub, err := secp256k1.ParsePubKey(g.Signer.PubKey)
	if err != nil {
		return false, fmt.Errorf("gentxvalidate: parse account pubkey: %w", err)
	}

	var r, s secp256k1.ModNScalar
	if overflow := r.SetByteSlice(g.Signature[:32]); overflow {
		return false, nil // r >= group order: not a valid signature
	}
	if overflow := s.SetByteSlice(g.Signature[32:]); overflow {
		return false, nil
	}
	sig := secpecdsa.NewSignature(&r, &s)

	hash := sha256.Sum256(signBytes)
	return sig.Verify(hash[:], pub), nil
}
