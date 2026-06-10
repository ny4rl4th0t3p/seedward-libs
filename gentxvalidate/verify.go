package gentxvalidate

import (
	"crypto/sha256"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

const (
	secp256k1PubKeyTypeURL = "/cosmos.crypto.secp256k1.PubKey"
	ed25519PubKeyTypeURL   = "/cosmos.crypto.ed25519.PubKey"

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
	if err := checkSingleSecpSigner(g); err != nil {
		return false, err
	}
	signBytes, err := DirectSignBytes(g, chainID, accountNumber)
	if err != nil {
		return false, err
	}
	return verifySecpCompact(g.Signer.PubKey, g.Signature, signBytes)
}

// checkSingleSecpSigner gates the single-key secp256k1 signer shape shared by
// the sign-mode verifiers (multisig signers arrive with Phase 2.3b).
func checkSingleSecpSigner(g *ParsedGentx) error {
	if g.Signer.PubKeyTypeURL != secp256k1PubKeyTypeURL {
		return fmt.Errorf("gentxvalidate: unsupported account key type %q", g.Signer.PubKeyTypeURL)
	}
	if len(g.Signer.PubKey) != compressedPubKeyLen {
		return fmt.Errorf("gentxvalidate: account pubkey must be %d bytes (compressed), got %d", compressedPubKeyLen, len(g.Signer.PubKey))
	}
	if len(g.Signature) != compactSigLen {
		return fmt.Errorf("gentxvalidate: signature must be %d bytes (r||s compact), got %d", compactSigLen, len(g.Signature))
	}
	return nil
}

// verifySecpCompact verifies a 64-byte r||s signature over SHA256(signBytes)
// against a compressed secp256k1 pubkey. False with nil error means the
// signature does not verify (including r or s at/above the group order).
func verifySecpCompact(pubKey, sig, signBytes []byte) (bool, error) {
	pub, err := secp256k1.ParsePubKey(pubKey)
	if err != nil {
		return false, fmt.Errorf("gentxvalidate: parse account pubkey: %w", err)
	}

	var r, s secp256k1.ModNScalar
	if overflow := r.SetByteSlice(sig[:32]); overflow {
		return false, nil // r >= group order: not a valid signature
	}
	if overflow := s.SetByteSlice(sig[32:]); overflow {
		return false, nil
	}
	ecdsaSig := secpecdsa.NewSignature(&r, &s)

	hash := sha256.Sum256(signBytes)
	return ecdsaSig.Verify(hash[:], pub), nil
}
