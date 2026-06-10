package gentxvalidate

// LegacyAminoPubKey (multisig) verification — Phase 2.3b. A multisig gentx
// signer carries a CompactBitArray marking which component keys signed and a
// MultiSignature protobuf envelope holding one compact signature per set bit.
// Every present signature must verify over the same amino sign bytes, and at
// least threshold components must have signed. (A "multisig DIRECT" gentx
// cannot exist: DIRECT sign bytes cover the bitarray in AuthInfo, so the SDK
// restricts legacy multisig to AMINO_JSON.)

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const legacyAminoPubKeyTypeURL = "/cosmos.crypto.multisig.LegacyAminoPubKey"

// Legacy amino registered-type prefixes (derived from the registered names per
// amino's hashing rules). The multisig account address is SHA256 over the
// amino binary encoding of the LegacyAminoPubKey, truncated to 20 bytes, and
// these prefixes are part of the hashed bytes.
var (
	multisigAminoPrefix = []byte{0x22, 0xC1, 0xF7, 0xE2} // tendermint/PubKeyMultisigThreshold
	secpAminoPrefix     = []byte{0xEB, 0x5A, 0xE9, 0x87} // tendermint/PubKeySecp256k1
	ed25519AminoPrefix  = []byte{0x16, 0x24, 0xDE, 0x64} // tendermint/PubKeyEd25519

	memberAminoPrefixes = map[string][]byte{
		secp256k1PubKeyTypeURL: secpAminoPrefix,
		ed25519PubKeyTypeURL:   ed25519AminoPrefix,
	}
)

// multisigAddressBytes derives the 20-byte account address of a
// LegacyAminoPubKey: SHA256 over its legacy amino binary encoding —
// type prefix, threshold as field 1 (varint), then each member key as
// field 2 (its own amino prefix + length + key bytes).
func multisigAddressBytes(ms *MultisigSigner) ([]byte, error) {
	b := append([]byte{}, multisigAminoPrefix...)
	b = appendVarintField(b, 1, uint64(ms.Threshold))
	for i, m := range ms.Members {
		prefix, ok := memberAminoPrefixes[m.PubKeyTypeURL]
		if !ok {
			return nil, fmt.Errorf("multisig component %d: no amino prefix for key type %q", i, m.PubKeyTypeURL)
		}
		entry := make([]byte, 0, len(prefix)+1+len(m.PubKey))
		entry = append(entry, prefix...)
		entry = appendUvarint(entry, uint64(len(m.PubKey)))
		entry = append(entry, m.PubKey...)
		b = appendBytesField(b, 2, entry)
	}

	sum := sha256.Sum256(b)
	return sum[:accountAddrLen], nil
}

func verifyAminoMultisig(ms *MultisigSigner, signature, signBytes []byte) (bool, error) {
	for i, mode := range ms.Modes {
		if mode != signModeAminoJSONName {
			return false, fmt.Errorf("gentxvalidate: multisig component %d: unsupported sign mode %q", i, mode)
		}
	}
	if bits := ms.bitCount(); bits != len(ms.Members) {
		return false, fmt.Errorf("gentxvalidate: multisig bitarray has %d bits for %d keys", bits, len(ms.Members))
	}

	signers := ms.signerIndices()
	sigs, err := parseMultiSignature(signature)
	if err != nil {
		return false, err
	}
	if len(sigs) != len(signers) || len(ms.Modes) != len(signers) {
		return false, fmt.Errorf("gentxvalidate: multisig has %d signatures and %d mode_infos for %d set bits",
			len(sigs), len(ms.Modes), len(signers))
	}
	if len(sigs) < int(ms.Threshold) {
		return false, nil // fewer signatures than the threshold: does not verify
	}

	for j, idx := range signers {
		member := ms.Members[idx]
		if member.PubKeyTypeURL != secp256k1PubKeyTypeURL {
			return false, fmt.Errorf("gentxvalidate: multisig component %d: unsupported key type %q", idx, member.PubKeyTypeURL)
		}
		if len(member.PubKey) != compressedPubKeyLen {
			return false, fmt.Errorf("gentxvalidate: multisig component %d: pubkey is %d bytes, want %d",
				idx, len(member.PubKey), compressedPubKeyLen)
		}
		if len(sigs[j]) != compactSigLen {
			return false, fmt.Errorf("gentxvalidate: multisig component %d: signature is %d bytes, want %d",
				idx, len(sigs[j]), compactSigLen)
		}
		ok, err := verifySecpCompact(member.PubKey, sigs[j], signBytes)
		if err != nil || !ok {
			return ok, err
		}
	}
	return true, nil
}

// bitCount is the number of bits the CompactBitArray stores.
func (ms *MultisigSigner) bitCount() int {
	if len(ms.BitarrayElems) == 0 {
		return 0
	}
	if ms.ExtraBitsStored == 0 {
		return len(ms.BitarrayElems) * 8
	}
	return (len(ms.BitarrayElems)-1)*8 + ms.ExtraBitsStored
}

// signerIndices lists the member indices whose CompactBitArray bit is set —
// the members a signature is present for, in signature order. Callers must
// have checked bitCount() == len(Members) first.
func (ms *MultisigSigner) signerIndices() []int {
	var idx []int
	for i := range ms.Members {
		if ms.BitarrayElems[i/8]&(1<<(7-i%8)) != 0 {
			idx = append(idx, i)
		}
	}
	return idx
}

// parseMultiSignature decodes a cosmos.crypto.multisig.v1beta1.MultiSignature
// protobuf envelope: repeated bytes signatures = 1. The reading counterpart of
// protowire.go's writer.
func parseMultiSignature(b []byte) ([][]byte, error) {
	const sigTag = 1<<3 | wireBytes // field 1, length-delimited
	var sigs [][]byte
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		if n <= 0 || tag != sigTag {
			return nil, fmt.Errorf("gentxvalidate: malformed MultiSignature envelope")
		}
		b = b[n:]

		size, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, fmt.Errorf("gentxvalidate: malformed MultiSignature envelope")
		}
		b = b[n:]
		if size > uint64(len(b)) {
			return nil, fmt.Errorf("gentxvalidate: MultiSignature length prefix overruns the envelope")
		}
		sigs = append(sigs, b[:size])
		b = b[size:]
	}
	if len(sigs) == 0 {
		return nil, fmt.Errorf("gentxvalidate: MultiSignature envelope contains no signatures")
	}
	return sigs, nil
}
