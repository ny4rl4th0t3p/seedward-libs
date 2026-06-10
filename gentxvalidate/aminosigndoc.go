package gentxvalidate

// SIGN_MODE_LEGACY_AMINO_JSON sign-bytes reconstruction (legacytx.StdSignDoc).
// The SDK builds these bytes as amino-codec JSON passed through sortJSON:
// every object key sorted, compact, HTML-escaped. encoding/json emits struct
// fields in declaration order with exactly that escaping, so the structs below
// declare their fields in alphabetical json-key order on purpose — that alone
// reproduces the sorted output, byte for byte, with no amino dependency.
// Field sets and omitempty mirror the gogoproto json tags; any drift is an
// invisible byte mismatch that only shows up as a failed signature (same
// stakes as signdoc.go).

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
)

const msgCreateValidatorAminoName = "cosmos-sdk/MsgCreateValidator"

// aminoConsensusKeyNames maps a consensus pubkey proto type URL to its legacy
// amino name.
var aminoConsensusKeyNames = map[string]string{
	"/cosmos.crypto.ed25519.PubKey": "tendermint/PubKeyEd25519",
}

type aminoStdSignDoc struct {
	AccountNumber string            `json:"account_number"`
	ChainID       string            `json:"chain_id"`
	Fee           aminoStdFee       `json:"fee"`
	Memo          string            `json:"memo"`
	Msgs          []json.RawMessage `json:"msgs"`
	Sequence      string            `json:"sequence"`
	TimeoutHeight string            `json:"timeout_height,omitempty"`
}

type aminoStdFee struct {
	Amount []aminoCoin `json:"amount"`
	Gas    string      `json:"gas"`
}

type aminoCoin struct {
	Amount string `json:"amount"`
	Denom  string `json:"denom"`
}

type aminoMsg struct {
	Type  string                  `json:"type"`
	Value aminoMsgCreateValidator `json:"value"`
}

type aminoMsgCreateValidator struct {
	Commission        aminoCommission  `json:"commission"`
	DelegatorAddress  string           `json:"delegator_address,omitempty"`
	Description       aminoDescription `json:"description"`
	MinSelfDelegation string           `json:"min_self_delegation"`
	Pubkey            aminoPubKey      `json:"pubkey"`
	ValidatorAddress  string           `json:"validator_address,omitempty"`
	Value             aminoCoin        `json:"value"`
}

type aminoCommission struct {
	MaxChangeRate string `json:"max_change_rate"`
	MaxRate       string `json:"max_rate"`
	Rate          string `json:"rate"`
}

type aminoDescription struct {
	Details         string `json:"details,omitempty"`
	Identity        string `json:"identity,omitempty"`
	Moniker         string `json:"moniker,omitempty"`
	SecurityContact string `json:"security_contact,omitempty"`
	Website         string `json:"website,omitempty"`
}

type aminoPubKey struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// AminoSignBytes reconstructs the SIGN_MODE_LEGACY_AMINO_JSON sign bytes for
// g: the sorted-keys StdSignDoc JSON over chainID and accountNumber
// (0 for a gentx — the account doesn't exist at genesis).
func AminoSignBytes(g *ParsedGentx, chainID string, accountNumber uint64) ([]byte, error) {
	if g.Signer.Mode != "SIGN_MODE_LEGACY_AMINO_JSON" {
		return nil, fmt.Errorf("gentxvalidate: unsupported sign mode %q", g.Signer.Mode)
	}
	consKeyName, ok := aminoConsensusKeyNames[g.Msg.ConsensusPubKeyTypeURL]
	if !ok {
		return nil, fmt.Errorf("gentxvalidate: no amino name for consensus key type %q", g.Msg.ConsensusPubKeyTypeURL)
	}

	msg := aminoMsg{
		Type: msgCreateValidatorAminoName,
		Value: aminoMsgCreateValidator{
			Commission: aminoCommission{
				MaxChangeRate: g.Msg.Commission.MaxChangeRate,
				MaxRate:       g.Msg.Commission.MaxRate,
				Rate:          g.Msg.Commission.Rate,
			},
			DelegatorAddress: g.Msg.DelegatorAddress,
			Description: aminoDescription{
				Details:         g.Msg.Description.Details,
				Identity:        g.Msg.Description.Identity,
				Moniker:         g.Msg.Description.Moniker,
				SecurityContact: g.Msg.Description.SecurityContact,
				Website:         g.Msg.Description.Website,
			},
			MinSelfDelegation: g.Msg.MinSelfDelegation,
			Pubkey: aminoPubKey{
				Type:  consKeyName,
				Value: base64.StdEncoding.EncodeToString(g.Msg.ConsensusPubKey),
			},
			ValidatorAddress: g.Msg.ValidatorAddress,
			Value:            aminoCoin{Amount: g.Msg.Value.Amount, Denom: g.Msg.Value.Denom},
		},
	}
	msgBz, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("gentxvalidate: marshal amino msg: %w", err)
	}

	feeAmount := make([]aminoCoin, 0, len(g.Fee.Amount))
	for _, c := range g.Fee.Amount {
		feeAmount = append(feeAmount, aminoCoin{Amount: c.Amount, Denom: c.Denom})
	}

	doc := aminoStdSignDoc{
		AccountNumber: strconv.FormatUint(accountNumber, base10),
		ChainID:       chainID,
		Fee:           aminoStdFee{Amount: feeAmount, Gas: strconv.FormatUint(g.Fee.GasLimit, base10)},
		Memo:          g.Memo,
		Msgs:          []json.RawMessage{msgBz},
		Sequence:      strconv.FormatUint(g.Signer.Sequence, base10),
	}
	if g.TimeoutHeight != 0 {
		doc.TimeoutHeight = strconv.FormatUint(g.TimeoutHeight, base10)
	}

	bz, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("gentxvalidate: marshal StdSignDoc: %w", err)
	}
	return bz, nil
}

// VerifyAminoJSON reconstructs the SIGN_MODE_LEGACY_AMINO_JSON sign bytes and
// verifies the gentx's signature against the account pubkey. Single-key
// secp256k1 signers only — the multisig signer shape arrives with Phase 2.3b.
//
// A false return with nil error means the signature simply does not verify;
// an error means the input couldn't be processed at all.
func VerifyAminoJSON(g *ParsedGentx, chainID string, accountNumber uint64) (bool, error) {
	if err := checkSingleSecpSigner(g); err != nil {
		return false, err
	}
	signBytes, err := AminoSignBytes(g, chainID, accountNumber)
	if err != nil {
		return false, err
	}
	return verifySecpCompact(g.Signer.PubKey, g.Signature, signBytes)
}
