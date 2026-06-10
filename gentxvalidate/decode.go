// Package gentxvalidate validates a single Cosmos SDK gentx against a launch's
// declared parameters.
package gentxvalidate

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
)

// MsgCreateValidatorTypeURL is the only message type the Phase 0 decoder accepts.
const MsgCreateValidatorTypeURL = "/cosmos.staking.v1beta1.MsgCreateValidator"

// ParsedGentx is the decoded, field-accessible gentx (spec §3): moniker,
// commission rates, consensus pubkey, operator/account addresses,
// self-delegation coin, signer info, and signature.
type ParsedGentx struct {
	Msg           MsgCreateValidator
	Memo          string
	TimeoutHeight uint64
	Signer        SignerInfo
	Fee           Fee
	Signature     []byte // 64-byte r||s compact form, not DER
}

type MsgCreateValidator struct {
	Description            Description
	Commission             CommissionRates
	MinSelfDelegation      string
	DelegatorAddress       string
	ValidatorAddress       string
	ConsensusPubKeyTypeURL string
	ConsensusPubKey        []byte
	Value                  Coin
}

type Description struct {
	Moniker         string
	Identity        string
	Website         string
	SecurityContact string
	Details         string
}

// CommissionRates holds the decimal strings exactly as they appear in the JSON
// (e.g. "0.100000000000000000"); wire scaling happens at encode time.
type CommissionRates struct {
	Rate          string
	MaxRate       string
	MaxChangeRate string
}

type Coin struct {
	Denom  string
	Amount string
}

type SignerInfo struct {
	PubKeyTypeURL string
	PubKey        []byte // 33-byte compressed secp256k1; nil for multisig signers
	Mode          string // for multisig: the first component mode (uniformity is enforced at verification)
	Sequence      uint64
	Multisig      *MultisigSigner // non-nil for LegacyAminoPubKey signers
}

// MultisigSigner is the decoded LegacyAminoPubKey signer shape: k-of-n
// component keys plus the compact bitarray marking which components signed.
type MultisigSigner struct {
	Threshold       int
	Members         []MultisigMember
	Modes           []string // one per present signature (per set bitarray bit)
	BitarrayElems   []byte
	ExtraBitsStored int
}

type MultisigMember struct {
	PubKeyTypeURL string
	PubKey        []byte
}

type Fee struct {
	Amount   []Coin
	GasLimit uint64
	Payer    string
	Granter  string
}

type coinJSON struct {
	Denom  string `json:"denom"`
	Amount string `json:"amount"`
}

type anyKeyJSON struct {
	Type string `json:"@type"`
	Key  string `json:"key"`
}

type msgCreateValidatorJSON struct {
	Type        string `json:"@type"`
	Description struct {
		Moniker         string `json:"moniker"`
		Identity        string `json:"identity"`
		Website         string `json:"website"`
		SecurityContact string `json:"security_contact"`
		Details         string `json:"details"`
	} `json:"description"`
	Commission struct {
		Rate          string `json:"rate"`
		MaxRate       string `json:"max_rate"`
		MaxChangeRate string `json:"max_change_rate"`
	} `json:"commission"`
	MinSelfDelegation string     `json:"min_self_delegation"`
	DelegatorAddress  string     `json:"delegator_address"`
	ValidatorAddress  string     `json:"validator_address"`
	Pubkey            anyKeyJSON `json:"pubkey"`
	Value             coinJSON   `json:"value"`
}

type signerInfoJSON struct {
	PublicKey signerPubKeyJSON `json:"public_key"`
	ModeInfo  modeInfoJSON     `json:"mode_info"`
	Sequence  string           `json:"sequence"`
}

// signerPubKeyJSON covers both account-key shapes: a single key (key) and
// LegacyAminoPubKey (threshold + public_keys).
type signerPubKeyJSON struct {
	Type       string       `json:"@type"`
	Key        string       `json:"key"`
	Threshold  int          `json:"threshold"`
	PublicKeys []anyKeyJSON `json:"public_keys"`
}

type modeInfoJSON struct {
	Single struct {
		Mode string `json:"mode"`
	} `json:"single"`
	Multi struct {
		Bitarray struct {
			ExtraBitsStored int    `json:"extra_bits_stored"`
			Elems           string `json:"elems"`
		} `json:"bitarray"`
		ModeInfos []modeInfoJSON `json:"mode_infos"`
	} `json:"multi"`
}

type gentxJSON struct {
	Body struct {
		Messages                    []json.RawMessage `json:"messages"`
		Memo                        string            `json:"memo"`
		TimeoutHeight               string            `json:"timeout_height"`
		ExtensionOptions            []json.RawMessage `json:"extension_options"`
		NonCriticalExtensionOptions []json.RawMessage `json:"non_critical_extension_options"`
	} `json:"body"`
	AuthInfo struct {
		SignerInfos []signerInfoJSON `json:"signer_infos"`
		Fee         struct {
			Amount   []coinJSON `json:"amount"`
			GasLimit string     `json:"gas_limit"`
			Payer    string     `json:"payer"`
			Granter  string     `json:"granter"`
		} `json:"fee"`
	} `json:"auth_info"`
	Signatures []string `json:"signatures"`
}

// Decode parses a gentx JSON document into ParsedGentx. Malformed input is an
// error, never a panic.
func Decode(data []byte) (*ParsedGentx, error) {
	var raw gentxJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("gentxvalidate: parse gentx JSON: %w", err)
	}

	// Exactly one message — the spec's single-MsgCreateValidator heavy
	// invariant is enforced here and reported under well_formed; it has no
	// separate invariant ID.
	if n := len(raw.Body.Messages); n != 1 {
		return nil, fmt.Errorf("gentxvalidate: expected exactly 1 message, got %d", n)
	}
	if n := len(raw.AuthInfo.SignerInfos); n != 1 {
		return nil, fmt.Errorf("gentxvalidate: expected exactly 1 signer_info, got %d", n)
	}
	if n := len(raw.Signatures); n != 1 {
		return nil, fmt.Errorf("gentxvalidate: expected exactly 1 signature, got %d", n)
	}
	// Extension options can't be re-encoded by the minimal marshaler; their
	// presence would silently break sign-bytes reconstruction, so reject them.
	if len(raw.Body.ExtensionOptions) > 0 || len(raw.Body.NonCriticalExtensionOptions) > 0 {
		return nil, fmt.Errorf("gentxvalidate: extension options are not supported")
	}

	var msg msgCreateValidatorJSON
	if err := json.Unmarshal(raw.Body.Messages[0], &msg); err != nil {
		return nil, fmt.Errorf("gentxvalidate: parse message: %w", err)
	}
	if msg.Type != MsgCreateValidatorTypeURL {
		return nil, fmt.Errorf("gentxvalidate: unsupported message type %q", msg.Type)
	}

	consPubKey, err := base64.StdEncoding.DecodeString(msg.Pubkey.Key)
	if err != nil {
		return nil, fmt.Errorf("gentxvalidate: decode consensus pubkey: %w", err)
	}

	signer, err := decodeSignerInfo(raw.AuthInfo.SignerInfos[0])
	if err != nil {
		return nil, err
	}

	sig, err := base64.StdEncoding.DecodeString(raw.Signatures[0])
	if err != nil {
		return nil, fmt.Errorf("gentxvalidate: decode signature: %w", err)
	}

	timeoutHeight, err := parseUint(raw.Body.TimeoutHeight, "timeout_height")
	if err != nil {
		return nil, err
	}
	gasLimit, err := parseUint(raw.AuthInfo.Fee.GasLimit, "gas_limit")
	if err != nil {
		return nil, err
	}

	feeAmount := make([]Coin, 0, len(raw.AuthInfo.Fee.Amount))
	for _, c := range raw.AuthInfo.Fee.Amount {
		feeAmount = append(feeAmount, Coin(c))
	}

	return &ParsedGentx{
		Msg: MsgCreateValidator{
			Description: Description{
				Moniker:         msg.Description.Moniker,
				Identity:        msg.Description.Identity,
				Website:         msg.Description.Website,
				SecurityContact: msg.Description.SecurityContact,
				Details:         msg.Description.Details,
			},
			Commission: CommissionRates{
				Rate:          msg.Commission.Rate,
				MaxRate:       msg.Commission.MaxRate,
				MaxChangeRate: msg.Commission.MaxChangeRate,
			},
			MinSelfDelegation:      msg.MinSelfDelegation,
			DelegatorAddress:       msg.DelegatorAddress,
			ValidatorAddress:       msg.ValidatorAddress,
			ConsensusPubKeyTypeURL: msg.Pubkey.Type,
			ConsensusPubKey:        consPubKey,
			Value:                  Coin{Denom: msg.Value.Denom, Amount: msg.Value.Amount},
		},
		Memo:          raw.Body.Memo,
		TimeoutHeight: timeoutHeight,
		Signer:        signer,
		Fee: Fee{
			Amount:   feeAmount,
			GasLimit: gasLimit,
			Payer:    raw.AuthInfo.Fee.Payer,
			Granter:  raw.AuthInfo.Fee.Granter,
		},
		Signature: sig,
	}, nil
}

// decodeSignerInfo decodes auth_info.signer_infos[0] — either a single
// account key or a LegacyAminoPubKey multisig.
func decodeSignerInfo(si signerInfoJSON) (SignerInfo, error) {
	sequence, err := parseUint(si.Sequence, "sequence")
	if err != nil {
		return SignerInfo{}, err
	}

	if si.PublicKey.Type != legacyAminoPubKeyTypeURL {
		pk, err := base64.StdEncoding.DecodeString(si.PublicKey.Key)
		if err != nil {
			return SignerInfo{}, fmt.Errorf("gentxvalidate: decode account pubkey: %w", err)
		}
		return SignerInfo{
			PubKeyTypeURL: si.PublicKey.Type,
			PubKey:        pk,
			Mode:          si.ModeInfo.Single.Mode,
			Sequence:      sequence,
		}, nil
	}

	ms, err := decodeMultisigSigner(si)
	if err != nil {
		return SignerInfo{}, err
	}
	return SignerInfo{
		PubKeyTypeURL: si.PublicKey.Type,
		Mode:          ms.Modes[0],
		Sequence:      sequence,
		Multisig:      ms,
	}, nil
}

func decodeMultisigSigner(si signerInfoJSON) (*MultisigSigner, error) {
	pub, multi := si.PublicKey, si.ModeInfo.Multi
	if len(pub.PublicKeys) == 0 {
		return nil, fmt.Errorf("gentxvalidate: multisig pubkey has no component keys")
	}
	if pub.Threshold < 1 || pub.Threshold > len(pub.PublicKeys) {
		return nil, fmt.Errorf("gentxvalidate: multisig threshold %d out of range for %d keys", pub.Threshold, len(pub.PublicKeys))
	}
	if len(multi.ModeInfos) == 0 {
		return nil, fmt.Errorf("gentxvalidate: multisig signer has no mode_infos")
	}

	elems, err := base64.StdEncoding.DecodeString(multi.Bitarray.Elems)
	if err != nil {
		return nil, fmt.Errorf("gentxvalidate: decode multisig bitarray: %w", err)
	}

	members := make([]MultisigMember, 0, len(pub.PublicKeys))
	for _, k := range pub.PublicKeys {
		pk, err := base64.StdEncoding.DecodeString(k.Key)
		if err != nil {
			return nil, fmt.Errorf("gentxvalidate: decode multisig component pubkey: %w", err)
		}
		members = append(members, MultisigMember{PubKeyTypeURL: k.Type, PubKey: pk})
	}

	modes := make([]string, 0, len(multi.ModeInfos))
	for _, mi := range multi.ModeInfos {
		modes = append(modes, mi.Single.Mode)
	}

	return &MultisigSigner{
		Threshold:       pub.Threshold,
		Members:         members,
		Modes:           modes,
		BitarrayElems:   elems,
		ExtraBitsStored: multi.Bitarray.ExtraBitsStored,
	}, nil
}

// parseUint parses proto-JSON's string-encoded uint64; absent ("") means 0.
func parseUint(s, field string) (uint64, error) {
	if s == "" {
		return 0, nil
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("gentxvalidate: parse %s: %w", field, err)
	}
	return v, nil
}
