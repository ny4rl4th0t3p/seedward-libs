package gentxvalidate

import (
	"fmt"
	"strings"
)

// Field numbers from the cosmos proto definitions. Emission rules follow
// gogoproto's generated marshalers:
//   - plain proto3 strings/bytes/varints: omitted when zero/empty
//   - (gogoproto.nullable)=false embedded messages: ALWAYS emitted, even empty
//   - customtype fields (LegacyDec, Int): ALWAYS emitted
//
// Getting any of these wrong is an invisible byte mismatch that only shows up
// as a failed signature.

const signModeDirect = 1 // cosmos.tx.signing.v1beta1.SignMode SIGN_MODE_DIRECT

const legacyDecPrecision = 18 // math.LegacyDec fixed decimal places

// DirectSignBytes reconstructs the SIGN_MODE_DIRECT sign bytes for g:
// SignDoc{ body_bytes=1, auth_info_bytes=2, chain_id=3, account_number=4 }.
// chain_id is a sign-time input — the gentx JSON does not carry it.
// account_number is 0 for a gentx (the account doesn't exist at genesis).
func DirectSignBytes(g *ParsedGentx, chainID string, accountNumber uint64) ([]byte, error) {
	if g.Signer.Mode != signModeDirectName {
		return nil, fmt.Errorf("gentxvalidate: unsupported sign mode %q", g.Signer.Mode)
	}

	bodyBytes, err := encodeTxBody(g)
	if err != nil {
		return nil, err
	}
	authBytes, err := encodeAuthInfo(g)
	if err != nil {
		return nil, err
	}

	var b []byte
	b = appendBytesField(b, 1, bodyBytes)
	b = appendBytesField(b, 2, authBytes)
	if chainID != "" {
		b = appendStringField(b, 3, chainID)
	}
	if accountNumber != 0 {
		b = appendVarintField(b, 4, accountNumber)
	}
	return b, nil
}

// encodeTxBody: TxBody{ messages=1 (repeated Any), memo=2, timeout_height=3 }.
func encodeTxBody(g *ParsedGentx) ([]byte, error) {
	msgBytes, err := encodeMsgCreateValidator(&g.Msg)
	if err != nil {
		return nil, err
	}
	msgAny := encodeAny(MsgCreateValidatorTypeURL, msgBytes)

	var b []byte
	b = appendBytesField(b, 1, msgAny)
	if g.Memo != "" {
		b = appendStringField(b, 2, g.Memo)
	}
	if g.TimeoutHeight != 0 {
		b = appendVarintField(b, 3, g.TimeoutHeight)
	}
	return b, nil
}

// encodeAuthInfo: AuthInfo{ signer_infos=1 (repeated), fee=2 }.
// fee is a pointer in gogo but always present in a real gentx — emitted
// unconditionally (decode guarantees the field parsed).
func encodeAuthInfo(g *ParsedGentx) ([]byte, error) {
	si := encodeSignerInfo(&g.Signer)
	fee, err := encodeFee(&g.Fee)
	if err != nil {
		return nil, err
	}

	var b []byte
	b = appendBytesField(b, 1, si)
	b = appendBytesField(b, 2, fee)
	return b, nil
}

// encodeSignerInfo: SignerInfo{ public_key=1 (Any), mode_info=2, sequence=3 }.
// ModeInfo{ single=1 } wrapping Single{ mode=1 }.
func encodeSignerInfo(s *SignerInfo) []byte {
	pubKeyMsg := appendBytesField(nil, 1, s.PubKey) // PubKey{ key=1 }
	pubKeyAny := encodeAny(s.PubKeyTypeURL, pubKeyMsg)

	single := appendVarintField(nil, 1, signModeDirect)
	modeInfo := appendBytesField(nil, 1, single)

	var b []byte
	b = appendBytesField(b, 1, pubKeyAny)
	b = appendBytesField(b, 2, modeInfo)
	if s.Sequence != 0 {
		b = appendVarintField(b, 3, s.Sequence)
	}
	return b
}

// encodeFee: Fee{ amount=1 (repeated Coin), gas_limit=2, payer=3, granter=4 }.
func encodeFee(f *Fee) ([]byte, error) {
	var b []byte
	for _, c := range f.Amount {
		coin, err := encodeCoin(c)
		if err != nil {
			return nil, err
		}
		b = appendBytesField(b, 1, coin)
	}
	if f.GasLimit != 0 {
		b = appendVarintField(b, 2, f.GasLimit)
	}
	if f.Payer != "" {
		b = appendStringField(b, 3, f.Payer)
	}
	if f.Granter != "" {
		b = appendStringField(b, 4, f.Granter)
	}
	return b, nil
}

// encodeMsgCreateValidator: MsgCreateValidator{ description=1, commission=2,
// min_self_delegation=3, delegator_address=4, validator_address=5,
// pubkey=6 (Any), value=7 }. Fields 1, 2, 3 and 7 are nullable=false /
// customtype → always emitted.
func encodeMsgCreateValidator(m *MsgCreateValidator) ([]byte, error) {
	desc := encodeDescription(&m.Description)

	comm, err := encodeCommission(&m.Commission)
	if err != nil {
		return nil, err
	}

	minSelf, err := intWire(m.MinSelfDelegation, "min_self_delegation")
	if err != nil {
		return nil, err
	}

	consAny := encodeAny(m.ConsensusPubKeyTypeURL, appendBytesField(nil, 1, m.ConsensusPubKey))

	value, err := encodeCoin(m.Value)
	if err != nil {
		return nil, err
	}

	var b []byte
	b = appendBytesField(b, 1, desc)
	b = appendBytesField(b, 2, comm)
	b = appendBytesField(b, 3, minSelf)
	if m.DelegatorAddress != "" {
		b = appendStringField(b, 4, m.DelegatorAddress)
	}
	if m.ValidatorAddress != "" {
		b = appendStringField(b, 5, m.ValidatorAddress)
	}
	b = appendBytesField(b, 6, consAny)
	b = appendBytesField(b, 7, value)
	return b, nil
}

// encodeDescription: Description{ moniker=1, identity=2, website=3,
// security_contact=4, details=5 } — plain strings, empty omitted.
func encodeDescription(d *Description) []byte {
	var b []byte
	if d.Moniker != "" {
		b = appendStringField(b, 1, d.Moniker)
	}
	if d.Identity != "" {
		b = appendStringField(b, 2, d.Identity)
	}
	if d.Website != "" {
		b = appendStringField(b, 3, d.Website)
	}
	if d.SecurityContact != "" {
		b = appendStringField(b, 4, d.SecurityContact)
	}
	if d.Details != "" {
		b = appendStringField(b, 5, d.Details)
	}
	return b
}

// encodeCommission: CommissionRates{ rate=1, max_rate=2, max_change_rate=3 }
// — all three are LegacyDec customtype, always emitted.
func encodeCommission(c *CommissionRates) ([]byte, error) {
	rate, err := legacyDecWire(c.Rate, "commission.rate")
	if err != nil {
		return nil, err
	}
	maxRate, err := legacyDecWire(c.MaxRate, "commission.max_rate")
	if err != nil {
		return nil, err
	}
	maxChange, err := legacyDecWire(c.MaxChangeRate, "commission.max_change_rate")
	if err != nil {
		return nil, err
	}

	var b []byte
	b = appendBytesField(b, 1, rate)
	b = appendBytesField(b, 2, maxRate)
	b = appendBytesField(b, 3, maxChange)
	return b, nil
}

// encodeCoin: Coin{ denom=1, amount=2 }. amount is Int customtype → always
// emitted; denom is a plain string.
func encodeCoin(c Coin) ([]byte, error) {
	amount, err := intWire(c.Amount, "coin amount")
	if err != nil {
		return nil, err
	}

	var b []byte
	if c.Denom != "" {
		b = appendStringField(b, 1, c.Denom)
	}
	b = appendBytesField(b, 2, amount)
	return b, nil
}

// encodeAny: google.protobuf.Any{ type_url=1, value=2 }.
func encodeAny(typeURL string, value []byte) []byte {
	var b []byte
	if typeURL != "" {
		b = appendStringField(b, 1, typeURL)
	}
	if len(value) > 0 {
		b = appendBytesField(b, 2, value)
	}
	return b
}

// legacyDecWire converts a LegacyDec JSON string ("0.100000000000000000") to
// its wire form: the value ×10¹⁸ as an ASCII integer with no decimal point and
// no leading zeros ("100000000000000000") — math.LegacyDec marshals as the
// scaled big.Int's MarshalText.
func legacyDecWire(s, field string) ([]byte, error) {
	intPart, fracPart, _ := strings.Cut(s, ".")
	if err := checkDigits(intPart, field); err != nil {
		return nil, err
	}
	if fracPart != "" {
		if err := checkDigits(fracPart, field); err != nil {
			return nil, err
		}
	}
	if len(fracPart) > legacyDecPrecision {
		return nil, fmt.Errorf("gentxvalidate: %s: more than %d decimal places", field, legacyDecPrecision)
	}
	fracPart += strings.Repeat("0", legacyDecPrecision-len(fracPart))

	scaled := strings.TrimLeft(intPart+fracPart, "0")
	if scaled == "" {
		scaled = "0"
	}
	return []byte(scaled), nil
}

// intWire validates a math.Int JSON string; the wire form is the same ASCII
// digits (big.Int MarshalText).
func intWire(s, field string) ([]byte, error) {
	if err := checkDigits(s, field); err != nil {
		return nil, err
	}
	return []byte(s), nil
}

func checkDigits(s, field string) error {
	if s == "" {
		return fmt.Errorf("gentxvalidate: %s: empty number", field)
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return fmt.Errorf("gentxvalidate: %s: invalid number %q", field, s)
		}
	}
	return nil
}
