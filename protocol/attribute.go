package protocol

import (
	"bytes"
	"encoding/asn1"
	"sort"
)

// Attribute ::= SEQUENCE {
//   attrType OBJECT IDENTIFIER,
//   attrValues SET OF AttributeValue }
//
// AttributeValue ::= ANY
type Attribute struct {
	Type asn1.ObjectIdentifier

	// This should be a SET OF ANY, but Go's asn1 parser can't handle slices of
	// RawValues. Use value() to get an AnySet of the value.
	RawValue asn1.RawValue
}

// NewAttribute creates a single-value Attribute.
func NewAttribute(typ asn1.ObjectIdentifier, val interface{}) (attr Attribute, err error) {
	var der []byte
	if der, err = asn1.Marshal(val); err != nil {
		return
	}

	var rv asn1.RawValue
	if _, err = asn1.Unmarshal(der, &rv); err != nil {
		return
	}

	if err = NewAnySet(rv).Encode(&attr.RawValue); err != nil {
		return
	}

	attr.Type = typ

	return
}

// Value further decodes the attribute Value as a SET OF ANY, which Go's asn1
// parser can't handle directly.
func (a Attribute) Value() (AnySet, error) {
	return DecodeAnySet(a.RawValue)
}

// Attributes is a common Go type for SignedAttributes and UnsignedAttributes.
//
// SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
//
// UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
type Attributes []Attribute

// MarshaledForSigning DER encodes the Attributes as needed for signing
// SignedAttributes. RFC5652 explains this encoding:
//   A separate encoding of the signedAttrs field is performed for message
//   digest calculation. The IMPLICIT [0] tag in the signedAttrs is not used for
//   the DER encoding, rather an EXPLICIT SET OF tag is used.  That is, the DER
//   encoding of the EXPLICIT SET OF tag, rather than of the IMPLICIT [0] tag,
//   MUST be included in the message digest calculation along with the length
//   and content octets of the SignedAttributes value.
func (attrs Attributes) MarshaledForSigning() ([]byte, error) {
	seq, err := asn1.Marshal(struct {
		Attributes `asn1:"set"`
	}{attrs})

	if err != nil {
		return nil, err
	}

	// unwrap the outer SEQUENCE
	var raw asn1.RawValue
	if _, err = asn1.Unmarshal(seq, &raw); err != nil {
		return nil, err
	}

	return raw.Bytes, nil
}

// MarshaledForVerification DER encodes the Attributes as needed for
// verification of SignedAttributes. This is done differently than
// MarshaledForSigning because when verifying attributes, we need to
// use the received order.
func (attrs Attributes) MarshaledForVerification() ([]byte, error) {
	seq, err := asn1.Marshal(struct {
		Attributes `asn1:"sequence"`
	}{attrs})

	if err != nil {
		return nil, err
	}

	// unwrap the outer SEQUENCE
	var raw asn1.RawValue
	if _, err = asn1.Unmarshal(seq, &raw); err != nil {
		return nil, err
	}

	// Change SEQUENCE OF to SET OF.
	raw.Bytes[0] = 0x31
	return raw.Bytes, nil
}

// GetOnlyAttributeValueBytes gets an attribute value, returning an error if the
// attribute occurs multiple times or has multiple values.
func (attrs Attributes) GetOnlyAttributeValueBytes(oid asn1.ObjectIdentifier) (rv asn1.RawValue, err error) {
	var vals []AnySet
	if vals, err = attrs.GetValues(oid); err != nil {
		return
	}
	if len(vals) != 1 {
		err = ASN1Error{"bad attribute count"}
		return
	}
	if len(vals[0].Elements) != 1 {
		err = ASN1Error{"bad attribute element count"}
		return
	}

	return vals[0].Elements[0], nil
}

// GetValues retreives the attributes with the given OID. A nil value is
// returned if the OPTIONAL SET of Attributes is missing from the SignerInfo. An
// empty slice is returned if the specified attribute isn't in the set.
func (attrs Attributes) GetValues(oid asn1.ObjectIdentifier) ([]AnySet, error) {
	if attrs == nil {
		return nil, nil
	}

	vals := []AnySet{}
	for _, attr := range attrs {
		if attr.Type.Equal(oid) {
			val, err := attr.Value()
			if err != nil {
				return nil, err
			}

			vals = append(vals, val)
		}
	}

	return vals, nil
}

// HasAttribute checks if an attribute is present.
func (attrs Attributes) HasAttribute(oid asn1.ObjectIdentifier) bool {
	for _, attr := range attrs {
		if attr.Type.Equal(oid) {
			return true
		}
	}

	return false
}

func sortAttributes(attrs ...Attribute) ([]Attribute, error) {
	// Sort attrs by their encoded values (including tag and
	// lengths) as specified in X690 Section 11.6 and implemented
	// in go >= 1.15's asn1.Marshal().
	sort.Slice(attrs, func(i, j int) bool {
		return bytes.Compare(
			attrs[i].RawValue.FullBytes,
			attrs[j].RawValue.FullBytes) < 0
	})

	return attrs, nil
}
