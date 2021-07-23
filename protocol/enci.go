package protocol

import (
	"encoding/asn1"
	"github.com/github/ietf-cms/oid"
)

// EncapsulatedContentInfo ::= SEQUENCE {
//   eContentType ContentType,
//   eContent [0] EXPLICIT OCTET STRING OPTIONAL }
//
// ContentType ::= OBJECT IDENTIFIER
type EncapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

// NewDataEncapsulatedContentInfo creates a new EncapsulatedContentInfo of type
// id-data.
func NewDataEncapsulatedContentInfo(data []byte) (EncapsulatedContentInfo, error) {
	return NewEncapsulatedContentInfo(oid.ContentTypeData, data)
}

// NewEncapsulatedContentInfo creates a new EncapsulatedContentInfo.
func NewEncapsulatedContentInfo(contentType asn1.ObjectIdentifier, content []byte) (EncapsulatedContentInfo, error) {
	octets, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagOctetString,
		Bytes:      content,
		IsCompound: false,
	})
	if err != nil {
		return EncapsulatedContentInfo{}, err
	}

	return EncapsulatedContentInfo{
		EContentType: contentType,
		EContent: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			Bytes:      octets,
			IsCompound: true,
		},
	}, nil
}

// EContentValue gets the OCTET STRING EContent value without tag or length.
// This is what the message digest is calculated over. A nil byte slice is
// returned if the OPTIONAL eContent field is missing.
func (eci EncapsulatedContentInfo) EContentValue() ([]byte, error) {
	if eci.EContent.Bytes == nil {
		return nil, nil
	}

	// The EContent is an `[0] EXPLICIT OCTET STRING`. EXPLICIT means that there
	// is another whole tag wrapping the OCTET STRING. When we decoded the
	// EContent into a asn1.RawValue we're just getting that outer tag, so the
	// EContent.Bytes is the encoded OCTET STRING, which is what we really want
	// the value of.
	var octets asn1.RawValue
	if rest, err := asn1.Unmarshal(eci.EContent.Bytes, &octets); err != nil {
		return nil, err
	} else if len(rest) > 0 {
		return nil, ErrTrailingData
	}
	if octets.Class != asn1.ClassUniversal || octets.Tag != asn1.TagOctetString {
		return nil, ASN1Error{"bad tag or class"}
	}

	// While we already tried converting BER to DER, we didn't take constructed
	// types into account. Constructed string types, as opposed to primitive
	// types, can encode indefinite length strings by including a bunch of
	// sub-strings that are joined together to get the actual value. Gpgsm uses
	// a constructed OCTET STRING for the EContent, so we have to manually decode
	// it here.
	var value []byte
	if octets.IsCompound {
		rest := octets.Bytes
		for len(rest) > 0 {
			var err error
			if rest, err = asn1.Unmarshal(rest, &octets); err != nil {
				return nil, err
			}

			// Don't allow further constructed types.
			if octets.Class != asn1.ClassUniversal || octets.Tag != asn1.TagOctetString || octets.IsCompound {
				return nil, ASN1Error{"bad class or tag"}
			}

			value = append(value, octets.Bytes...)
		}
	} else {
		value = octets.Bytes
	}

	return value, nil
}

// IsTypeData checks if the EContentType is id-data.
func (eci EncapsulatedContentInfo) IsTypeData() bool {
	return eci.EContentType.Equal(oid.ContentTypeData)
}

// DataEContent gets the EContent assuming EContentType is data.
func (eci EncapsulatedContentInfo) DataEContent() ([]byte, error) {
	if !eci.IsTypeData() {
		return nil, ErrWrongType
	}
	return eci.EContentValue()
}
