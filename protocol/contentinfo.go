package protocol

import (
	"encoding/asn1"
	"github.com/github/ietf-cms/oid"
)

// ContentInfo ::= SEQUENCE {
//   contentType ContentType,
//   content [0] EXPLICIT ANY DEFINED BY contentType }
//
// ContentType ::= OBJECT IDENTIFIER
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// ParseContentInfo parses a top-level ContentInfo type from BER encoded data.
func ParseContentInfo(ber []byte) (ci ContentInfo, err error) {
	var der []byte
	if der, err = BER2DER(ber); err != nil {
		return
	}

	var rest []byte
	if rest, err = asn1.Unmarshal(der, &ci); err != nil {
		return
	}
	if len(rest) > 0 {
		err = ErrTrailingData
	}

	return
}

// SignedDataContent gets the content assuming contentType is signedData.
func (ci ContentInfo) SignedDataContent() (*SignedData, error) {
	if !ci.ContentType.Equal(oid.ContentTypeSignedData) {
		return nil, ErrWrongType
	}

	sd := new(SignedData)
	if rest, err := asn1.Unmarshal(ci.Content.Bytes, sd); err != nil {
		return nil, err
	} else if len(rest) > 0 {
		return nil, ErrTrailingData
	}

	return sd, nil
}
