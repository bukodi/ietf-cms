package protocol

import (
	"crypto/x509"
	"encoding/asn1"
	"math/big"
)

// IssuerAndSerialNumber ::= SEQUENCE {
// 	issuer Name,
// 	serialNumber CertificateSerialNumber }
//
// CertificateSerialNumber ::= INTEGER
type IssuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// NewIssuerAndSerialNumber creates a IssuerAndSerialNumber SID for the given
// cert.
func NewIssuerAndSerialNumber(cert *x509.Certificate) (rv asn1.RawValue, err error) {
	sid := IssuerAndSerialNumber{
		SerialNumber: new(big.Int).Set(cert.SerialNumber),
	}

	if _, err = asn1.Unmarshal(cert.RawIssuer, &sid.Issuer); err != nil {
		return
	}

	var der []byte
	if der, err = asn1.Marshal(sid); err != nil {
		return
	}

	if _, err = asn1.Unmarshal(der, &rv); err != nil {
		return
	}

	return
}
