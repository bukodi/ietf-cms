package protocol

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"github.com/github/ietf-cms/oid"
	"time"
)

// SignerInfo ::= SEQUENCE {
//   version CMSVersion,
//   sid SignerIdentifier,
//   digestAlgorithm DigestAlgorithmIdentifier,
//   signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
//   signatureAlgorithm SignatureAlgorithmIdentifier,
//   signature SignatureValue,
//   unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
//
// CMSVersion ::= INTEGER
//               { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
//
// SignerIdentifier ::= CHOICE {
//   issuerAndSerialNumber IssuerAndSerialNumber,
//   subjectKeyIdentifier [0] SubjectKeyIdentifier }
//
// DigestAlgorithmIdentifier ::= AlgorithmIdentifier
//
// SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
//
// SignatureAlgorithmIdentifier ::= AlgorithmIdentifier
//
// SignatureValue ::= OCTET STRING
//
// UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
type SignerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        Attributes `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      Attributes `asn1:"set,optional,tag:1"`
}

// FindCertificate finds this SignerInfo's certificate in a slice of
// certificates.
func (si SignerInfo) FindCertificate(certs []*x509.Certificate) (*x509.Certificate, error) {
	switch si.Version {
	case 1: // SID is issuer and serial number
		isn, err := si.issuerAndSerialNumberSID()
		if err != nil {
			return nil, err
		}

		for _, cert := range certs {
			if bytes.Equal(cert.RawIssuer, isn.Issuer.FullBytes) && isn.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return cert, nil
			}
		}
	case 3: // SID is SubjectKeyIdentifier
		ski, err := si.subjectKeyIdentifierSID()
		if err != nil {
			return nil, err
		}

		for _, cert := range certs {
			for _, ext := range cert.Extensions {
				if oid.ExtensionSubjectKeyIdentifier.Equal(ext.Id) {
					if bytes.Equal(ski, ext.Value) {
						return cert, nil
					}
				}
			}
		}
	default:
		return nil, ErrUnsupported
	}

	return nil, ErrNoCertificate
}

// issuerAndSerialNumberSID gets the SID, assuming it is a issuerAndSerialNumber.
func (si SignerInfo) issuerAndSerialNumberSID() (isn IssuerAndSerialNumber, err error) {
	if si.SID.Class != asn1.ClassUniversal || si.SID.Tag != asn1.TagSequence {
		err = ErrWrongType
		return
	}

	var rest []byte
	if rest, err = asn1.Unmarshal(si.SID.FullBytes, &isn); err == nil && len(rest) > 0 {
		err = ErrTrailingData
	}

	return
}

// subjectKeyIdentifierSID gets the SID, assuming it is a subjectKeyIdentifier.
func (si SignerInfo) subjectKeyIdentifierSID() ([]byte, error) {
	if si.SID.Class != asn1.ClassContextSpecific || si.SID.Tag != 0 {
		return nil, ErrWrongType
	}

	return si.SID.Bytes, nil
}

// Hash gets the crypto.Hash associated with this SignerInfo's DigestAlgorithm.
// 0 is returned for unrecognized algorithms.
func (si SignerInfo) Hash() (crypto.Hash, error) {
	algo := si.DigestAlgorithm.Algorithm.String()
	hash := oid.DigestAlgorithmToCryptoHash[algo]
	if hash == 0 || !hash.Available() {
		return 0, ErrUnsupported
	}

	return hash, nil
}

// X509SignatureAlgorithm gets the x509.SignatureAlgorithm that should be used
// for verifying this SignerInfo's signature.
func (si SignerInfo) X509SignatureAlgorithm() x509.SignatureAlgorithm {
	var (
		sigOID    = si.SignatureAlgorithm.Algorithm.String()
		digestOID = si.DigestAlgorithm.Algorithm.String()
	)

	if sa := oid.SignatureAlgorithmToX509SignatureAlgorithm[sigOID]; sa != x509.UnknownSignatureAlgorithm {
		return sa
	}

	return oid.PublicKeyAndDigestAlgorithmToX509SignatureAlgorithm[sigOID][digestOID]
}

// GetContentTypeAttribute gets the signed ContentType attribute from the
// SignerInfo.
func (si SignerInfo) GetContentTypeAttribute() (asn1.ObjectIdentifier, error) {
	rv, err := si.SignedAttrs.GetOnlyAttributeValueBytes(oid.AttributeContentType)
	if err != nil {
		return nil, err
	}

	var ct asn1.ObjectIdentifier
	if rest, err := asn1.Unmarshal(rv.FullBytes, &ct); err != nil {
		return nil, err
	} else if len(rest) > 0 {
		return nil, ErrTrailingData
	}

	return ct, nil
}

// GetMessageDigestAttribute gets the signed MessageDigest attribute from the
// SignerInfo.
func (si SignerInfo) GetMessageDigestAttribute() ([]byte, error) {
	rv, err := si.SignedAttrs.GetOnlyAttributeValueBytes(oid.AttributeMessageDigest)
	if err != nil {
		return nil, err
	}
	if rv.Class != asn1.ClassUniversal || rv.Tag != asn1.TagOctetString {
		return nil, ASN1Error{"bad class or tag"}
	}

	return rv.Bytes, nil
}

// GetSigningTimeAttribute gets the signed SigningTime attribute from the
// SignerInfo.
func (si SignerInfo) GetSigningTimeAttribute() (time.Time, error) {
	var t time.Time

	if !si.SignedAttrs.HasAttribute(oid.AttributeSigningTime) {
		return t, nil
	}
	rv, err := si.SignedAttrs.GetOnlyAttributeValueBytes(oid.AttributeSigningTime)
	if err != nil {
		return t, err
	}
	if rv.Class != asn1.ClassUniversal || (rv.Tag != asn1.TagUTCTime && rv.Tag != asn1.TagGeneralizedTime) {
		return t, ASN1Error{"bad class or tag"}
	}

	if rest, err := asn1.Unmarshal(rv.FullBytes, &t); err != nil {
		return t, err
	} else if len(rest) > 0 {
		return t, ErrTrailingData
	}

	return t, nil
}
