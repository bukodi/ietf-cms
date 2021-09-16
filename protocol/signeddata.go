package protocol

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"github.com/github/ietf-cms/oid"
	"time"
)

// SignedData ::= SEQUENCE {
//   version CMSVersion,
//   digestAlgorithms DigestAlgorithmIdentifiers,
//   encapContentInfo EncapsulatedContentInfo,
//   certificates [0] IMPLICIT CertificateSet OPTIONAL,
//   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
//   signerInfos SignerInfos }
//
// CMSVersion ::= INTEGER
//               { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
//
// DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
//
// CertificateSet ::= SET OF CertificateChoices
//
// CertificateChoices ::= CHOICE {
//   certificate Certificate,
//   extendedCertificate [0] IMPLICIT ExtendedCertificate, -- Obsolete
//   v1AttrCert [1] IMPLICIT AttributeCertificateV1,       -- Obsolete
//   v2AttrCert [2] IMPLICIT AttributeCertificateV2,
//   other [3] IMPLICIT OtherCertificateFormat }
//
// OtherCertificateFormat ::= SEQUENCE {
//   otherCertFormat OBJECT IDENTIFIER,
//   otherCert ANY DEFINED BY otherCertFormat }
//
// RevocationInfoChoices ::= SET OF RevocationInfoChoice
//
// RevocationInfoChoice ::= CHOICE {
//   crl CertificateList,
//   other [1] IMPLICIT OtherRevocationInfoFormat }
//
// OtherRevocationInfoFormat ::= SEQUENCE {
//   otherRevInfoFormat OBJECT IDENTIFIER,
//   otherRevInfo ANY DEFINED BY otherRevInfoFormat }
//
// SignerInfos ::= SET OF SignerInfo
type SignedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo EncapsulatedContentInfo
	Certificates     []asn1.RawValue `asn1:"optional,set,tag:0"`
	CRLs             []asn1.RawValue `asn1:"optional,set,tag:1"`
	SignerInfos      []SignerInfo    `asn1:"set"`
}

// NewSignedData creates a new SignedData.
func NewSignedData(eci EncapsulatedContentInfo) (*SignedData, error) {
	// The version is picked based on which CMS features are used. We only use
	// version 1 features, except for supporting non-data econtent.
	version := 1
	if !eci.IsTypeData() {
		version = 3
	}

	return &SignedData{
		Version:          version,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{},
		EncapContentInfo: eci,
		SignerInfos:      []SignerInfo{},
	}, nil
}

// AddSignerInfo adds a SignerInfo to the SignedData.
func (sd *SignedData) AddSignerInfo(chain []*x509.Certificate, signer crypto.Signer) error {
	// figure out which certificate is associated with signer.
	pub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return err
	}

	var (
		cert    *x509.Certificate
		certPub []byte
	)

	for _, c := range chain {
		if err = sd.AddCertificate(c); err != nil {
			return err
		}

		if certPub, err = x509.MarshalPKIXPublicKey(c.PublicKey); err != nil {
			return err
		}

		if bytes.Equal(pub, certPub) {
			cert = c
		}
	}
	if cert == nil {
		return ErrNoCertificate
	}

	sid, err := NewIssuerAndSerialNumber(cert)
	if err != nil {
		return err
	}

	digestAlgorithmID := digestAlgorithmForPublicKey(pub)

	signatureAlgorithmOID, ok := oid.X509PublicKeyAndDigestAlgorithmToSignatureAlgorithm[cert.PublicKeyAlgorithm][digestAlgorithmID.Algorithm.String()]
	if !ok {
		return errors.New("unsupported certificate public key algorithm")
	}

	signatureAlgorithmID := pkix.AlgorithmIdentifier{Algorithm: signatureAlgorithmOID}

	si := SignerInfo{
		Version:            1,
		SID:                sid,
		DigestAlgorithm:    digestAlgorithmID,
		SignedAttrs:        nil,
		SignatureAlgorithm: signatureAlgorithmID,
		Signature:          nil,
		UnsignedAttrs:      nil,
	}

	// Get the message
	content, err := sd.EncapContentInfo.EContentValue()
	if err != nil {
		return err
	}
	if content == nil {
		return errors.New("already detached")
	}

	// Digest the message.
	hash, err := si.Hash()
	if err != nil {
		return err
	}
	md := hash.New()
	if _, err = md.Write(content); err != nil {
		return err
	}

	// Build our SignedAttributes
	stAttr, err := NewAttribute(oid.AttributeSigningTime, time.Now().UTC())
	if err != nil {
		return err
	}
	mdAttr, err := NewAttribute(oid.AttributeMessageDigest, md.Sum(nil))
	if err != nil {
		return err
	}
	ctAttr, err := NewAttribute(oid.AttributeContentType, sd.EncapContentInfo.EContentType)
	if err != nil {
		return err
	}

	// sort attributes to match required order in marshaled form
	si.SignedAttrs, err = sortAttributes(stAttr, mdAttr, ctAttr)
	if err != nil {
		return err
	}

	// Signature is over the marshaled signed attributes
	sm, err := si.SignedAttrs.MarshaledForSigning()
	if err != nil {
		return err
	}
	smd := hash.New()
	if _, errr := smd.Write(sm); errr != nil {
		return errr
	}
	if si.Signature, err = signer.Sign(rand.Reader, smd.Sum(nil), hash); err != nil {
		return err
	}

	sd.addDigestAlgorithm(si.DigestAlgorithm)

	sd.SignerInfos = append(sd.SignerInfos, si)

	return nil
}

// algorithmsForPublicKey takes an opinionated stance on what algorithms to use
// for the given public key.
func digestAlgorithmForPublicKey(pub crypto.PublicKey) pkix.AlgorithmIdentifier {
	if ecPub, ok := pub.(*ecdsa.PublicKey); ok {
		switch ecPub.Curve {
		case elliptic.P384():
			return pkix.AlgorithmIdentifier{Algorithm: oid.DigestAlgorithmSHA384}
		case elliptic.P521():
			return pkix.AlgorithmIdentifier{Algorithm: oid.DigestAlgorithmSHA512}
		}
	}

	return pkix.AlgorithmIdentifier{Algorithm: oid.DigestAlgorithmSHA256}
}

// ClearCertificates removes all certificates.
func (sd *SignedData) ClearCertificates() {
	sd.Certificates = []asn1.RawValue{}
}

// AddCertificate adds a *x509.Certificate.
func (sd *SignedData) AddCertificate(cert *x509.Certificate) error {
	for _, existing := range sd.Certificates {
		if bytes.Equal(existing.Bytes, cert.Raw) {
			return errors.New("certificate already added")
		}
	}

	var rv asn1.RawValue
	if _, err := asn1.Unmarshal(cert.Raw, &rv); err != nil {
		return err
	}

	sd.Certificates = append(sd.Certificates, rv)

	return nil
}

// addDigestAlgorithm adds a new AlgorithmIdentifier if it doesn't exist yet.
func (sd *SignedData) addDigestAlgorithm(algo pkix.AlgorithmIdentifier) {
	for _, existing := range sd.DigestAlgorithms {
		if existing.Algorithm.Equal(algo.Algorithm) {
			return
		}
	}

	sd.DigestAlgorithms = append(sd.DigestAlgorithms, algo)
}

// X509Certificates gets the certificates, assuming that they're X.509 encoded.
func (sd *SignedData) X509Certificates() ([]*x509.Certificate, error) {
	// Certificates field is optional. Handle missing value.
	if sd.Certificates == nil {
		return nil, nil
	}

	// Empty set
	if len(sd.Certificates) == 0 {
		return []*x509.Certificate{}, nil
	}

	certs := make([]*x509.Certificate, 0, len(sd.Certificates))
	for _, raw := range sd.Certificates {
		if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagSequence {
			return nil, ErrUnsupported
		}

		cert, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			return nil, err
		}

		certs = append(certs, cert)
	}

	return certs, nil
}

// ContentInfo returns the SignedData wrapped in a ContentInfo packet.
func (sd *SignedData) ContentInfo() (ContentInfo, error) {
	var nilCI ContentInfo

	der, err := asn1.Marshal(*sd)
	if err != nil {
		return nilCI, err
	}

	return ContentInfo{
		ContentType: oid.ContentTypeSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			Bytes:      der,
			IsCompound: true,
		},
	}, nil

}

// ContentInfoDER returns the SignedData wrapped in a ContentInfo packet and DER
// encoded.
func (sd *SignedData) ContentInfoDER() ([]byte, error) {
	ci, err := sd.ContentInfo()
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(ci)
}