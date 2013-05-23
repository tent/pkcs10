// Package pkcs10 implements ASN.1 serialization of PKCS #10 Certificate Signing
// Requests.
package pkcs10

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
)

type Request struct {
	Subject pkix.Name

	// Subject Alternate Name values
	AltDNSNames       []string
	AltEmailAddresses []string
	AltIPAddresses    []net.IP
}

func (r Request) encodeSANExt() *pkixAttribute {
	if len(r.AltDNSNames) == 0 && len(r.AltEmailAddresses) == 0 && len(r.AltIPAddresses) == 0 {
		return nil
	}
	attr := &pkixAttribute{Type: oidPKCS9ExtensionRequest}
	ext := pkix.Extension{Id: oidExtensionSubjectAltName}

	var rawValues []asn1.RawValue
	for _, name := range r.AltDNSNames {
		rawValues = append(rawValues, asn1.RawValue{Tag: 2, Class: 2, Bytes: []byte(name)})
	}
	for _, email := range r.AltEmailAddresses {
		rawValues = append(rawValues, asn1.RawValue{Tag: 1, Class: 2, Bytes: []byte(email)})
	}
	for _, rawIP := range r.AltIPAddresses {
		// If possible, we always want to encode IPv4 addresses in 4 bytes.
		ip := rawIP.To4()
		if ip == nil {
			ip = rawIP
		}
		rawValues = append(rawValues, asn1.RawValue{Tag: 7, Class: 2, Bytes: ip})
	}
	ext.Value, _ = asn1.Marshal(rawValues)
	attr.Values = []interface{}{[]pkix.Extension{ext}}
	return attr
}

func (req *Request) Marshal(key *rsa.PrivateKey) ([]byte, error) {
	csr := pkixRequest{
		RequestInfo: pkixRequestInfo{
			Subject:       req.Subject.ToRDNSequence(),
			SubjectPKInfo: encodePublicKey(&key.PublicKey),
		},
	}
	if ext := req.encodeSANExt(); ext != nil {
		csr.RequestInfo.Attributes = append(csr.RequestInfo.Attributes, *ext)
	}
	var err error
	csr.SignatureAlgorithm, csr.Signature, err = csr.RequestInfo.signature(key)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(csr)
}

type pkixRequest struct {
	RequestInfo        pkixRequestInfo
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
}

type pkixRequestInfo struct {
	Version       int
	Subject       pkix.RDNSequence
	SubjectPKInfo pkixPublicKey
	Attributes    []pkixAttribute `asn1:"tag:0"`
}

func (r pkixRequestInfo) signature(key *rsa.PrivateKey) (a pkix.AlgorithmIdentifier, b asn1.BitString, err error) {
	data, err := asn1.Marshal(r)
	if err != nil {
		return
	}

	h := sha1.New()
	h.Write(data)

	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA1, h.Sum(nil))
	return pkix.AlgorithmIdentifier{Algorithm: oidSignatureSHA1WithRSA}, asn1.BitString{BitLength: len(signature) * 8, Bytes: signature}, err
}

type pkixPublicKey struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type pkixAttribute struct {
	Type   asn1.ObjectIdentifier
	Values []interface{} `asn1:"set"`
}

// rsaPublicKey reflects the ASN.1 structure of a PKCS#1 public key.
type rsaPublicKey struct {
	N *big.Int
	E int
}

var (
	oidSignatureSHA1WithRSA    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidPublicKeyRSA            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidPKCS9ExtensionRequest   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
	oidExtensionSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
)

func encodePublicKey(pub *rsa.PublicKey) pkixPublicKey {
	data, _ := asn1.Marshal(rsaPublicKey{N: pub.N, E: pub.E})
	return pkixPublicKey{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidPublicKeyRSA},
		PublicKey: asn1.BitString{BitLength: len(data) * 8, Bytes: data},
	}
}
