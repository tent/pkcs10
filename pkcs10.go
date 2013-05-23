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
)

type Details struct {
	Organization       string
	OrganizationalUnit string
	Country            string
	Locality           string
	Province           string
	StreetAddress      string
	PostalCode         string
	CommonName         string

	SubjectAlternateNames []string
}

func (d Details) toPkixName() pkix.Name {
	n := pkix.Name{CommonName: d.CommonName}
	if d.Country != "" {
		n.Country = []string{d.Country}
	}
	if d.Organization != "" {
		n.Organization = []string{d.Organization}
	}
	if d.OrganizationalUnit != "" {
		n.OrganizationalUnit = []string{d.OrganizationalUnit}
	}
	if d.Locality != "" {
		n.Locality = []string{d.Locality}
	}
	if d.Province != "" {
		n.Province = []string{d.Province}
	}
	if d.StreetAddress != "" {
		n.StreetAddress = []string{d.StreetAddress}
	}
	if d.PostalCode != "" {
		n.PostalCode = []string{d.PostalCode}
	}
	return n
}

func CreateRequest(key *rsa.PrivateKey, details *Details) ([]byte, error) {
	csr := pkixRequest{
		RequestInfo: pkixRequestInfo{
			Subject:       details.toPkixName().ToRDNSequence(),
			SubjectPKInfo: encodePublicKey(&key.PublicKey),
		},
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
	Values []interface{}
}

// rsaPublicKey reflects the ASN.1 structure of a PKCS#1 public key.
type rsaPublicKey struct {
	N *big.Int
	E int
}

var oidSignatureSHA1WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
var oidPublicKeyRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}

func encodePublicKey(pub *rsa.PublicKey) pkixPublicKey {
	data, _ := asn1.Marshal(rsaPublicKey{N: pub.N, E: pub.E})
	return pkixPublicKey{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidPublicKeyRSA},
		PublicKey: asn1.BitString{BitLength: len(data) * 8, Bytes: data},
	}
}
