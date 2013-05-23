package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/cupcake/pkcs10"
	"os"
)

func maybePanic(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	maybePanic(err)
	err = pem.Encode(os.Stdout, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	maybePanic(err)
	csr, err := pkcs10.EncodeRequest(key, &pkcs10.Request{
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "example.com",
		},
		AltDNSNames: []string{"example.net", "example.org", "example.io"},
	})
	maybePanic(err)
	err = pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})
	maybePanic(err)
}
