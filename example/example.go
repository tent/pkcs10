package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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
	csr, err := pkcs10.CreateRequest(key, &pkcs10.Details{Organization: "Test Org", CommonName: "example.com"})
	maybePanic(err)
	err = pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})
	maybePanic(err)
}
