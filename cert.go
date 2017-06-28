package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"net"
	"time"
)

type Cert struct {
	Text string `json:"text"`
}

func NewCert(user, domain string) Cert {
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generating random key: %v", err)
	}

	rootCertPEM, err := generateCert(user, domain, rootKey)
	if err != nil {
		log.Fatalf("error creating cert: %v", err)
	}

	text := string(rootCertPEM) + privateKeyText(rootKey)
	return Cert{Text: text}
}

func certTemplate(user, domain string) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errors.New("failed to generate serial number: " + err.Error())
	}

	subject := pkix.Name{
		Organization: []string{"Trust " + user + ", LLC."},
		Province:     []string{"IL"},
		Locality:     []string{"Chicago"},
		Country:      []string{"US"},
		CommonName:   domain,
	}

	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour), // valid for an hour
		BasicConstraintsValid: true,
	}

	return &tmpl, nil
}

func createCert(template, parent *x509.Certificate, pub interface{}, parentPriv interface{}) (certPEM []byte, err error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentPriv)
	if err != nil {
		return
	}

	_, err = x509.ParseCertificate(certDER)
	if err != nil {
		return
	}

	b := pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	certPEM = pem.EncodeToMemory(&b)
	return
}

func privateKeyText(rootKey *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rootKey),
		},
	))
}

func generateCert(user, domain string, rootKey *rsa.PrivateKey) (rootCertPEM []byte, err error) {
	rootCertTmpl, err := certTemplate(user, domain)
	if err != nil {
		log.Fatalf("creating cert template: %v", err)
	}
	rootCertTmpl.IsCA = true
	rootCertTmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	rootCertTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	rootCertTmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}

	return createCert(rootCertTmpl, rootCertTmpl, &rootKey.PublicKey, rootKey)
}
