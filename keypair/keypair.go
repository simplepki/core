package keypair

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
)

func NewKeyPair(selector string) KeyPair {
	switch selector {
	case "memory":
		return NewInMemoryKP()
	default:
		return NewInMemoryKP()

	}
}

type KeyPair interface {
	GetCertificate() *x509.Certificate
	CreateCSR(pkix.Name, []string) *x509.CertificateRequest
	IssueCertificate(*x509.Certificate) *x509.Certificate
	TLSCertificate() tls.Certificate
	Base64Encode() string
	Base64Decode(string)
}
