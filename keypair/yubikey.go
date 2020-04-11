package keypair

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
)

type YubikeyKP struct{}

type YubikeyKeyPairConfig struct{}

func (y *YubikeyKP) GetCertificate() *x509.Certificate {
	return nil
}

func (y *YubikeyKP) GetCertificateChain() []*x509.Certificate {
	return []*x509.Certificate{}
}

func (y *YubikeyKP) ImportCertificate(certBytes []byte) error {
	return nil
}

func (y *YubikeyKP) ImportCertificateChain(chainBytes [][]byte) error {
	return nil
}

func (y *YubikeyKP) CreateCSR(name pkix.Name, altNames []string) *x509.CertificateRequest {
	return nil
}

func (y *YubikeyKP) IssueCertificate(inCert *x509.Certificate) *x509.Certificate {
	return nil
}

func (y *Yubikey) TLSCertificate() tls.Certificate {
	return tls.Certificate{}
}

func (y *Yubikey) Base64Encode() string {
	return ""
}

func (y *Yubikey) Base64Decode(certString string) {}

func (y *Yubikey) CertificatePEM() []byte {
	return []byte{}
}

func (y *Yubikey) KeyPEM() []byte {
	return []byte{}
}

func (y *Yubikey) ChainPEM() [][]byte {
	return [][]byte{}
}
