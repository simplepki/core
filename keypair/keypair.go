package keypair

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
)

type KEY_PAIR_TYPE = uint8

const (
	IN_MEMORY KEY_PAIR_TYPE = iota
	FILE_SYSTEM
	YUBIKEY
)

type KeyPairConfig struct {
	KeyPairType      KEY_PAIR_TYPE
	InMemoryConfig   *InMemoryKeyPairConfig
	FileSystemConfig *FileSystemKeyPairConfig
}

func NewKeyPair(config *KeyPairConfig) (KeyPair, error) {
	switch config.KeyPairType {
	case IN_MEMORY:
		return NewInMemoryKP(config.InMemoryConfig)
	case FILE_SYSTEM:
		return NewFileSystemKP(config.FileSystemConfig)
	default:
		return NewInMemoryKP(config.InMemoryConfig)

	}
}

type KeyPair interface {
	GetCertificate() *x509.Certificate
	GetCertificateChain() []*x509.Certificate
	ImportCertificate([]byte) error
	ImportCertificateChain([][]byte) error
	CreateCSR(pkix.Name, []string) *x509.CertificateRequest
	IssueCertificate(*x509.Certificate) *x509.Certificate
	TLSCertificate() tls.Certificate
	Base64Encode() string
	Base64Decode(string)
	CertificatePEM() []byte
	KeyPEM() []byte
	ChainPEM() [][]byte
}
