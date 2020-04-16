package keypair

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
)

type KeyPairType = uint8

const (
	InMemory KeyPairType = iota
	FileSystem
	Yubikey
)

type KeyPairConfig struct {
	KeyPairType      KeyPairType
	InMemoryConfig   *InMemoryKeyPairConfig
	FileSystemConfig *FileSystemKeyPairConfig
	//YubikeyConfig    *YubikeyKeyPairConfig
	CommonName string
}

/*func NewKeyPair(config *KeyPairConfig) (KeyPair, error) {
	switch config.KeyPairType {
	case InMemory:
		kp := &InMemoryKP{}
		err := kp.New(config)
		return kp, err
	case FileSystem:
		kp := &FileSystemKP{}
		err := kp.New(config)
		return kp, err
	case Yubikey:
	kp := &YubikeyKP{}
	err := kp.New(config)
	return kp, err
	default:
		return nil, nil

	}
}*/

/*func LoadKeyPair(config *KeyPairConfig) (KeyPair, error) {
	switch config.KeyPairType {
	case InMemory:
		kp := &InMemoryKP{}
		err := kp.Load(config)
		return kp, err
	case FileSystem:
		kp := &FileSystemKP{}
		err := kp.Load(config)
		return kp, err
	case Yubikey:
		kp := &YubikeyKP{}
		err := kp.Load(config)
		return kp, err
	default:
		return nil, nil

	}
}*/

type KeyPair interface {
	New(*KeyPairConfig) error
	Load(*KeyPairConfig) error
	GetCertificate() *x509.Certificate
	GetCertificateChain() []*x509.Certificate
	ImportCertificate(derBytes []byte) error
	ImportCertificateChain(listDerBytes [][]byte) error
	CreateCSR(pkix.Name, []string) (derCSR []byte, err error)
	IssueCertificate(csr *x509.CertificateRequest, isCA bool, isSelfSigned bool) (derBytes []byte, err error)
	TLSCertificate() (tls.Certificate, error)
	Base64Encode() string
	Base64Decode(string)
	CertificatePEM() []byte
	KeyPEM() []byte
	ChainPEM() [][]byte
}
