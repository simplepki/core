package keypair

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/mitchellh/go-homedir"
)

type FileSystemKP struct {
	Config *FileSystemKeyPairConfig
	KP     *InMemoryKP
}

type FileSystemKeyPairConfig struct {
	CertFile  string
	KeyFile   string
	ChainFile string
}

// returns the expanded file path and whether or not the
// file exists
//
// if there is an internal error it will return "", false
func expandAndCheck(path string) (string, bool) {
	var expandedPath string
	expandedPath, err := homedir.Expand(path)
	if err != nil {
		return "", false
	}

	expandedPath, err = filepath.Abs(expandedPath)
	if err != nil {
		return "", false
	}

	fileInfo, err := os.Stat(expandedPath)

	if os.IsNotExist(err) {
		return expandedPath, false
	}

	if fileInfo.IsDir() {
		return "", false
	}

	return expandedPath, true

}

// InMemoryKP Helpers
func toFile(config *FileSystemKeyPairConfig, kp *InMemoryKP) error {
	// cert
	expandedCertFile, _ := expandAndCheck(config.CertFile)
	err := ioutil.WriteFile(expandedCertFile, kp.CertificatePEM(), 0644)
	if err != nil {
		return err
	}
	// key
	expandedKeyFile, _ := expandAndCheck(config.KeyFile)
	err = ioutil.WriteFile(expandedKeyFile, kp.KeyPEM(), 0644)
	if err != nil {
		return err
	}

	// chain
	expandedChainFile, _ := expandAndCheck(config.ChainFile)
	err = ioutil.WriteFile(expandedChainFile, kp.ChainPEM(), 0644)
	if err != nil {
		return err
	}
	return nil
}

func fromFile(config *FileSystemKeyPairConfig) (*InMemoryKP, error) {
	kp := &InMemoryKP{}
	// cert
	expandedCertFile, certFileExists := expandAndCheck(config.CertFile)
	if !certFileExists {
		return nil, errors.New("given certificate file does not exist")
	}
	certPEMBytes, err := ioutil.ReadFile(expandedCertFile)
	if err != nil {
		return nil, err
	}

	certPEM, _ := pem.Decode(certPEMBytes)
	err = kp.ImportCertificate(certPEM.Bytes)
	if err != nil {
		return nil, err
	}
	// key
	expandedKeyFile, keyFileExists := expandAndCheck(config.KeyFile)
	if !keyFileExists {
		return nil, errors.New("given key file does not exist")
	}
	keyPEMBytes, err := ioutil.ReadFile(expandedKeyFile)
	if err != nil {
		return nil, err
	}

	keyPEM, _ := pem.Decode(keyPEMBytes)
	switch strings.Contains(keyPEM.Type, "RSA") {
	case true:
		key, err := x509.ParsePKCS1PrivateKey(keyPEM.Bytes)
		if err != nil {
			return nil, err
		}
		kp.PrivateKey = key
	case false:
		key, err := x509.ParseECPrivateKey(keyPEM.Bytes)
		if err != nil {
			return nil, err
		}
		kp.PrivateKey = key
	}
	// chain
	expandedChainFile, ChainFileExists := expandAndCheck(config.ChainFile)
	if !ChainFileExists {
		return nil, errors.New("given chain file does not exist")
	}

	chainPEMBytes, err := ioutil.ReadFile(expandedChainFile)
	if err != nil {
		return nil, err
	}

	chain := []*x509.Certificate{}
	restPEMBytes := chainPEMBytes
	var currentBlock *pem.Block = nil
	for true {
		currentBlock, restPEMBytes = pem.Decode(restPEMBytes)
		if currentBlock == nil {
			log.Println("no more PEM block found in chain file")
			break
		}
		log.Println("parsing pem block in chain file")
		chainCert, err := x509.ParseCertificate(currentBlock.Bytes)
		if err != nil {
			log.Printf("error parsing chain cert: %#v\n", err.Error())
			break
		}
		chain = append(chain, chainCert)
	}

	kp.Chain = chain

	return kp, nil
}

func (fs *FileSystemKP) New(config *KeyPairConfig) error {
	kp := &InMemoryKP{}
	err := kp.New(config)
	if err != nil {
		return err
	}
	toFile(config.FileSystemConfig, kp)

	fs.KP = kp
	fs.Config = config.FileSystemConfig

	return nil
}

func (fs *FileSystemKP) Load(config *KeyPairConfig) error {
	kp, err := fromFile(config.FileSystemConfig)
	if err != nil {
		return nil
	}

	fs.KP = kp
	fs.Config = config.FileSystemConfig

	return nil
}

func (fs *FileSystemKP) GetCertificate() *x509.Certificate {
	return fs.KP.GetCertificate()
}

func (fs *FileSystemKP) GetCertificateChain() []*x509.Certificate {
	return fs.KP.GetCertificateChain()
}

func (fs *FileSystemKP) ImportCertificate(derBytes []byte) error {
	err := fs.KP.ImportCertificate(derBytes)
	if err != nil {
		return err
	}
	return toFile(fs.Config, fs.KP)
}

func (fs *FileSystemKP) ImportCertificateChain(listDerBytes [][]byte) error {
	err := fs.KP.ImportCertificateChain(listDerBytes)
	if err != nil {
		return err
	}

	return toFile(fs.Config, fs.KP)
}

func (fs *FileSystemKP) CreateCSR(name pkix.Name, altNames []string) ([]byte, error) {
	return fs.KP.CreateCSR(name, altNames)
}

func (fs *FileSystemKP) IssueCertificate(csr *x509.CertificateRequest, isCA bool, selfSign bool) ([]byte, error) {
	return fs.KP.IssueCertificate(csr, isCA, selfSign)
}

func (fs *FileSystemKP) TLSCertificate() (tls.Certificate, error) {
	return fs.KP.TLSCertificate()
}

func (fs *FileSystemKP) CertificatePEM() []byte {
	return fs.KP.CertificatePEM()
}

func (fs *FileSystemKP) KeyPEM() []byte {
	return fs.KP.KeyPEM()
}

func (fs *FileSystemKP) ChainPEM() []byte {
	return fs.KP.ChainPEM()
}

func (fs *FileSystemKP) Close() error {
	toFile(fs.Config, fs.KP)
	return fs.KP.Close()
}
