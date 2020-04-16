package keypair

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
)

type KeyPairFile struct {
	Keypair string `json:"keypair`
}

type FileSystemKP struct {
	Config    *FileSystemKeyPairConfig
	KP        *InMemoryKP
	Locations []string
}

type FileSystemKeyPairConfig struct {
	Location []string
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
func toFile(paths []string, kp *InMemoryKP) error {
	for _, path := range paths {
		fileContents := &KeyPairFile{
			Keypair: kp.Base64Encode(),
		}

		jsonBytes, err := json.Marshal(fileContents)
		if err != nil {
			return err
		}

		err = ioutil.WriteFile(path, jsonBytes, 0644)
		if err != nil {
			return err
		}
	}

	return nil
}

func fromFile(path string, config *FileSystemKeyPairConfig) (*InMemoryKP, error) {
	kp := &InMemoryKP{}

	jsonBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	kpFile := &KeyPairFile{}
	err = json.Unmarshal(jsonBytes, kpFile)
	if err != nil {
		return nil, err
	}

	kp.Base64Decode(kpFile.Keypair)

	return kp, nil
}

func (fs *FileSystemKP) New(config *KeyPairConfig) error {
	expandedPaths := map[string]bool{}
	oneExists := false

	for _, path := range config.FileSystemConfig.Location {
		basePath := path
		if filepath.Ext(basePath) != ".pki" {
			basePath = basePath + ".pki"
		}

		expandedPath, exists := expandAndCheck(basePath)

		expandedPaths[expandedPath] = exists
		if exists {
			oneExists = true
		}
	}

	log.Printf("creating kp from paths: %#v\n", expandedPaths)
	switch oneExists {
	case true:
		return errors.New("simplepki file already exists in path given")
	case false:
		log.Println("creating new kp from scratch")
		// create new KP and save it to all paths
		memKP := &InMemoryKP{}
		err := memKP.New(config)
		if err != nil {
			return err
		}

		fs.KP = memKP
		fs.Config = config.FileSystemConfig
		fs.Locations = []string{}

		for path := range expandedPaths {
			fs.Locations = append(fs.Locations, path)
			err = toFile([]string{path}, fs.KP)
			if err != nil {
				return err
			}
		}

		return nil
	}

	return nil
}

func (fs *FileSystemKP) Load(config *KeyPairConfig) error {
	log.Println("loading filesystem kp")

	expandedPaths := map[string]bool{}
	oneExists := false

	for _, path := range config.FileSystemConfig.Location {
		basePath := path
		if filepath.Ext(basePath) != ".pki" {
			basePath = basePath + ".pki"
		}

		expandedPath, exists := expandAndCheck(basePath)

		expandedPaths[expandedPath] = exists
		if exists {
			oneExists = true
		}
	}

	log.Printf("creating kp from paths: %#v\n", expandedPaths)
	switch oneExists {
	case true:
		log.Println("loading in kp from file")
		// find the first one where the file exists
		var pathToUse string
		for path, exist := range expandedPaths {
			if exist {
				pathToUse = path
				break
			}
		}
		// load it
		log.Printf("pki file at path: %s\n", pathToUse)
		kp, err := fromFile(pathToUse, config.FileSystemConfig)
		if err != nil {
			return err
		}
		fs.KP = kp
		// copy it to other locations
		fs.Locations = []string{pathToUse}
		for path := range expandedPaths {
			if path != pathToUse {
				fs.Locations = append(fs.Locations, path)
				toFile([]string{path}, fs.KP)
			}
		}
		return nil
	case false:
		return errors.New("no pki available at any given paths")
	}

	return nil
}

func (fs *FileSystemKP) GetCertificate() *x509.Certificate {
	return fs.KP.GetCertificate()
}

func (fs *FileSystemKP) GetCertificateChain() []*x509.Certificate {
	return fs.KP.GetCertificateChain()
}

func (fs *FileSystemKP) ImportCertificate(derBytes []byte) error {
	return fs.KP.ImportCertificate(derBytes)
}

func (fs *FileSystemKP) ImportCertificateChain(listDerBytes [][]byte) error {
	return fs.KP.ImportCertificateChain(listDerBytes)
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

func (fs *FileSystemKP) Base64Encode() string {
	return fs.KP.Base64Encode()
}

func (fs *FileSystemKP) Base64Decode(b64String string) {
	fs.KP.Base64Decode(b64String)
}

func (fs *FileSystemKP) CertificatePEM() []byte {
	return fs.KP.CertificatePEM()
}

func (fs *FileSystemKP) KeyPEM() []byte {
	return fs.KP.KeyPEM()
}

func (fs *FileSystemKP) ChainPEM() [][]byte {
	return fs.KP.ChainPEM()
}
