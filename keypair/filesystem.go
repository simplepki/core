package keypair

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
)

type KeyPairFile struct {
	Cert  string   `json:"cert"`
	Key   string   `json:"key"`
	Chain []string `json:"chain"`
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
func toFile(paths [] string, kp *InMemoryKP) error {
	for _, path := range paths {
		fileContents := &KeyPairFile{
			//Cert: string(kp.CertificatePEM()),
			Key: string(kp.KeyPEM()),
		}

		if kp.Certificate != nil {
			fileContents.Cert = string(kp.CertificatePEM())
		}

		chainStrings := []string{}
		for _, chainBytes := range kp.ChainPEM() {
			chainStrings = append(chainStrings, string(chainBytes))
		}

		fileContents.Chain = chainStrings

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

	if kpFile.Cert != "" {
		err = kp.ImportCertificate([]byte(kpFile.Cert))
		if err != nil {
			return nil, err
		}
	}

	chainBytes := [][]byte{}
	for _, certString := range kpFile.Chain {
		chainBytes = append(chainBytes, []byte(certString))
	}
	kp.ImportCertificateChain(chainBytes)
	if err != nil {
		return nil, err
	}

	keyPem, _ := pem.Decode([]byte(kpFile.Key))
	key, err := x509.ParsePKCS1PrivateKey(keyPem.Bytes)
	if err != nil {
		return nil, err
	}

	kp.PrivateKey = key

	return kp, nil
}

func (fs *FileSystemKP) New(config *KeyPairConfig) error {
	expandedPaths := map[string]bool{}
	oneExists := false

	for _, path := range config.Location {
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

		fs.KP  = memKP
		fs.Config = config.FileSystemKeyPairConfig
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

	for _, path := range config.Location {
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
		kp, err := fromFile(pathToUse, config)
		if err != nil {
			return  err
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
		return fsKP, nil
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

func (fs *FileSystemKP) ImportCertificate(certBytes []byte) error {
	return fs.KP.(certBytes)
}

func (fs *FileSystemKP) ImportCertificateChain(chainBytes [][]byte) error {
	return fs.KP.ImportCertificateChain(chainBytes)
}

func (fs *FileSystemKP) CreateCSR(name pkix.Name, altNames []string) *x509.CertificateRequest {
	return fs.KP.CreateCSR(name, altNames)
}

func (fs *FileSystemKP) IssueCertificate(cert *x509.Certificate) *x509.Certificate {
	return fs.KP.IssueCertificate(cert)
}

func (fs *FileSystemKP) TLSCertificate() tls.Certificate {
	return fs.KP.TLSCertificate()
}

func (fs *FileSystemKP) Base64Encode() string {
	return fs.KP.Base64Decode()
}

func (fs *FileSystemKP) Base64Decode(b64String string) {
	fs.KP.Base64Decode(b64String)
}

func (fs *FileSystemKP) CertificatePEM() []byte {
	return ks.KP.CertificatePEM()
}

func (fs *FileSystemKP) KeyPEM() []byte {
	return fs.KP.KeyPEM()
}

func (fs *FileSystemKP) ChainPEM() [][]byte {
	return fs.KP.ChainPEM()
}
