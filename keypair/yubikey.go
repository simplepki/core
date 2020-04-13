package keypair

import (
	"log"
	"errors"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"github.com/jtaylorcpp/piv-go/piv"
)

type YubikeyKP struct{
	Config *YubikeyKeyPairConfig
	Yubikey *piv.YubiKey
}

type YubikeyKeyPairConfig struct{
	CertSubjectName string
	Name *string
	Serial *uint32
	PIN *string
	PUK *string
	Base64ManagementKey *string
	managementKey []byte
}

func(y *YubikeyKeyPairConfig) parseAndGetDefaults() error {
	if y.PIN == nil {
		y.PIN = piv.DefaultPIN
	}

	if y.PUK == nil {
		y.PUK = piv.DefaultPUK
	}

	if y.Base64ManagementKey == nil {
		y.managementKey = piv.DefaultManagementKey
	} else {
		// 
	}

	return nil
}

func getAllYubikeys() (map[uint32]string, error) {
	cards, err := piv.Cards()
	if err != nil {
		log.Printf("no yubikey present w/ error: %s\n", err.Error())
		return map[uint32]string{}, err
	}

	yubis := map[uint32]string{}
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			yk, err := piv.Open(card)
			if err != nil {
				log.Printf("unable to open yubikey: %s\n", cards)
				continue
			}

			serial, err := yk.Serial()
			if err != nil {
				log.Printf("unable to get yubikey serial number: %v\n", serial)
				continue
			}
			yubis[serial] = card
			yk.Close()
		}
	}
	return yubis, nil
}

func NewYubikeyKP(config *YubikeyKeyPairConfig) (*YubikeyKP, error) {
	availableYubis,_ := getAllYubikeys()
	log.Printf("currently available yubikeys: %#v\n", availableYubis)
	if config.Serial != nil {
		if name, ok := availableYubis[*config.Serial]; ok {
			yk, err := piv.Open(name)
			if err != nil {
				log.Println(err.Error())
				return nil, errors.New("unable to open yubikey with serial provided")
			}

			serial, err := yk.Serial()
			if err != nil {
				return nil, err
			}
			log.Printf("opened and using yubikey %s with serial %v\n", name, serial)

			ykKP := &YubikeyKP{
				Config: config,
				Yubikey: yk,
			}

			return ykKP, nil

		} else {
			return nil, errors.New("serial for yubikey provided is not available")
		}
	} else if config.Name != nil {
		for serial, name := range availableYubis {
			if name == *config.Name {
				yk, err := piv.Open(name)
				if err != nil {
					log.Printf("unable to open yubikey with provided name and infered serial number: <%s,%v>\n", name, serial)
					log.Println(err.Error())
					return nil, errors.New("unable to open yubikey with name provided")
				}

				ykKP := &YubikeyKP{
					Config: config,
					Yubikey: yk,
				}

				return ykKP, nil
			}
		}

		return nil, errors.New("no yubikey available for provided name")
	} else {
		// open and use first one that doesnt error
		for serial, name  := range availableYubis {
			yk, err := piv.Open(name)
			if err != nil {
				log.Printf("unable to open yubikey <%s,%v>\n", name, serial)
				continue
			}

			ykKP := &YubikeyKP{
				Config: config,
				Yubikey: yk,
			}

			return ykKP, nil
		}

		return nil, errors.New("no yubikeys available")
	}


	return nil, nil
}

func (y *Yubikey) 

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

func (y *YubikeyKP) TLSCertificate() tls.Certificate {
	return tls.Certificate{}
}

func (y *YubikeyKP) Base64Encode() string {
	return ""
}

func (y *YubikeyKP) Base64Decode(certString string) {}

func (y *YubikeyKP) CertificatePEM() []byte {
	return []byte{}
}

func (y *YubikeyKP) KeyPEM() []byte {
	return []byte{}
}

func (y *YubikeyKP) ChainPEM() [][]byte {
	return [][]byte{}
}
