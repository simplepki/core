package keypair

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/jtaylorcpp/piv-go/piv"
	log "github.com/sirupsen/logrus"
)

type YubikeyKP struct {
	Config  *YubikeyKeyPairConfig
	Yubikey *piv.YubiKey
	PubKey  crypto.PublicKey
	PrivKey crypto.PrivateKey
	Chain   []*x509.Certificate
}

type YubikeyKeyPairConfig struct {
	CertSubjectName     string
	Reset               bool
	Name                *string
	Serial              *uint32
	PIN                 *string
	PUK                 *string
	Base64ManagementKey *string
	managementKey       [24]byte
}

type yubikeyMarshaller struct {
	Serial string
	Chain  []string
}

func (y *YubikeyKeyPairConfig) parseAndGetDefaults() error {
	if y.PIN == nil {
		defPin := piv.DefaultPIN
		y.PIN = &defPin
	}

	if y.PUK == nil {
		defPuk := piv.DefaultPUK
		y.PUK = &defPuk
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

func getYubikey(config *YubikeyKeyPairConfig) (*piv.YubiKey, error) {
	availableYubis, err := getAllYubikeys()
	if err != nil {
		return nil, err
	}
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

			return yk, nil

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

				return yk, nil
			}
		}

		return nil, errors.New("no yubikey available for provided name")
	} else {
		// open and use first one that doesnt error
		for serial, name := range availableYubis {
			yk, err := piv.Open(name)
			if err != nil {
				log.Printf("unable to open yubikey <%s,%v>\n", name, serial)
				continue
			}

			return yk, nil
		}

		return nil, errors.New("no yubikeys available")
	}
}

func (y *YubikeyKP) New(config *KeyPairConfig) error {
	if config.YubikeyConfig == nil {
		y.Config = &YubikeyKeyPairConfig{}
		y.Config.parseAndGetDefaults()
	} else {
		y.Config = config.YubikeyConfig
		y.Config.parseAndGetDefaults()
	}

	var err error = nil
	y.Yubikey, err = getYubikey(y.Config)
	if err != nil {
		return err
	}

	if y.Config.Reset {
		if err := y.Yubikey.Reset(); err != nil {
			log.Println("unable to reset yubikey")
			return err
		}
	}

	keyOpts := piv.Key{
		Algorithm:   piv.AlgorithmEC384,
		PINPolicy:   piv.PINPolicyNever,
		TouchPolicy: piv.TouchPolicyNever,
	}

	pub, err := y.Yubikey.GenerateKey(
		y.Config.managementKey,
		piv.SlotAuthentication,
		keyOpts)

	if err != nil {
		return err
	}

	y.PubKey = pub

	auth := piv.KeyAuth{PIN: *config.YubikeyConfig.PIN}
	priv, err := y.Yubikey.PrivateKey(piv.SlotAuthentication, pub, auth)
	if err != nil {
		return err
	}

	y.PrivKey = priv

	return nil
}

func (y *YubikeyKP) Load(config *KeyPairConfig) error {
	if config.YubikeyConfig == nil {
		y.Config = &YubikeyKeyPairConfig{}
		y.Config.parseAndGetDefaults()
	} else {
		y.Config = config.YubikeyConfig
		y.Config.parseAndGetDefaults()
	}

	var err error = nil
	y.Yubikey, err = getYubikey(y.Config)
	if err != nil {
		return err
	}

	cert, err := y.Yubikey.Certificate(piv.SlotAuthentication)
	if err != nil {
		return err
	}

	if cert == nil {
		return errors.New("certificate provided is nil")
	}

	y.PubKey = cert.PublicKey

	auth := piv.KeyAuth{PIN: *config.YubikeyConfig.PIN}
	priv, err := y.Yubikey.PrivateKey(piv.SlotAuthentication, y.PubKey, auth)
	if err != nil {
		return err
	}

	y.PrivKey = priv

	return nil
}

func (y *YubikeyKP) GetCertificate() *x509.Certificate {
	cert, err := y.Yubikey.Certificate(piv.SlotAuthentication)
	if err != nil {
		log.Warningln("unable to get yubikey certificate")
		return nil
	}

	return cert
}

func (y *YubikeyKP) GetCertificateChain() []*x509.Certificate {
	return []*x509.Certificate{}
}

func (y *YubikeyKP) ImportCertificate(bytes []byte) error {

	cert, err := x509.ParseCertificate(bytes)
	if err != nil {
		log.Println("Error parsing imported certificate: ", err.Error())
		return err
	}

	log.Printf("kp: %#v\n", y)
	log.Printf("management key: %#v\n", y.Config.managementKey)
	err = y.Yubikey.SetCertificate(y.Config.managementKey, piv.SlotAuthentication, cert)
	if err != nil {
		return err
	}
	return nil
}

func (y *YubikeyKP) ImportCertificateChain(chainBytes [][]byte) error {
	return nil
}

func (y *YubikeyKP) CreateCSR(subj pkix.Name, altNames []string) ([]byte, error) {
	uri, err := url.Parse(subj.CommonName)
	if err != nil {
		return []byte{}, err
	}

	log.Printf("creating csr with uri: %#v\n", uri)

	uris := make([]*url.URL, 1)
	uris[0] = uri

	// parse DNS/IP address/email address from altNames
	dns := []string{}
	ipAddr := []net.IP{}
	emailAddr := []string{}
	for _, name := range altNames {
		if net.ParseIP(name) != nil {
			ipAddr = append(ipAddr, net.ParseIP(name))
		} else if strings.Contains(name, "@") {
			emailAddr = append(emailAddr, name)
		} else if match, err := regexp.MatchString(`[a-zA-Z0-9\-\.]+`, name); err == nil && match {
			dns = append(dns, name)
		}
	}

	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{
			Subject:        subj,
			DNSNames:       dns,
			IPAddresses:    ipAddr,
			EmailAddresses: emailAddr,
			URIs:           uris,
		},
		y.PrivKey)
	if err != nil {
		log.Fatal(err)
	}

	return der, err
}

func (y *YubikeyKP) IssueCertificate(csr *x509.CertificateRequest, isCA bool, selfSign bool) ([]byte, error) {
	var certTemplate *x509.Certificate
	if isCA {
		certTemplate = csrToCATemplate(csr)
	} else {
		certTemplate = csrToNonCATemplate(csr)
	}

	if selfSign {
		return x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, certTemplate.PublicKey, y.PrivKey)
	} else {
		cert, err := y.Yubikey.Certificate(piv.SlotAuthentication)
		if err != nil {
			return []byte{}, err
		}
		return x509.CreateCertificate(rand.Reader, certTemplate, cert, certTemplate.PublicKey, y.PrivKey)
	}
}

func (y *YubikeyKP) TLSCertificate() (tls.Certificate, error) {
	return tls.Certificate{
		Certificate: [][]byte{y.GetCertificate().Raw},
		PrivateKey:  y.PrivKey,
	}, nil
}

func (y *YubikeyKP) Base64Encode() string {
	return ""
}

func (y *YubikeyKP) Base64Decode(certString string) {}

func (y *YubikeyKP) CertificatePEM() []byte {
	cert := y.GetCertificate()
	if cert == nil {
		return []byte{}
	} else {
		return pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
	}
}

func (y *YubikeyKP) KeyPEM() []byte {
	return []byte{}
}

func (y *YubikeyKP) ChainPEM() []byte {
	chainBytes := []byte{}

	for _, chainCert := range y.Chain {
		chainBytes = append(chainBytes,
			pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: chainCert.Raw,
			})...)
	}

	return chainBytes
}

func (y *YubikeyKP) Close() error {
	return y.Yubikey.Close()
}
