package keypair

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"net"
	"net/url"
	"regexp"
	"strings"
)

type InMemoryKP struct {
	PrivateKey   crypto.PrivateKey
	Certificate  *x509.Certificate
	KeyAlgorithm Algorithm
	Chain        []*x509.Certificate
}

type InMemoryKeyPairConfig struct{}

type inMemoryMarshaller struct {
	Cert  string
	Key   string
	Chain []string
}

func (mem *InMemoryKP) New(config *KeyPairConfig) error {
	mem.KeyAlgorithm = config.KeyAlgorithm
	switch mem.KeyAlgorithm {
	case AlgorithmEC256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		mem.PrivateKey = key
	case AlgorithmEC384:
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return err
		}
		mem.PrivateKey = key
	case AlgorithmRSA2048:
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		mem.PrivateKey = privateKey
	case AlgorithmRSA4096:
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		mem.PrivateKey = privateKey
	}

	return nil
}

func (mem *InMemoryKP) Load(config *KeyPairConfig) error {
	return mem.New(config)
}

// GetCertificate returns the Certificate help in the InMemoryKP
func (mem *InMemoryKP) GetCertificate() *x509.Certificate {
	return mem.Certificate
}

// GetCertificateChain returns the Certificate Authority
// chain for this signed certificate
func (mem *InMemoryKP) GetCertificateChain() []*x509.Certificate {
	return mem.Chain
}

// ImportCertificate takes a PEM encoded certificate and adds it to the
// InMemoryKP
func (mem *InMemoryKP) ImportCertificate(derBytes []byte) error {
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		log.Println("Error parsing imported certificate: ", err.Error())
		return err
	}

	mem.Certificate = cert
	return nil
}

// ImportCertificateChain takes a list of raw certificate bytes, parses them,
// and adds them to the InMemoryKP to be used for generating TLS
func (mem *InMemoryKP) ImportCertificateChain(derBytesList [][]byte) error {
	mem.Chain = []*x509.Certificate{}
	for _, derBytes := range derBytesList {
		cert, err := x509.ParseCertificate(derBytes)
		if err != nil {
			log.Println("Error parsing certificate: ", err.Error())
			return err
		}

		mem.Chain = append(mem.Chain, cert)
	}

	return nil
}

// CreateCSR generates a bland Certificate Signing Request with the given
// PKI name and DNS strings (SANs) to be added
func (mem *InMemoryKP) CreateCSR(subj pkix.Name, altNames []string) ([]byte, error) {
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
		mem.PrivateKey)
	if err != nil {
		return []byte{}, err
	}

	return der, nil
}

// IssueCertificate takes in and signs CSR with the private key in the
// InMemoryKP
func (mem *InMemoryKP) IssueCertificate(csr *x509.CertificateRequest, isCA bool, isSelfSigned bool) ([]byte, error) {
	var certTemplate *x509.Certificate
	if isCA {
		certTemplate = csrToCATemplate(csr)
	} else {
		certTemplate = csrToNonCATemplate(csr)
	}

	if isSelfSigned {
		der, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, certTemplate.PublicKey, mem.PrivateKey)
		if err != nil {
			return []byte{}, err
		}

		return der, nil
	} else {
		der, err := x509.CreateCertificate(rand.Reader, certTemplate, mem.Certificate, certTemplate.PublicKey, mem.PrivateKey)
		if err != nil {
			return []byte{}, err
		}

		return der, nil
	}

}

func (mem *InMemoryKP) TLSCertificate() (tls.Certificate, error) {
	return tls.X509KeyPair(mem.CertificatePEM(), mem.KeyPEM())
}

func (mem *InMemoryKP) CertificatePEM() []byte {
	if mem.Certificate == nil {
		return []byte{}
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: mem.Certificate.Raw,
	})
}

func (mem *InMemoryKP) KeyPEM() []byte {
	switch mem.KeyAlgorithm {
	case AlgorithmEC384, AlgorithmEC256:
		keyBytes, err := x509.MarshalECPrivateKey(mem.PrivateKey.(*ecdsa.PrivateKey))
		if err != nil {
			log.Printf("error parsing key: %s\n", err.Error())
		}
		return pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: keyBytes,
		})
	case AlgorithmRSA4096, AlgorithmRSA2048:
		keyBytes := x509.MarshalPKCS1PrivateKey(mem.PrivateKey.(*rsa.PrivateKey))
		return pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: keyBytes,
		})
	default:
		return []byte{}
	}
}

func (mem *InMemoryKP) ChainPEM() []byte {
	chainBytes := []byte{}

	for _, chainCert := range mem.Chain {
		chainBytes = append(chainBytes,
			pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: chainCert.Raw,
			})...)
	}

	return chainBytes
}

/*func (mem *InMemoryKP) Base64Encode() string {
	marshalled := inMemoryMarshaller{
		Cert:  string(mem.CertificatePEM()),
		Key:   string(mem.KeyPEM()),
		Chain: []string{},
	}

	for _, chainCert := range mem.ChainPEM() {
		marshalled.Chain = append(marshalled.Chain, string(chainCert))
	}

	jsonKP, err := json.Marshal(marshalled)
	if err != nil {
		log.Fatal(err)
	}

	b64KP := base64.StdEncoding.EncodeToString(jsonKP)

	return b64KP
}

func (mem *InMemoryKP) Base64Decode(b64String string) {
	jsonKP, err := base64.StdEncoding.DecodeString(b64String)
	if err != nil {
		log.Fatal(err)
	}

	var unmarshalled inMemoryMarshaller
	err = json.Unmarshal(jsonKP, &unmarshalled)
	if err != nil {
		panic(err)
		log.Fatal(err)
	}

	//log.Println("PEM Cert: ", unmarshalled.Cert)
	if unmarshalled.Cert != "" {
		certPEM, rest := pem.Decode([]byte(unmarshalled.Cert))
		if len(rest) != 0 {
			log.Println(string(rest))
			log.Fatal("Did not pem decode all of certificate")
		}

		mem.Certificate, err = x509.ParseCertificate(certPEM.Bytes)
		if err != nil {
			log.Fatal(err)
		}
	}

	privPEM, rest := pem.Decode([]byte(unmarshalled.Key))
	if len(rest) != 0 {
		log.Println(string(rest))
		panic(err)
		log.Fatal("Did not pem decode all of priv key")
	}

	mem.PrivateKey, err = x509.ParsePKCS1PrivateKey(privPEM.Bytes)
	if err != nil {
		panic(err)
		log.Fatal(err)
	}

}*/

func (m *InMemoryKP) Close() error {
	m.PrivateKey = nil
	m.Certificate = nil
	return nil
}
