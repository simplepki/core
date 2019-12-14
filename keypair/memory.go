package keypair

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
)

type InMemoryKP struct {
	PrivateKey  *rsa.PrivateKey
	Certificate *x509.Certificate
	Chain []*x509.Certificate
}

type inMemoryMarshaller struct {
	Cert string
	Key  string
}

func NewInMemoryKP() *InMemoryKP {

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	return &InMemoryKP{
		PrivateKey: privateKey,
	}
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
func (mem *InMemoryKP) ImportCertificate(pemBytes []byte) error {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("Import fail for non-certificate pem")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Println("Error parsing imported certificate: ", err.Error())
		return err
	}

	mem.Certificate = cert
	return nil
}

// ImportCertificateChain takes a list of PEM encoded certificates, decodes them,
// and adds them to the InMemoryKP to be used for generating TLS
func (mem *InMemoryKP) ImportCertificateChain(pemList [][]byte) error {
	mem.Chain = []*x509.Certificate{}
	for _, pemBytes := range pemList {
		block, _ := pem.Decode(pemBytes)
		if block == nil || block.Type != "CERTIFICATE" {
			return errors.New("Import fail for non-certificate pem")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
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
func (mem *InMemoryKP) CreateCSR(subj pkix.Name, altNames []string) *x509.CertificateRequest {
	uri, err := url.Parse(subj.CommonName)
	if err != nil {
		log.Fatal("error parsing csr uri: ", err)
	}
	
	log.Printf("creating csr with uri: %#v\n", uri)

	uris := make([]*url.URL,1)
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
			Subject:  subj,
			DNSNames: dns,
			IPAddresses: ipAddr,
			EmailAddresses: emailAddr,
			URIs:     uris,
		},
		mem.PrivateKey)
	if err != nil {
		log.Fatal(err)
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("csr uri: %#v\n", csr.URIs)

	return csr
}

// IssueCertificate takes in and signs CSR with the private key in the 
// InMemoryKP
func (mem *InMemoryKP) IssueCertificate(certTemplate *x509.Certificate) *x509.Certificate {

	der, err := x509.CreateCertificate(rand.Reader, certTemplate, mem.Certificate, certTemplate.PublicKey, mem.PrivateKey)
	if err != nil {
		log.Fatal(err)
	}



	signedCert, err := x509.ParseCertificate(der)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("template uris: %#v\n", certTemplate.URIs)
	log.Printf("signing uri: %#v\n", mem.GetCertificate().URIs)

	log.Printf("signed certificate with uris: %#v\n", signedCert.URIs)

	return signedCert
}

func (mem *InMemoryKP) TLSCertificate() tls.Certificate {
	cert, err := tls.X509KeyPair(mem.CertificatePEM(), mem.KeyPEM())
	if err != nil {
		log.Fatal(err)
	}

	return cert
}

func (mem *InMemoryKP) CertificatePEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: mem.Certificate.Raw,
	})
}

func (mem *InMemoryKP) KeyPEM() []byte {
	//keyBytes, err := x509.MarshalECPrivateKey(mem.PrivateKey)
	keyBytes := x509.MarshalPKCS1PrivateKey(mem.PrivateKey)

	return pem.EncodeToMemory(&pem.Block{
		//Type:  "EC PRIVATE KEY",
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})
}

func (mem *InMemoryKP) ToFile(name string) {
	certOut, err := os.Create(fmt.Sprintf("%s.pem", name))
	if err != nil {
		log.Fatal(err)
	}
	pem.Encode(certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: mem.Certificate.Raw,
	})
	certOut.Close()

	keyOut, err := os.OpenFile(fmt.Sprintf("%s.key", name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatal(err)
	}
	keyB := x509.MarshalPKCS1PrivateKey(mem.PrivateKey)

	pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyB,
	})
	keyOut.Close()

}

func (mem *InMemoryKP) Base64Encode() string {
	marshalled := inMemoryMarshaller{
		Cert: string(mem.CertificatePEM()),
		Key:  string(mem.KeyPEM()),
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
	certPEM, rest := pem.Decode([]byte(unmarshalled.Cert))
	if len(rest) != 0 {
		log.Println(string(rest))
		log.Fatal("Did not pem decode all of certificate")
	}

	mem.Certificate, err = x509.ParseCertificate(certPEM.Bytes)
	if err != nil {
		log.Fatal(err)
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

}
