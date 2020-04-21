package keypair

import (
	"crypto/rand"
	"crypto/x509"
	"io"
	"log"
	"math/big"
	"time"
)

func csrToNonCATemplate(csr *x509.CertificateRequest) *x509.Certificate {
	return &x509.Certificate{
		Subject:               csr.Subject,
		PublicKey:             csr.PublicKey,
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		SerialNumber:          serialNumber(8),
		DNSNames:              csr.DNSNames,
		EmailAddresses:        csr.EmailAddresses,
		IPAddresses:           csr.IPAddresses,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  false,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(2 * time.Hour),
		URIs:                  csr.URIs,
	}
}

func csrToCATemplate(csr *x509.CertificateRequest) *x509.Certificate {
	return &x509.Certificate{
		Subject:               csr.Subject,
		PublicKey:             csr.PublicKey,
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		SerialNumber:          serialNumber(8),
		DNSNames:              csr.DNSNames,
		EmailAddresses:        csr.EmailAddresses,
		IPAddresses:           csr.IPAddresses,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(2 * time.Hour),
		URIs:                  csr.URIs,
	}
}

func serialNumber(size int) *big.Int {
	serialData := make([]byte, size)
	read, err := io.ReadFull(rand.Reader, serialData)
	if err != nil {
		log.Fatal(err)
	}

	if read != size {
		log.Fatal("Not enough crypto/rand bytes for cert serial number")
	}

	serial := big.NewInt(12345)
	serial.SetBytes(serialData)

	return serial
}
