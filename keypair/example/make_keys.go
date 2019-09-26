package main

import (
	"log"

	//"io/ioutil"
	"crypto/x509/pkix"

	kp "github.com/simplepki/core/keypair"
)

func main() {
	ca := kp.NewInMemoryKP()
	caName := pkix.Name{
		CommonName: "test-ca",
	}
	caCsr := ca.CreateCSR(caName, []string{"ca.localhost"})
	caTemp := kp.CsrToCACert(caCsr)
	ca.Certificate = caTemp
	ca.Certificate = ca.IssueCertificate(caTemp)
	log.Println("in memory ca created")

	clientCert := kp.NewInMemoryKP()
	clientName := pkix.Name{
		CommonName: "test-client",
	}
	clientCsr := clientCert.CreateCSR(clientName, []string{"client.local"})
	clientTemp := kp.CsrToCert(clientCsr)
	clientCert.Certificate = ca.IssueCertificate(clientTemp)
	log.Println("in memory client cert created")

	serverCert := kp.NewInMemoryKP()
	serverName := pkix.Name{
		CommonName: "localhost",
	}
	serverCsr := serverCert.CreateCSR(serverName, []string{"localhost"})
	serverTemp := kp.CsrToCert(serverCsr)
	serverCert.Certificate = ca.IssueCertificate(serverTemp)
	log.Println("in memory server cert created")

	ca.ToFile("ca")
	serverCert.ToFile("cert")
}
