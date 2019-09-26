package main

import (
	"log"

	//"io/ioutil"
	"crypto/x509/pkix"
	"io/ioutil"

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

	clientCert.ToFile("test")

	clientMem := clientCert.CertificatePEM()
	clientFile, err := ioutil.ReadFile("test.pem")
	if err != nil {
		log.Fatal(err)
	}

	log.Println(string(clientMem))
	log.Println(string(clientFile))

	if len(clientMem) == len(clientFile) {
		log.Println("certs same size")
	} else {
		log.Println("cert size mem vs file: ", len(clientMem), len(clientFile))
	}

	for idx, elem := range clientMem {
		if elem != clientFile[idx] {
			log.Println("mismatch byte: ", idx)
		}
	}

}
