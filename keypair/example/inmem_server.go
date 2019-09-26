package main

import (
	"log"

	//"io/ioutil"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/http"

	kp "github.com/simplepki/core/keypair"
)

type tcpKeepAliveListener struct {
	*net.TCPListener
}

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

	/*clientCert := kp.NewInMemoryKP()
	clientName := pkix.Name{
		CommonName: "test-client",
	}
	clientCsr := clientCert.CreateCSR(clientName, []string{"client.local"})
	clientTemp := kp.CsrToCert(clientCsr)
	clientCert.Certificate = ca.IssueCertificate(clientTemp)
	log.Println("in memory client cert created")*/

	serverCert := kp.NewInMemoryKP()
	serverName := pkix.Name{
		CommonName: "localhost",
	}
	serverCsr := serverCert.CreateCSR(serverName, []string{"localhost"})
	serverTemp := kp.CsrToCert(serverCsr)
	serverCert.Certificate = ca.IssueCertificate(serverTemp)
	log.Println("in memory server cert created")

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handler)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(ca.Certificate)

	/*config := &tls.Config{}
	//config.NextProtos = []string{"http/1.1"}
	config.Certificates = []tls.Certificate{serverCert.TLSCertificate()}
	//config.Certificates = make([]tls.Certificate, 1)
	//config.Certificates[0] = serverCert.TLSCertificate()
	config.RootCAs = rootPool*/
	config := &tls.Config{
		NextProtos:               []string{"http/1.1"},
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		RootCAs:      rootPool,
		Certificates: []tls.Certificate{serverCert.TLSCertificate()},
	}

	srv := &http.Server{
		Addr:      ":8443",
		Handler:   mux,
		TLSConfig: config,
	}

	log.Fatal(srv.ListenAndServeTLS("", ""))

}
