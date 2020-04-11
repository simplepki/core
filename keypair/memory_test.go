package keypair

import (
	"crypto/tls"
	"crypto/x509"

	"crypto/x509/pkix"
	"io/ioutil"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInMemoryKPAssertion(t *testing.T) {
	inmem, _ := NewInMemoryKP(nil)
	var kp interface{} = inmem
	_, ok := kp.(KeyPair)
	if !ok {
		t.Fatal("InMemoryKP doesnt fullfil KeyPair")
	}
}

func TestNewInMemoryKP(t *testing.T) {
	kp, _ := NewInMemoryKP(nil)
	t.Log("in memory kp: ", kp)

	csr := kp.CreateCSR(pkix.Name{}, []string{})
	t.Log("in memory kp csr: ", csr)
}

func TestInMemorySelfSigned(t *testing.T) {
	kp, _ := NewInMemoryKP(nil)

	csr := kp.CreateCSR(pkix.Name{}, []string{})

	cert := CsrToCACert(csr)

	assert.Equal(t, true, cert.IsCA, "should be set to be a CA template")

	kp.Certificate = cert

	issuedCert := kp.IssueCertificate(cert)

	kp.Certificate = issuedCert

	assert.Equal(t, true, kp.Certificate.IsCA, "should be a ca certificate")
}

func TestInMemoryCA(t *testing.T) {
	t.Log("generating ca")
	ca, _ := NewInMemoryKP(nil)
	caCsr := ca.CreateCSR(pkix.Name{}, []string{})
	caCertTemp := CsrToCACert(caCsr)
	ca.Certificate = caCertTemp
	ca.IssueCertificate(caCertTemp)
	assert.Equal(t, true, ca.Certificate.IsCA, "ca should be the ca")

	cert1, _ := NewInMemoryKP(nil)
	cert1Csr := cert1.CreateCSR(pkix.Name{}, []string{})
	cert1Temp := CsrToCert(cert1Csr)
	t.Log("cert1 kp and csr/template created")

	cert1.Certificate = ca.IssueCertificate(cert1Temp)
	assert.Equal(t, false, cert1.Certificate.IsCA, "cert1 should not be a ca")

	err := cert1.Certificate.CheckSignatureFrom(ca.Certificate)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("verified cert1 signed by the ca")

	cert2, _ := NewInMemoryKP(nil)
	cert2Csr := cert2.CreateCSR(pkix.Name{}, []string{})
	cert2Temp := CsrToCert(cert2Csr)
	t.Log("cert2 kp and csr/template created")

	cert2.Certificate = cert1.IssueCertificate(cert2Temp)
	assert.Equal(t, false, cert1.Certificate.IsCA, "cert1 should not be a ca")
	assert.Equal(t, false, cert2.Certificate.IsCA, "cert2 should not be a ca")
	err = cert2.Certificate.CheckSignatureFrom(cert1.Certificate)
	if err == nil {
		t.Fatal("cert1 should not be able to sign cert2")
	} else {
		t.Log("verified cert1 should not be able to sign cert 2 with error: ", err)
	}

	err = cert2.Certificate.CheckSignatureFrom(ca.Certificate)
	if err == nil {
		t.Fatal("cert2 not signed by ca and should not be linked via cert1(non-intermediate)")
	} else {
		t.Log("verified cerified cert2 not linked to ca through non-intermediate cert1: ", err)
	}
}

func TestInMemoryCAandIntermediate(t *testing.T) {
	ca, _ := NewInMemoryKP(nil)
	caCsr := ca.CreateCSR(pkix.Name{}, []string{})
	caTemp := CsrToCACert(caCsr)
	ca.Certificate = caTemp
	ca.Certificate = ca.IssueCertificate(caTemp)
	t.Log("in memory ca created")

	inter, _ := NewInMemoryKP(nil)
	interCsr := inter.CreateCSR(pkix.Name{}, []string{})
	interTemp := CsrToCACert(interCsr)
	inter.Certificate = ca.IssueCertificate(interTemp)
	t.Log("in memory intermediate ca created")

	err := inter.Certificate.CheckSignatureFrom(ca.Certificate)
	if err == nil {
		t.Log("intermediate properly signed by ca")
	} else {
		t.Fatal("intermediate not properly signed by ca: ", err)
	}

	cert1, _ := NewInMemoryKP(nil)
	cert1Csr := cert1.CreateCSR(pkix.Name{}, []string{})
	cert1Temp := CsrToCert(cert1Csr)
	cert1.Certificate = inter.IssueCertificate(cert1Temp)
	t.Log("cert1 signed by intermediate ca")

	err = cert1.Certificate.CheckSignatureFrom(inter.Certificate)
	if err == nil {
		t.Log("verified cert1 signed by intermediate")
	} else {
		t.Fatal("error with cert1 being properly signed by intermediate ca: ", err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(ca.Certificate)

	interCertPool := x509.NewCertPool()
	interCertPool.AddCert(inter.Certificate)

	verifyOpts := x509.VerifyOptions{
		Intermediates: interCertPool,
		Roots:         caCertPool,
	}

	t.Log("new cert pool made of ca and intermediate: ", verifyOpts)

	chain, err := cert1.Certificate.Verify(verifyOpts)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(chain)
}

func TestInMemoryMTLS(t *testing.T) {
	ca, _ := NewInMemoryKP(nil)
	caName := pkix.Name{
		CommonName: "test-ca",
	}
	caCsr := ca.CreateCSR(caName, []string{"ca.localhost"})
	caTemp := CsrToCACert(caCsr)
	ca.Certificate = caTemp
	ca.Certificate = ca.IssueCertificate(caTemp)
	t.Log("in memory ca created")

	clientCert, _ := NewInMemoryKP(nil)
	clientName := pkix.Name{
		CommonName: "test-client",
	}
	clientCsr := clientCert.CreateCSR(clientName, []string{"client.local"})
	clientTemp := CsrToCert(clientCsr)
	clientCert.Certificate = ca.IssueCertificate(clientTemp)
	t.Log("in memory client cert created")

	serverCert, _ := NewInMemoryKP(nil)
	serverName := pkix.Name{
		CommonName: "localhost",
	}
	serverCsr := serverCert.CreateCSR(serverName, []string{"localhost", "127.0.0.1"})
	serverTemp := CsrToCert(serverCsr)
	serverCert.Certificate = ca.IssueCertificate(serverTemp)
	t.Log("in memory server cert created")

	rootPool := x509.NewCertPool()
	if ok := rootPool.AppendCertsFromPEM(ca.CertificatePEM()); !ok {
		t.Fatal("Fail to append")
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handler)

	servertls := &tls.Config{
		ClientAuth:               tls.RequireAndVerifyClientCert,
		ClientCAs:                rootPool,
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		RootCAs:                  rootPool,
		Certificates:             []tls.Certificate{serverCert.TLSCertificate()},
		InsecureSkipVerify:       false,
	}

	servertls.BuildNameToCertificate()

	srv := &http.Server{
		Addr:         ":8443",
		Handler:      mux,
		TLSConfig:    servertls,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	go func() {
		srv.ListenAndServeTLS("", "")
	}()

	defer srv.Close()
	t.Log("server running")

	clienttls := &tls.Config{
		Certificates: []tls.Certificate{clientCert.TLSCertificate()},
		RootCAs:      rootPool,
	}
	clienttls.BuildNameToCertificate()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: clienttls,
		},
	}

	resp, err := client.Get("https://localhost:8443/")
	if err != nil {
		t.Fatal(err)
	}

	msg, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}

	if string(msg) != "ok" {
		t.Fatal("failed to connect to server")
	}

	resp2, err := client.Get("https://127.0.0.1:8443/")
	if err != nil {
		t.Fatal(err)
	}

	msg, err = ioutil.ReadAll(resp2.Body)
	resp2.Body.Close()
	if err != nil {
		t.Fatal(err)
	}

	if string(msg) != "ok" {
		t.Fatal("failed to connect to server")
	}

}

func TestB64Marshalling(t *testing.T) {
	ca, _ := NewInMemoryKP(nil)
	caName := pkix.Name{
		CommonName: "test-ca",
	}
	caCsr := ca.CreateCSR(caName, []string{"ca.localhost"})
	caTemp := CsrToCACert(caCsr)
	ca.Certificate = caTemp
	ca.Certificate = ca.IssueCertificate(caTemp)
	t.Log("in memory ca created")

	kp, _ := NewInMemoryKP(nil)
	csr := kp.CreateCSR(pkix.Name{}, []string{})
	kpCert := CsrToCert(csr)
	kp.Certificate = ca.IssueCertificate(kpCert)

	t.Log("marshalling into b64 string")
	b64KP := kp.Base64Encode()
	t.Log("marshalled b64 string")
	t.Log(b64KP)

	assert.Equal(t, 0, len(b64KP)%4, "all b64 strings should be modulo 4")

	kpTest := &InMemoryKP{}
	kpTest.Base64Decode(b64KP)

	t.Log("parsed b64 string into KP")

	assert.Equal(t, kp.CertificatePEM(), kpTest.CertificatePEM(), "cert pem should be the same")
	assert.Equal(t, kp.KeyPEM(), kpTest.KeyPEM(), "key pem should be the same")

}
