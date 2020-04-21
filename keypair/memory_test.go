package keypair

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net/http"

	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewInMemoryKP(t *testing.T) {
	kp := &InMemoryKP{}
	kp.New(nil)
	t.Log("in memory kp: ", kp)

	csr, err := kp.CreateCSR(pkix.Name{}, []string{})
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Log("in memory kp csr: ", csr)
}

func TestInMemorySelfSigned(t *testing.T) {
	kp := &InMemoryKP{}
	kp.New(nil)

	csrDer, err := kp.CreateCSR(pkix.Name{}, []string{})
	if err != nil {
		t.Fatal(err.Error())
	}

	csrCert, err := x509.ParseCertificateRequest(csrDer)
	if err != nil {
		t.Fatal(err.Error())
	}

	issuedCertBytes, err := kp.IssueCertificate(csrCert, true, true)
	if err != nil {
		t.Fatal(err.Error())
	}
	issuedCert, err := x509.ParseCertificate(issuedCertBytes)
	if err != nil {
		t.Fatal(err.Error())
	}
	kp.Certificate = issuedCert

	assert.Equal(t, true, kp.Certificate.IsCA, "should be a ca certificate")
}

func TestInMemoryCA(t *testing.T) {
	t.Log("generating ca")
	ca := &InMemoryKP{}
	ca.New(nil)
	caCsrBytes, err := ca.CreateCSR(pkix.Name{}, []string{})
	if err != nil {
		t.Fatal(err.Error())
	}

	caCSRCert, err := x509.ParseCertificateRequest(caCsrBytes)
	if err != nil {
		t.Fatal(err.Error())
	}
	issuedCertBytes, err := ca.IssueCertificate(caCSRCert, true, true)
	if err != nil {
		t.Fatal(err.Error())
	}

	issuedCACert, err := x509.ParseCertificate(issuedCertBytes)
	if err != nil {
		t.Fatal(err.Error())
	}
	assert.Equal(t, true, issuedCACert.IsCA, "ca should be the ca")
	err = ca.ImportCertificate(issuedCertBytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	cert1 := &InMemoryKP{}
	cert1.New(nil)
	cert1CsrBytes, err := cert1.CreateCSR(pkix.Name{}, []string{})
	if err != nil {
		t.Fatal(err.Error())
	}

	cert1CSR, err := x509.ParseCertificateRequest(cert1CsrBytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	issuedCert1Bytes, err := ca.IssueCertificate(cert1CSR, false, false)
	if err != nil {
		t.Fatal(err.Error())
	}

	err = cert1.ImportCertificate(issuedCert1Bytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	err = cert1.Certificate.CheckSignatureFrom(ca.Certificate)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("verified cert1 signed by the ca")

	cert2 := &InMemoryKP{}
	cert2.New(nil)
	cert2CsrBytes, err := cert2.CreateCSR(pkix.Name{}, []string{})
	if err != nil {
		t.Fatal(err.Error())
	}

	cert2CSR, err := x509.ParseCertificateRequest(cert2CsrBytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	cert2Bytes, err := cert1.IssueCertificate(cert2CSR, false, false)
	if err != nil {
		t.Fatal(err.Error())
	}

	err = cert2.ImportCertificate(cert2Bytes)
	if err != nil {
		t.Fatal(err.Error())
	}
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
	ca := &InMemoryKP{}
	ca.New(nil)
	caCsrBytes, err := ca.CreateCSR(pkix.Name{}, []string{})
	if err != nil {
		t.Fatal(err.Error())
	}

	caCSR, err := x509.ParseCertificateRequest(caCsrBytes)
	if err != nil {
		t.Fatal(err.Error())
	}
	caCertBytes, err := ca.IssueCertificate(caCSR, true, true)
	if err != nil {
		t.Fatal(err.Error())
	}

	err = ca.ImportCertificate(caCertBytes)
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Log("in memory ca created")

	inter := &InMemoryKP{}
	inter.New(nil)
	interCsrBytes, err := inter.CreateCSR(pkix.Name{}, []string{})
	if err != nil {
		t.Fatal(err.Error())
	}

	interCSR, err := x509.ParseCertificateRequest(interCsrBytes)
	if err != nil {
		t.Fatal(err.Error())
	}
	interCertBytes, err := ca.IssueCertificate(interCSR, true, false)
	if err != nil {
		t.Fatal(err.Error())
	}

	err = inter.ImportCertificate(interCertBytes)
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Log("in memory intermediate ca created")

	err = inter.Certificate.CheckSignatureFrom(ca.Certificate)
	if err == nil {
		t.Log("intermediate properly signed by ca")
	} else {
		t.Fatal("intermediate not properly signed by ca: ", err)
	}

	cert1 := &InMemoryKP{}
	cert1.New(nil)
	cert1CSRBytes, err := cert1.CreateCSR(pkix.Name{}, []string{})
	if err != nil {
		t.Fatal(err.Error())
	}

	cert1CSR, err := x509.ParseCertificateRequest(cert1CSRBytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	cert1Bytes, err := inter.IssueCertificate(cert1CSR, false, false)
	if err != nil {
		t.Fatal(err.Error())
	}

	err = cert1.ImportCertificate(cert1Bytes)
	if err != nil {
		t.Fatal(err.Error())
	}
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
	ca := &InMemoryKP{}
	ca.New(nil)
	caName := pkix.Name{
		CommonName: "test-ca",
	}
	caCsrBytes, err := ca.CreateCSR(caName, []string{"ca.localhost"})
	if err != nil {
		t.Fatal(err.Error())
	}

	caCSR, err := x509.ParseCertificateRequest(caCsrBytes)
	if err != nil {
		t.Fatal(err.Error())
	}
	caCertBytes, err := ca.IssueCertificate(caCSR, true, true)
	if err != nil {
		t.Fatal(err.Error())
	}

	err = ca.ImportCertificate(caCertBytes)
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Log("in memory ca created")

	clientCert := &InMemoryKP{}
	clientCert.New(nil)
	clientName := pkix.Name{
		CommonName: "test-client",
	}
	clientCsrBytes, err := clientCert.CreateCSR(clientName, []string{"client.local"})
	if err != nil {
		t.Fatal(err.Error())
	}

	clientCSR, err := x509.ParseCertificateRequest(clientCsrBytes)
	if err != nil {
		t.Fatal(err.Error())
	}
	clientCertBytes, err := ca.IssueCertificate(clientCSR, false, false)
	if err != nil {
		t.Fatal(err.Error())
	}

	err = clientCert.ImportCertificate(clientCertBytes)
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Log("in memory client cert created")

	serverCert := &InMemoryKP{}
	serverCert.New(nil)
	serverName := pkix.Name{
		CommonName: "localhost",
	}
	serverCsrBytes, err := serverCert.CreateCSR(serverName, []string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatal(err.Error())
	}

	serverCSR, err := x509.ParseCertificateRequest(serverCsrBytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	serverCertBytes, err := ca.IssueCertificate(serverCSR, false, false)
	if err != nil {
		t.Fatal(err.Error())
	}

	err = serverCert.ImportCertificate(serverCertBytes)
	if err != nil {
		t.Fatal(err.Error())
	}
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

	serverTLS, err := serverCert.TLSCertificate()
	if err != nil {
		t.Fatal(err.Error())
	}
	servertls := &tls.Config{
		ClientAuth:               tls.RequireAndVerifyClientCert,
		ClientCAs:                rootPool,
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		RootCAs:                  rootPool,
		Certificates:             []tls.Certificate{serverTLS},
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

	clientTLS, err := clientCert.TLSCertificate()
	if err != nil {
		t.Fatal(err.Error())
	}
	clienttls := &tls.Config{
		Certificates: []tls.Certificate{clientTLS},
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
	ca := &InMemoryKP{}
	ca.New(nil)
	caName := pkix.Name{
		CommonName: "test-ca",
	}
	caCsrBytes, err := ca.CreateCSR(caName, []string{"ca.localhost"})
	if err != nil {
		t.Fatal(err.Error())
	}

	caCSR, err := x509.ParseCertificateRequest(caCsrBytes)
	if err != nil {
		t.Fatal(err.Error())
	}
	caCertBytes, err := ca.IssueCertificate(caCSR, true, true)
	if err != nil {
		t.Fatal(err.Error())
	}

	err = ca.ImportCertificate(caCertBytes)
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Log("in memory ca created")

	kp := InMemoryKP{}
	kp.New(nil)
	csrBytes, err := kp.CreateCSR(pkix.Name{}, []string{})
	if err != nil {
		t.Fatal(err.Error())
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		t.Fatal(err.Error())
	}
	certBytes, err := ca.IssueCertificate(csr, false, false)
	if err != nil {
		t.Fatal(err.Error())
	}
	err = kp.ImportCertificate(certBytes)
	if err != nil {
		t.Fatal(err.Error())
	}
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
