package keypair

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io/ioutil"
	"net/http"
	"reflect"
	"testing"
)

func TestGetPivs(t *testing.T) {
	cards, err := getAllYubikeys()
	if err != nil {
		t.Fatalf("no pivs: %s\n", err.Error())
	}

	for serial, card := range cards {
		t.Logf("card found: <%v,%s>\n", serial, card)
	}
}

func TestYubikeySerial(t *testing.T) {
	serial := uint32(7713152)
	conf := &YubikeyKeyPairConfig{
		Serial: &serial,
	}

	kp := &YubikeyKP{}
	err := kp.New(&KeyPairConfig{
		YubikeyConfig: conf,
	})
	if err != nil {
		t.Fatal(err.Error())
	}

	if kp == nil {
		t.Fatal("returned kp is nil")
	}

	kp.Yubikey.Close()
}

func TestYubikeyName(t *testing.T) {
	name := "Yubico YubiKey OTP+FIDO+CCID 00 00"
	conf := &YubikeyKeyPairConfig{
		Name: &name,
	}

	kp := &YubikeyKP{}
	err := kp.New(&KeyPairConfig{
		YubikeyConfig: conf,
	})
	if err != nil {
		t.Fatal(err.Error())
	}

	if kp == nil {
		t.Fatal("returned kp is nil")
	}

	kp.Yubikey.Close()
}

func TestYubikeyFirst(t *testing.T) {
	conf := &YubikeyKeyPairConfig{}

	kp := &YubikeyKP{}
	err := kp.New(&KeyPairConfig{
		YubikeyConfig: conf,
	})
	if err != nil {
		t.Fatal(err.Error())
	}

	if kp == nil {
		t.Fatal("returned kp is nil")
	}

	kp.Yubikey.Close()
}

func TestYubikeyNeW(t *testing.T) {
	serial := uint32(7713152)
	conf := &YubikeyKeyPairConfig{
		Serial: &serial,
		Reset:  true,
	}

	kp := &YubikeyKP{}
	err := kp.New(&KeyPairConfig{
		YubikeyConfig: conf,
	})
	if err != nil {
		t.Fatal(err.Error())
	}

	if kp == nil {
		t.Fatal("returned kp is nil")
	}

	caCSRBytes, err := kp.CreateCSR(pkix.Name{}, []string{})
	if err != nil {
		t.Fatal(err.Error())
	}

	csr, err := x509.ParseCertificateRequest(caCSRBytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	caCertBytes, err := kp.IssueCertificate(csr, true, true)
	err = kp.ImportCertificate(caCertBytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	kp.Yubikey.Close()
}

func TestYubikeyLoad(t *testing.T) {
	serial := uint32(7713152)
	conf := &YubikeyKeyPairConfig{
		Serial: &serial,
		Reset:  true,
	}

	kp := &YubikeyKP{}
	err := kp.New(&KeyPairConfig{
		YubikeyConfig: conf,
	})
	if err != nil {
		t.Fatal(err.Error())
	}

	if kp == nil {
		t.Fatal("returned kp is nil")
	}

	caCSRBytes, err := kp.CreateCSR(pkix.Name{}, []string{})
	if err != nil {
		t.Fatal(err.Error())
	}

	csr, err := x509.ParseCertificateRequest(caCSRBytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	caCertBytes, err := kp.IssueCertificate(csr, true, true)
	err = kp.ImportCertificate(caCertBytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	cert1 := kp.GetCertificate()
	t.Logf("got cert: %#v\n", cert1.Raw)
	kp.Yubikey.Close()

	kp2 := &YubikeyKP{}
	err = kp2.Load(&KeyPairConfig{
		YubikeyConfig: conf,
	})
	if err != nil {
		t.Fatal(err.Error())
	}

	if kp2 == nil {
		t.Fatal("returned kp is nil")
	}

	cert2 := kp2.GetCertificate()

	if cert2 == nil {
		t.Fatal("loaded cert is nil")
	}

	t.Logf("got cert: %#v\n", cert2.Raw)

	if !reflect.DeepEqual(cert1.Raw, cert2.Raw) {
		t.Fatal("loaded yubikey kp not the same as the original")
	}

	kp2.Yubikey.Close()
}

func TestYubikeySigningCert(t *testing.T) {
	serial := uint32(7713152)
	conf := &YubikeyKeyPairConfig{
		Serial: &serial,
		Reset:  true,
	}

	ca := &YubikeyKP{}
	err := ca.New(&KeyPairConfig{
		YubikeyConfig: conf,
	})
	if err != nil {
		t.Fatal(err.Error())
	}

	if ca == nil {
		t.Fatal("returned kp is nil")
	}

	caCSRBytes, err := ca.CreateCSR(pkix.Name{}, []string{})
	if err != nil {
		t.Fatal(err.Error())
	}

	csr, err := x509.ParseCertificateRequest(caCSRBytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	caCertBytes, err := ca.IssueCertificate(csr, true, true)
	err = ca.ImportCertificate(caCertBytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	// sign in memory cert off chain
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

	cert1Bytes, err := ca.IssueCertificate(cert1CSR, false, false)
	if err != nil {
		t.Fatal(err.Error())
	}

	err = cert1.ImportCertificate(cert1Bytes)
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Log("cert1 signed by ca")

	err = cert1.Certificate.CheckSignatureFrom(ca.GetCertificate())
	if err == nil {
		t.Log("verified cert1 signed by intermediate")
	} else {
		t.Fatal("error with cert1 being properly signed by intermediate ca: ", err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(ca.GetCertificate())

	interCertPool := x509.NewCertPool()

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

	ca.Yubikey.Close()
}

func TestYubikeyServer(t *testing.T) {
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

	// set up server cert
	serial := uint32(7713152)
	conf := &YubikeyKeyPairConfig{
		Serial: &serial,
		Reset:  true,
	}

	server := &YubikeyKP{}
	err = server.New(&KeyPairConfig{
		YubikeyConfig: conf,
	})
	if err != nil {
		t.Fatal(err.Error())
	}

	if server == nil {
		t.Fatal("returned kp is nil")
	}

	serverCSRBytes, err := server.CreateCSR(pkix.Name{}, []string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatal(err.Error())
	}

	serverCSR, err := x509.ParseCertificateRequest(serverCSRBytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	serverCertBytes, err := ca.IssueCertificate(serverCSR, false, false)
	err = server.ImportCertificate(serverCertBytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	rootPool := x509.NewCertPool()
	if ok := rootPool.AppendCertsFromPEM(ca.CertificatePEM()); !ok {
		t.Fatal("Fail to append")
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handler)

	serverTLS, err := server.TLSCertificate()
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

func TestYubikeyClient(t *testing.T) {
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

	// set up server cert

	serial := uint32(7713152)
	conf := &YubikeyKeyPairConfig{
		Serial: &serial,
		Reset:  true,
	}

	client := &YubikeyKP{}
	err = client.New(&KeyPairConfig{
		YubikeyConfig: conf,
	})
	if err != nil {
		t.Fatal(err.Error())
	}

	if client == nil {
		t.Fatal("returned kp is nil")
	}

	clientCSRBytes, err := client.CreateCSR(pkix.Name{}, []string{"localhost", "127.0.0.1"})
	if err != nil {
		t.Fatal(err.Error())
	}

	clientCSR, err := x509.ParseCertificateRequest(clientCSRBytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	clientCertBytes, err := ca.IssueCertificate(clientCSR, false, false)
	err = client.ImportCertificate(clientCertBytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	t.Log("yubikey server cert created")

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

	clientTLS, err := client.TLSCertificate()
	if err != nil {
		t.Fatal(err.Error())
	}
	clienttls := &tls.Config{
		Certificates: []tls.Certificate{clientTLS},
		RootCAs:      rootPool,
	}
	clienttls.BuildNameToCertificate()

	httpclient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: clienttls,
		},
	}

	resp, err := httpclient.Get("https://localhost:8443/")
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

	resp2, err := httpclient.Get("https://127.0.0.1:8443/")
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
