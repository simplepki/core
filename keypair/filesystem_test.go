package keypair

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"reflect"
	"testing"
)

func TestToFile(t *testing.T) {
	config := &FileSystemKeyPairConfig{
		CertFile:  "/tmp/cert.pem",
		KeyFile:   "/tmp/key.pem",
		ChainFile: "/tmp/chain.pem",
	}

	kp := &FileSystemKP{}
	err := kp.New(&KeyPairConfig{
		FileSystemConfig: config,
	})

	if err != nil {
		t.Fatal(err.Error())
	}

	os.Remove(config.CertFile)
	os.Remove(config.KeyFile)
	os.Remove(config.ChainFile)
}

func TestFromFile(t *testing.T) {
	config := &FileSystemKeyPairConfig{
		CertFile:  "/tmp/cert.pem",
		KeyFile:   "/tmp/key.pem",
		ChainFile: "/tmp/chain.pem",
	}

	metaConfig := &KeyPairConfig{
		FileSystemConfig: config,
	}

	kp1 := &FileSystemKP{}
	err := kp1.New(metaConfig)
	if err != nil {
		t.Fatal(err.Error())
	}

	kp1CSRBytes, err := kp1.CreateCSR(pkix.Name{}, []string{})
	if err != nil {
		t.Fatal(err.Error())
	}

	kp1CSR, err := x509.ParseCertificateRequest(kp1CSRBytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	kp1CertBytes, err := kp1.IssueCertificate(kp1CSR, true, true)
	if err != nil {
		t.Fatal(err.Error())
	}

	err = kp1.ImportCertificate(kp1CertBytes)
	if err != nil {
		t.Fatal(err.Error())
	}

	err = kp1.ImportCertificateChain([][]byte{kp1CertBytes})
	if err != nil {
		t.Fatal(err.Error())
	}

	kp2 := &FileSystemKP{}
	err = kp2.Load(metaConfig)
	if err != nil {
		t.Fatal(err.Error())
	}

	if !reflect.DeepEqual(kp1, kp2) {
		t.Fatal("key generated and saved was not loaded")
	}

	os.Remove(config.CertFile)
	os.Remove(config.KeyFile)
	os.Remove(config.ChainFile)
}

/*
func TestMultipleToFile(t *testing.T) {
	config := &FileSystemKeyPairConfig{
		Location: []string{
			"/tmp/testa.pki",
			"/tmp/testb",
		},
	}

	kp := FileSystemKP{}
	err := kp.New(&KeyPairConfig{
		FileSystemConfig: config,
	})

	if err != nil {
		t.Fatal(err.Error())
	}

	for _, file := range kp.Locations {
		err = os.Remove(file)
		if err != nil {
			t.Log(err.Error())
		}
	}
}
*/
