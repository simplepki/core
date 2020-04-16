package keypair

import (
	"crypto/x509/pkix"
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

func TestYubikeyNewCA(t *testing.T) {
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

	caCSR := kp.CreateCSR(pkix.Name{}, []string{})
	caCertTemp := CsrToCACert(caCSR)

	kp.importCert(caCertTemp)
	/*caCert := kp.IssueCertificate(caCertTemp)
	caPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.Raw,
	})
	err = kp.ImportCertificate(caPEM)
	if err != nil {
		t.Fatal(err.Error())
	}*/

	kp.Yubikey.Close()
}
