package keypair

import (
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

	kp, err := NewYubikeyKP(conf)
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
	conf :=  &YubikeyKeyPairConfig{
		Name: &name,
	}

	kp, err := NewYubikeyKP(conf)
	if err != nil {
		t.Fatal(err.Error())
	}

	if kp == nil {
		t.Fatal("returned kp is nil")
	}

	kp.Yubikey.Close()
}


func TestYubikeyFirst(t *testing.T) {
	conf :=  &YubikeyKeyPairConfig{}

	kp, err := NewYubikeyKP(conf)
	if err != nil {
		t.Fatal(err.Error())
	}

	if kp == nil {
		t.Fatal("returned kp is nil")
	}

	kp.Yubikey.Close()
}


func TestYubikeyCA(t *testing.T) {
	serial := uint32(7713152)
	conf := &YubikeyKeyPairConfig{
		Serial: &serial,
	}

	kp, err := NewYubikeyKP(conf)
	if err != nil {
		t.Fatal(err.Error())
	}

	if kp == nil {
		t.Fatal("returned kp is nil")
	}

}