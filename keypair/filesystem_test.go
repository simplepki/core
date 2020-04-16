package keypair

import (
	"os"
	"testing"
)

func TestToFile(t *testing.T) {
	config := &FileSystemKeyPairConfig{
		Location: []string{"/tmp/test1.pki"},
	}

	kp := &FileSystemKP{}
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

func TestFromFile(t *testing.T) {
	config := &FileSystemKeyPairConfig{
		Location: []string{"/tmp/test2.pki"},
	}

	metaConfig := &KeyPairConfig{
		FileSystemConfig: config,
	}

	kp1 := &FileSystemKP{}
	err := kp1.New(metaConfig)
	if err != nil {
		t.Fatal(err.Error())
	}

	kp2 := &FileSystemKP{}
	err = kp2.Load(metaConfig)
	if err != nil {
		t.Fatal(err.Error())
	}

	if kp1.KP.PrivateKey.D.Cmp(kp2.KP.PrivateKey.D) != 0 {
		t.Fatal("key generated and saved was not loaded")
	}

	for _, file := range kp1.Locations {
		err = os.Remove(file)
		if err != nil {
			t.Log(err.Error())
		}
	}

	for _, file := range kp2.Locations {
		err = os.Remove(file)
		if err != nil {
			t.Log(err.Error())
		}
	}
}

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
