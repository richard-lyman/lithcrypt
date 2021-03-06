package lithcrypt

import (
	"testing"
)

var password = []byte("some password")
var payload = []byte("some payload")

func TestDecEnc(t *testing.T) {
    encrypted_payload, _ := Encrypt(password, payload)
    if p, _ := Decrypt(password, encrypted_payload); string(p) != string(payload) {
        t.Error("Decrypting what was encrypted did not return the original payload")
    }
}

func TestDecCustomEnc(t *testing.T) {
	encrypted_payload, _ := ParameterizedEncrypt(password, payload, 4096, 16)
	if p, _ := Decrypt(password, encrypted_payload); string(p) != string(payload) {
		t.Error("Decrypting what was custom encrypted did not return the original payload")
	}
}

func TestForMemoryLeak(t *testing.T) {
    i := 100
    for i > 0 {
        encrypted_payload, _ := Encrypt(password, payload)
        if p, _ := Decrypt(password, encrypted_payload); string(p) != string(payload) {
            t.Error("Decrypting what was encrypted did not return the original payload")
        }
        i--
    }
}
