package lithcrypt

import (
	"code.google.com/p/go.crypto/scrypt"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
  "errors"
  "fmt"
  "io"
)

const salt_size = 16

func Encrypt(password []byte, payload []byte) ([]byte, error) {
	return ParameterizedEncrypt(password, payload, 32768, 8, 1, 16)
}

func ParameterizedEncrypt(password []byte, payload []byte, N int, r int, p int, keyLen int) ([]byte, error) {
	salt, salt_error := getRandom(salt_size)
	if salt_error != nil {
		return nil, salt_error
	}
	key, key_error := genKey(password, salt, N, r, p, keyLen)
	if key_error != nil {
		return nil, key_error
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv, iv_err := getRandom(c.BlockSize())
	if iv_err != nil {
		return nil, iv_err
	}

	result := make([]byte, 0, len(payload)+len(salt)+len(iv)+10+2+2+3+3)
	result = append(result, salt...)
	result = append(result, []byte(injectInt(N, 10)+injectInt(r, 2)+injectInt(p, 2)+injectInt(keyLen, 3)+injectInt(len(iv), 3))...)
	result = append(result, iv...)

	return append(result, xorKeyStream(cipher.NewCFBEncrypter(c, iv), payload)...), nil
}

func Decrypt(password []byte, payload []byte) (result []byte, err error) {
  defer func(){
    if r := recover(); r!= nil {
      err = errors.New(fmt.Sprintf("%v",r))
    }
  }()
	salt := payload[:salt_size]
	N := extractInt(string(payload[salt_size:(salt_size+10)]), 10)
	r := extractInt(string(payload[salt_size+10:(salt_size+12)]), 2)
	p := extractInt(string(payload[salt_size+12:(salt_size+14)]), 2)
	keyLen := extractInt(string(payload[salt_size+14:(salt_size+17)]), 3)
	ivLen := extractInt(string(payload[salt_size+17:(salt_size+20)]), 3)
	iv := payload[salt_size+20 : salt_size+20+ivLen]
	key, key_error := genKey(password, salt, N, r, p, keyLen)
	if key_error != nil {
		return nil, key_error
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return xorKeyStream(cipher.NewCFBDecrypter(c, iv), payload[salt_size+20+ivLen:]), nil
}

func paddedIntFormat(space int) string {
	return fmt.Sprintf("%%%dd", space)
}

func extractInt(s string, space int) int {
	result := -1
	fmt.Sscanf(s, paddedIntFormat(space), &result)
	return result
}

func injectInt(i int, space int) string {
	return fmt.Sprintf(paddedIntFormat(space), i)
}

func xorKeyStream(cfb cipher.Stream, payload []byte) []byte {
	result := make([]byte, len(payload))
	cfb.XORKeyStream(result, payload)
	return result
}

func getRandom(size int) ([]byte, error) {
	result := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, result); err != nil {
		return nil, err
	}
	return result, nil
}

func genKey(password []byte, salt []byte, N int, r int, p int, keyLen int) ([]byte, error) {
	return scrypt.Key(password, salt, N, r, p, keyLen)
}
