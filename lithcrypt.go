package lithcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"errors"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io"
)

const salt_size = 32

func Encrypt(password []byte, payload []byte) ([]byte, error) {
	return ParameterizedEncrypt(password, payload, 4092, 32)
}

func ParameterizedEncrypt(password []byte, payload []byte, iter int, keyLen int) ([]byte, error) {
	salt, salt_error := GetRandom(salt_size)
	if salt_error != nil {
		return nil, salt_error
	}
	key, key_error := GenKey(password, salt, iter, keyLen)
	if key_error != nil {
		return nil, key_error
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv, iv_err := GetRandom(c.BlockSize())
	if iv_err != nil {
		return nil, iv_err
	}

	result := make([]byte, 0, len(payload)+len(salt)+len(iv)+8+3+3)
	result = append(result, salt...)
	result = append(result, []byte(injectInt(iter, 8)+injectInt(keyLen, 3)+injectInt(len(iv), 3))...)
	result = append(result, iv...)

	return append(result, xorKeyStream(cipher.NewCFBEncrypter(c, iv), payload)...), nil
}

func Decrypt(password []byte, payload []byte) (result []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New(fmt.Sprintf("%v", r))
		}
	}()
	salt := payload[:salt_size]
	iter := extractInt(string(payload[salt_size:(salt_size+8)]), 8)
	keyLen := extractInt(string(payload[salt_size+8:(salt_size+11)]), 3)
	ivLen := extractInt(string(payload[salt_size+11:(salt_size+14)]), 3)
	iv := payload[salt_size+14 : salt_size+14+ivLen]
	key, key_error := GenKey(password, salt, iter, keyLen)
	if key_error != nil {
		return nil, key_error
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	preresult := xorKeyStream(cipher.NewCFBDecrypter(c, iv), payload[salt_size+14+ivLen:])
	return preresult, nil
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

func GetRandom(size int) ([]byte, error) {
	result := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, result); err != nil {
		return nil, err
	}
	return result, nil
}

func GenKey(password []byte, salt []byte, iter int, keyLen int) ([]byte, error) {
	result := pbkdf2.Key(password, salt, iter, keyLen, sha1.New)
	return result, nil
}
