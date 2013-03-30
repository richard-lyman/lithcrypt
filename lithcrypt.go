package lithcrypt

import (
	"code.google.com/p/go.crypto/scrypt"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"os"
)

const salt_size = 128

func Encrypt(password []byte, payload []byte) ([]byte, error) {
    return ParameterizedEncrypt( password, payload, 32768, 8, 1, 32 )
}

func ParameterizedEncrypt(password []byte, payload []byte, N int, r int, p int, keyLen int ) ([]byte, error) {
	salt := genSalt()
	key := genKey(password, salt, N, r, p, keyLen)

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

func Decrypt(password []byte, payload []byte) ([]byte, error) {
	salt := payload[:salt_size]
	N := extractInt(string(payload[salt_size:(salt_size+10)]), 10)
	r := extractInt(string(payload[salt_size+10:(salt_size+12)]), 2)
	p := extractInt(string(payload[salt_size+12:(salt_size+14)]), 2)
	keyLen := extractInt(string(payload[salt_size+14:(salt_size+17)]), 3)
	ivLen := extractInt(string(payload[salt_size+17:(salt_size+20)]), 3)
	iv := payload[salt_size+20 : salt_size+20+ivLen]
	key := genKey(password, salt, N, r, p, keyLen)
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
	return fmt.Sprintf(fmt.Sprintf("%%%dd", space), i)
}

func xorKeyStream(cfb cipher.Stream, payload []byte) []byte {
	result := make([]byte, len(payload))
	cfb.XORKeyStream(result, payload)
	return result
}

func getRandom(size int) ([]byte, error) {
	result := make([]byte, size)
	if _, err := rand.Read(result); err != nil {
		return nil, err
	}
	return result, nil
}

func genSalt() []byte {
	salt, err := getRandom(salt_size)
	if err != nil {
		fmt.Println("Error generating salt:", err)
		os.Exit(1)
	}
	return salt
}

func genKey(password []byte, salt []byte, N int, r int, p int, keyLen int) []byte {
	key, err := scrypt.Key(password, salt, N, r, p, keyLen)
	if err != nil {
		fmt.Println("Error with scrypt:", err)
		os.Exit(1)
	}
	return key
}
