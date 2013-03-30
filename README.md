
# Install #
```go get github.com/richard-lyman/lithcrypt/```

# Example #
 1. Run the installation command from above
 2. Place the following code in some file (we'll call ours 'main.go')
 3. From the same folder where you created your file ('main.go'), run the command ```go run main.go``` (replacing 'main.go' with whatever name you gave your file)

```go
package main

import (
    "encoding/base64"
    "fmt"
    "github.com/richard-lyman/lithcrypt"
)

func main() {

    payload := []byte("Something to be encrypted")
    password := []byte("some password")

    encrypted, encrypt_error := lithcrypt.Encrypt(password, payload)
    if encrypt_error != nil {
        fmt.Println("Failed to encrypt:", encrypt_error)
    }
    fmt.Println("Encrypted payload:", byteSliceToBase64(encrypted))

    original, decrypt_error := lithcrypt.Decrypt(password, encrypted)
    if decrypt_error != nil {
        fmt.Println("Failed to decrypt:", decrypt_error)
    }
    fmt.Println("Decrypted payload:", string(original))

}

func byteSliceToBase64(b []byte) string {
    result := make([]byte, base64.StdEncoding.EncodedLen(len(b)))
    base64.StdEncoding.Encode(result, b)
    return string(result)
}
```
