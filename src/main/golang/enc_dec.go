package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

type AESBouncyCastle struct {
	key []byte
}

func (a *AESBouncyCastle) setKey(key []byte) {
	a.key = key
}

func (a *AESBouncyCastle) encrypt(input []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(input))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], input)

	return ciphertext, nil
}

func (a *AESBouncyCastle) decrypt(input []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}

	if len(input) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := input[:aes.BlockSize]
	input = input[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(input, input)

	return input, nil
}

func main() {
	aesBC := &AESBouncyCastle{}
	key, _ := base64.StdEncoding.DecodeString("8wxoTnDywJC5WpruGPqlbjjCugl776VqP6NAMpq2z2E=")
	aesBC.setKey(key)

	plaintext := []byte("Hello, Bouncy Castle!")
	ciphertext, err := aesBC.encrypt(plaintext)
	if err != nil {
		fmt.Println("Encryption error:", err)
		return
	}

	fmt.Printf("Encrypted: %x\n", ciphertext)

	decrypted, err := aesBC.decrypt(ciphertext)
	if err != nil {
		fmt.Println("Decryption error:", err)
		return
	}

	fmt.Println("Decrypted:", string(decrypted))
}
