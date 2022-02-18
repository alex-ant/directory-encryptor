package cbc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
)

var (
	initialVector = "1010101010101010"
)

// Encrypt encrypts passed data into AES-256-CBC base64-encoded string.
func Encrypt(data, key string) (string, error) {
	if data == "" {
		return "", errors.New("empty data payload provided")
	}

	c, cErr := aes.NewCipher([]byte(key))
	if cErr != nil {
		return "", fmt.Errorf("failed to create new AES cipher: %v", cErr)
	}

	enc := cipher.NewCBCEncrypter(c, []byte(initialVector))

	dataB := pkcs5Padding([]byte(data), c.BlockSize())

	encrypted := make([]byte, len(dataB))
	enc.CryptBlocks(encrypted, dataB)

	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// Decrypt decrypts passed AES-256-CBC encrypted base64-encoded data.
func Decrypt(data, key string) (string, error) {
	encrypted, encryptedErr := base64.StdEncoding.DecodeString(data)
	if encryptedErr != nil {
		return "", fmt.Errorf("failed to decode encrypted base64 string: %v", encryptedErr)
	}

	c, cErr := aes.NewCipher([]byte(key))
	if cErr != nil {
		return "", fmt.Errorf("failed to create new AES cipher: %v", cErr)
	}

	dec := cipher.NewCBCDecrypter(c, []byte(initialVector))

	decrypted := make([]byte, len(encrypted))
	dec.CryptBlocks(decrypted, encrypted)

	tr, trErr := pkcs5Trimming(decrypted)
	if trErr != nil {
		return "", trErr
	}

	return string(tr), nil
}

func pkcs5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func pkcs5Trimming(encrypt []byte) ([]byte, error) {
	padding := encrypt[len(encrypt)-1]

	if int(padding) == 0 || int(padding) > len(encrypt)-1 {
		return nil, errors.New("invalid encryption key")
	}

	return encrypt[:len(encrypt)-int(padding)], nil
}
