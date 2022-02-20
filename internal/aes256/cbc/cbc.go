package cbc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
)

// Encrypt encrypts passed data into AES-256-CBC base64-encoded string.
func Encrypt(data []byte, key, iv string) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data payload provided")
	}

	c, cErr := aes.NewCipher([]byte(key))
	if cErr != nil {
		return nil, fmt.Errorf("failed to create new AES cipher: %v", cErr)
	}

	enc := cipher.NewCBCEncrypter(c, []byte(iv))

	dataB := pkcs5Padding(data, c.BlockSize())

	encrypted := make([]byte, len(dataB))
	enc.CryptBlocks(encrypted, dataB)

	return []byte(base64.StdEncoding.EncodeToString(encrypted)), nil
}

// Decrypt decrypts passed AES-256-CBC encrypted base64-encoded data.
func Decrypt(data []byte, key, iv string) ([]byte, error) {
	encrypted, encryptedErr := base64.StdEncoding.DecodeString(string(data))
	if encryptedErr != nil {
		return nil, fmt.Errorf("failed to decode encrypted base64 string: %v", encryptedErr)
	}

	c, cErr := aes.NewCipher([]byte(key))
	if cErr != nil {
		return nil, fmt.Errorf("failed to create new AES cipher: %v", cErr)
	}

	dec := cipher.NewCBCDecrypter(c, []byte(iv))

	decrypted := make([]byte, len(encrypted))
	dec.CryptBlocks(decrypted, encrypted)

	tr, trErr := pkcs5Trimming(decrypted)
	if trErr != nil {
		return nil, trErr
	}

	return tr, nil
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
