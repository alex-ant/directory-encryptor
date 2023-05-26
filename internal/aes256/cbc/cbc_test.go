package cbc

import (
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCBC(t *testing.T) {
	rand.Seed(time.Now().UnixNano())

	const (
		testKey = `NJ*R07(l@K!<P8j0\qI^0'(rb;f&\;.f` // 32 bytes
		iv      = `hII>]?oE=96mk&U&`                 // 16 bytes

		minDataSrtLen = 10
		maxDataSrtLen = 300

		iterations = 10
	)

	for i := 0; i < iterations; i++ {
		// Generate test data.
		testData := randomString(randomInt(minDataSrtLen, maxDataSrtLen))

		// Encrypt test data.
		encrypted, encryptedErr := Encrypt([]byte(testData), testKey, iv)
		require.NoError(t, encryptedErr)

		// Decrypt test data.
		decryted, decrytedErr := Decrypt(encrypted, testKey, iv)
		require.NoError(t, decrytedErr)
		require.Equal(t, testData, string(decryted))
	}
}

func randomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func randomInt(min, max int) int {
	return rand.Intn(max-min) + min
}
