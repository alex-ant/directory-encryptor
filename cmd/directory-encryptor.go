package main

import (
	"log"
	"time"

	"github.com/alex-ant/directory-encryptor/internal/config"
	"github.com/alex-ant/directory-encryptor/internal/encryptor"
)

func main() {
	enc, encErr := encryptor.New(*config.MaxBatchSize, *config.SourceDir, *config.OutputDir, *config.EncryptionPassword)
	if encErr != nil {
		log.Fatalf("failed to initialize new encrypter processor: %v", encErr)
	}

	startTime := time.Now()

	var pErr error

	switch *config.Mode {
	case "encrypt":
		pErr = enc.Encrypt()

	case "decrypt":
		pErr = enc.Decrypt()

	case "validate":
		pErr = enc.Validate()

	default:
		log.Fatalf("invalid mode %s, supported modes - encrypt/decryp/validatet", *config.Mode)
	}

	if pErr != nil {
		log.Printf("failed to %s data: %v", *config.Mode, pErr)
	}

	log.Printf("%s finished in %d seconds", *config.Mode, int(time.Since(startTime).Seconds()))
}
