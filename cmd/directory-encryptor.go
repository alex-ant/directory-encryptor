package main

import (
	"log"
	"time"

	"github.com/alex-ant/directory-encryptor/internal/config"
	"github.com/alex-ant/directory-encryptor/internal/encryptor"
)

func main() {
	enc, encErr := encryptor.New(*config.Mode, *config.MaxBatchSize, *config.SourceDir, *config.OutputDir, *config.EncryptionPassword, *config.Verbose)
	if encErr != nil {
		log.Fatalf("failed to initialize new encrypter processor: %v", encErr)
	}

	startTime := time.Now()

	if *config.Mode == "encrypt" {
		enc.Encrypt()
	} else {
		enc.Decrypt()
	}

	log.Printf("%s finished in %d seconds", *config.Mode, int(time.Since(startTime).Seconds()))
}
