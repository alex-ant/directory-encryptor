package main

import (
	"log"

	"github.com/alex-ant/directory-encryptor/internal/config"
	"github.com/alex-ant/directory-encryptor/internal/encryptor"
)

func main() {
	enc, encErr := encryptor.New(*config.MaxBatchSize, *config.SourceDir, *config.OutputDir, *config.EncryptionKey, *config.Verbose)
	if encErr != nil {
		log.Fatalf("failed to initialize new encrypter processor: %v", encErr)
	}

	enc.Encrypt()
}
