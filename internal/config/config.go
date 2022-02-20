package config

import (
	"flag"
	"log"

	"github.com/alex-ant/envs"
)

const (
	batchSize4p2Gb = 4509715660
)

var (
	EncryptionKey = flag.String("k", "", "Encryption key")

	SourceDir = flag.String("s", ".", "Directory to encrypt")
	OutputDir = flag.String("o", "./encrypted", "Output directory")

	Mode = flag.String("m", "", "operation mode (encrypt/decrypt)")

	Verbose = flag.Bool("v", false, "Verbose logs")

	MaxBatchSize = flag.Int64("b", batchSize4p2Gb, "Max encrypted batch file size in bytes (4.2Gb by default)")
)

func init() {
	// Parse flags if not parsed already.
	if !flag.Parsed() {
		flag.Parse()
	}

	// Determine and read environment variables.
	flagsErr := envs.GetAllFlags()
	if flagsErr != nil {
		log.Fatal(flagsErr)
	}
}
