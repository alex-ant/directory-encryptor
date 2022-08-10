package config

import (
	"flag"
	"log"

	"github.com/alex-ant/envs"
)

const (
	batchSize200Mb = 200 * 1024 * 1024
)

var (
	EncryptionPassword = flag.String("p", "", "Encryption password")

	SourceDir = flag.String("s", "", "Directory to encrypt")
	OutputDir = flag.String("o", "", "Output directory")

	Mode = flag.String("m", "", "operation mode (encrypt/decrypt)")

	IgnoredFiles = flag.String("i", ".DS_Store", "comma-separated list of file base names to ignore during the validation")

	MaxBatchSize = flag.Int64("b", batchSize200Mb, "Max encrypted batch file size in bytes (200Mb by default)")
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
