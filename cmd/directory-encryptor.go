package main

import (
	"fmt"

	"github.com/alex-ant/directory-encryptor/internal/config"
)

func main() {
	fmt.Println(*config.MaxBatchSize)
}
