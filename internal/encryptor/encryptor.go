package encryptor

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
)

const (
	chunkSize int = 16
)

// Processor contains encryptor processor data.
type Processor struct {
	maxBatchSize int64

	sourceDir string
	outputDir string

	verboseLogs bool
}

// New returns new Processor.
func New(maxBatchSize int64, sourceDir, outputDir string, verboseLogs bool) (*Processor, error) {
	// Check if output directory exists.
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		mkdirErr := os.Mkdir(outputDir, 0755)
		if mkdirErr != nil {
			return nil, fmt.Errorf("failed to create output directory: %v", mkdirErr)
		}
	}

	// Check if source directory exists.
	if _, err := os.Stat(sourceDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("source directory %s doesn't exist", sourceDir)
	}

	return &Processor{
		maxBatchSize: maxBatchSize,

		sourceDir: sourceDir,
		outputDir: outputDir,

		verboseLogs: verboseLogs,
	}, nil
}

type filetype int

const (
	FILE filetype = iota
	DIRECTORY
)

type fileInfo struct {
	RelativePath string   `json:"p"`
	Filetype     filetype `json:"t"`
	size         int64
}

func (p *Processor) Encrypt() error {
	files := []*fileInfo{}

	// List files to encrypt.
	walkErr := filepath.Walk(
		p.sourceDir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Trim path.
			if path[len(path)-1] == '/' {
				path = path[:len(path)-1]
			}

			path = path[len(p.sourceDir):]

			if len(path) == 0 {
				return nil
			}

			if path[0] == '/' {
				path = path[1:]
			}

			// Populate file metadata.
			ft := FILE
			var size int64

			if info.IsDir() {
				ft = DIRECTORY
			} else {
				// Track only file sizes.
				size = info.Size()
			}

			files = append(files, &fileInfo{
				RelativePath: path,
				Filetype:     ft,
				size:         size,
			})

			return nil
		})
	if walkErr != nil {
		return fmt.Errorf("failed to get contents of %s: %v", p.sourceDir, walkErr)
	}

	// Generate metadata batches.
	batches := [][]*fileInfo{}

	var currentBatchSize int64

	currBatch := []*fileInfo{}
	for _, f := range files {
		if currentBatchSize+f.size > p.maxBatchSize {
			batches = append(batches, currBatch)
			currBatch = []*fileInfo{}
			currentBatchSize = 0
		}

		currBatch = append(currBatch, f)
		currentBatchSize += f.size
	}

	batches = append(batches, currBatch)

	// Print.
	for _, batch := range batches {
		fmt.Println("-----")

		for _, f := range batch {
			// Marshall metadata.
			fb, _ := json.Marshal(*f)

			fmt.Println(string(fb))

			if f.Filetype == FILE {
				// Read file contents.
				readErr := readFileInChunks(path.Join(p.sourceDir, f.RelativePath), func(data []byte) {
					fmt.Println(string(data))
				})
				if readErr != nil {
					log.Fatalf("failed to read file contents: %v", readErr)
				}
			}
		}

		break // TODO: remove
	}

	return nil
}

func readFileInChunks(file string, handler func(data []byte)) error {
	f, fErr := os.Open(file)
	if fErr != nil {
		return fmt.Errorf("failed to open file %s: %v", file, fErr)
	}

	defer f.Close()

	reader := bufio.NewReader(f)
	buf := make([]byte, chunkSize)

	for {
		n, rErr := reader.Read(buf)
		if rErr != nil {
			if rErr != io.EOF {
				return fmt.Errorf("failed to read file %s: %v", file, rErr)
			}

			break
		}

		handler(buf[0:n])
	}

	return nil
}

// base64( enc( json(f1-metadata) ) ) ? base64( enc( f1-contents-p1 ) ) base64( enc( f1-contents-p2 ) ) $ base64( enc( json(d1-metadata) ) ) $
