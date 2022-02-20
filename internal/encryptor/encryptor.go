package encryptor

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/alex-ant/directory-encryptor/internal/aes256/cbc"
)

const (
	// TODO: change
	sourceFileReadChunkSize int = 16
)

const (
	ENCRYPT string = "encrypt"
	DECRYPT string = "decrypt"
)

// Processor contains encryptor processor data.
type Processor struct {
	maxBatchSize int64

	sourceDir string
	outputDir string

	encryptionKey string
	iv            string

	verboseLogs bool
}

// New returns new Processor.
func New(mode string, maxBatchSize int64, sourceDir, outputDir string, encryptionKey string, verboseLogs bool) (*Processor, error) {
	if mode != ENCRYPT && mode != DECRYPT {
		return nil, fmt.Errorf("invalid operation mode provided, must be %s or %s", ENCRYPT, DECRYPT)
	}

	if len(encryptionKey) != 32 {
		return nil, errors.New("32-byte encryption key is expected")
	}

	if outputDir == "" {
		return nil, errors.New("empty outputDir provided")
	}

	// Trim output path.
	if outputDir[len(outputDir)-1] == '/' {
		outputDir = outputDir[:len(outputDir)-1]
	}

	// Create output directory exists.
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

	// Deternime IV.
	iv, ivErr := sha256Hash(encryptionKey, 10)
	if ivErr != nil {
		return nil, fmt.Errorf("failed to determine IV: %v", ivErr)
	}

	iv = formatIV(iv)

	return &Processor{
		maxBatchSize: maxBatchSize,

		sourceDir: sourceDir,
		outputDir: outputDir,

		encryptionKey: encryptionKey,
		iv:            iv,

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

	// Write result file.
	for batchI, batch := range batches {
		// Open batch result file.
		fnStr, fnStrErr := fileNumber(batchI+1, 32)
		if fnStrErr != nil {
			log.Fatalf("failed to generate file number string: %v", fnStrErr)
		}

		resF, resFErr := os.OpenFile(fmt.Sprintf("%s/%s.data", p.outputDir, fnStr), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0755)
		if resFErr != nil {
			log.Fatalf("failed to open result file: %v", resFErr)
		}

		for _, f := range batch {
			// Marshall and encrypt metadata.
			fb, _ := json.Marshal(*f)

			encFb, encFbErr := cbc.Encrypt(fb, p.encryptionKey, p.iv)
			if encFbErr != nil {
				log.Fatalf("failed to encrypt metadata: %v", encFbErr)
			}

			// Update IV.
			var pIVErr error
			p.iv, pIVErr = nextIV(p.iv)
			if pIVErr != nil {
				log.Fatalf("failed to generate next IV: %v", pIVErr)
			}

			// Write metadata.
			_, mdWErr := resF.Write(encFb)
			if encFbErr != nil {
				log.Fatalf("failed to write metadata: %v", mdWErr)
			}

			// Write data delimiters.
			if f.Filetype == DIRECTORY {
				_, wErr := resF.Write([]byte("$"))
				if encFbErr != nil {
					log.Fatalf("failed to write metadata delimiter: %v", wErr)
				}

				// No file data to write, move to next file.
				continue
			} else {
				_, wErr := resF.Write([]byte("?"))
				if encFbErr != nil {
					log.Fatalf("failed to write file data delimiter: %v", wErr)
				}
			}

			// Read file contents.
			var chunkI int
			readErr := readFileInChunks(path.Join(p.sourceDir, f.RelativePath), func(data []byte) {
				if chunkI > 0 {
					_, wErr := resF.Write([]byte("?"))
					if encFbErr != nil {
						log.Fatalf("failed to write metadata delimiter: %v", wErr)
					}
				}

				// Encrypt and write file contents.
				encData, encDataErr := cbc.Encrypt(data, p.encryptionKey, p.iv)
				if encDataErr != nil {
					log.Fatalf("failed to encrypt file data: %v", encDataErr)
				}

				// Update IV.
				var pIVErr error
				p.iv, pIVErr = nextIV(p.iv)
				if pIVErr != nil {
					log.Fatalf("failed to generate next IV: %v", pIVErr)
				}

				_, wErr := resF.Write(encData)
				if encFbErr != nil {
					log.Fatalf("failed to write file data: %v", wErr)
				}

				chunkI++
			})
			if readErr != nil {
				log.Fatalf("failed to read file contents: %v", readErr)
			}

			_, wErr := resF.Write([]byte("$"))
			if encFbErr != nil {
				log.Fatalf("failed to write metadata delimiter: %v", wErr)
			}
		}

		resF.Close()
	}

	return nil
}

func (p *Processor) Decrypt() error {
	// List encrypted files.
	var sFilenames []string

	sFiles, sFilesErr := ioutil.ReadDir(p.sourceDir)
	if sFilesErr != nil {
		return fmt.Errorf("failed to list source files directory: %v", sFilesErr)
	}

	for _, sf := range sFiles {
		if sf.IsDir() {
			continue
		}

		sFilenames = append(sFilenames, sf.Name())
	}

	sort.Strings(sFilenames)

	// Loop over encrypted files.
	for _, sfn := range sFilenames {
		// Read file.
		fPath := path.Join(p.sourceDir, sfn)

		encF, encFErr := os.Open(fPath)
		if encFErr != nil {
			return fmt.Errorf("failed to open file %s: %v", fPath, encFErr)
		}

		br := bufio.NewReader(encF)

		var currSectorData []byte
		var currFile *os.File
		var mdRead bool

		resetState := func() {
			currSectorData = []byte{}
			mdRead = false

			if currFile != nil {
				currFile.Close()
				currFile = nil
			}
		}

		decryptMD := func() (*fileInfo, error) {
			// Decrypt metadata.
			decMD, decMDErr := cbc.Decrypt(currSectorData, p.encryptionKey, p.iv)
			if decMDErr != nil {
				return nil, fmt.Errorf("failed to decrypt metadata: %v", decMDErr)
			}

			// Update IV.
			var pIVErr error
			p.iv, pIVErr = nextIV(p.iv)
			if pIVErr != nil {
				return nil, fmt.Errorf("failed to generate next IV: %v", pIVErr)
			}

			// Unmarshall metadata.
			var fi fileInfo

			fiErr := json.Unmarshal(decMD, &fi)
			if pIVErr != nil {
				return nil, fmt.Errorf("failed to unmarshall metadata (%s): %v", string(decMD), fiErr)
			}

			return &fi, nil
		}

		for {
			b, bErr := br.ReadByte()
			if bErr != nil {
				if bErr != io.EOF {
					return fmt.Errorf("failed to read file %s byte: %v", fPath, bErr)
				}

				break
			}

			switch string(b) {
			case "$":
				if !mdRead {
					// Decrypt directory metadata.
					fi, fiErr := decryptMD()
					if fiErr != nil {
						return fmt.Errorf("failed to decrypt directory metadata: %v", fiErr)
					}

					if fi.Filetype != DIRECTORY {
						return fmt.Errorf("expected directory (%d) metadata but received (%d)", DIRECTORY, fi.Filetype)
					}

					// Create directory.
					dirPath := path.Join(p.outputDir, fi.RelativePath)

					mkdirErr := os.MkdirAll(dirPath, 0755)
					if mkdirErr != nil {
						return fmt.Errorf("failed to create directory %s", dirPath)
					}

					// Reset state.
					resetState()

					// Proceed reading next bytes.
					continue

				} else {
					// Decrypt file part contents.
					decFC, decFCErr := cbc.Decrypt(currSectorData, p.encryptionKey, p.iv)
					if decFCErr != nil {
						return fmt.Errorf("failed to decrypt file part contents: %v", decFCErr)
					}

					// Update IV.
					var pIVErr error
					p.iv, pIVErr = nextIV(p.iv)
					if pIVErr != nil {
						return fmt.Errorf("failed to generate next IV: %v", pIVErr)
					}

					// Append to file.
					_, decFCWErr := currFile.Write(decFC)
					if decFCWErr != nil {
						log.Fatalf("failed to write file part contents: %v", decFCWErr)
					}

					// Reset state.
					resetState()

					// Proceed reading next bytes.
					continue
				}

			case "?":
				// Process file metadata
				if !mdRead {
					// Decrypt file metadata.
					fi, fiErr := decryptMD()
					if fiErr != nil {
						return fmt.Errorf("failed to decrypt file metadata: %v", fiErr)
					}

					if fi.Filetype != FILE {
						return fmt.Errorf("expected file (%d) metadata but received (%d)", FILE, fi.Filetype)
					}

					fName := fmt.Sprintf("%s/%s", p.outputDir, fi.RelativePath)

					// Create file directory if doesn't exist.
					os.MkdirAll(filepath.Dir(fName), 0755)

					// Create file.
					decF, decFErr := os.OpenFile(fName, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0755)
					if decFErr != nil {
						return fmt.Errorf("failed to open decrypted file: %v", decFErr)
					}

					// Store file pointer.
					currFile = decF

					mdRead = true

					currSectorData = []byte{}

					// Continue with file contents in the following bytes.
					continue
				} else {
					// Decrypt file part contents.
					decFC, decFCErr := cbc.Decrypt(currSectorData, p.encryptionKey, p.iv)
					if decFCErr != nil {
						return fmt.Errorf("failed to decrypt file part contents: %v", decFCErr)
					}

					// Update IV.
					var pIVErr error
					p.iv, pIVErr = nextIV(p.iv)
					if pIVErr != nil {
						return fmt.Errorf("failed to generate next IV: %v", pIVErr)
					}

					// Append to file.
					_, decFCWErr := currFile.Write(decFC)
					if decFCWErr != nil {
						log.Fatalf("failed to write file part contents: %v", decFCWErr)
					}

					currSectorData = []byte{}

					// Continue with file contents in the following bytes.
					continue

				}

			}

			currSectorData = append(currSectorData, b)
		}

		encF.Close()
	}

	return nil
}

// base64( enc( json(d1-metadata) ) ) $ base64( enc( json(f1-metadata) ) ) ? base64( enc( f1-contents-p1 ) ) ? base64( enc( f1-contents-p2 ) ) $

func readFileInChunks(file string, handler func(data []byte)) error {
	f, fErr := os.Open(file)
	if fErr != nil {
		return fmt.Errorf("failed to open file %s: %v", file, fErr)
	}

	defer f.Close()

	reader := bufio.NewReader(f)
	buf := make([]byte, sourceFileReadChunkSize)

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

func sha256Hash(data string, interN int) (string, error) {
	if interN < 1 {
		return "", errors.New("invalid interN provided")
	}

	for i := 0; i < interN; i++ {
		h := sha256.New()
		h.Write([]byte(data))
		data = hex.EncodeToString(h.Sum(nil))
	}

	return data, nil
}

func formatIV(s string) string {
	var res string

	if len(s) < 16 {
		for i := 0; i < 16; i++ {
			if i < len(s) {
				res += string(s[i])
			} else {
				res += "x"
			}
		}
	} else {
		return s[:16]
	}

	return res
}

func nextIV(iv string) (string, error) {
	if len(iv) != 16 {
		return "", errors.New("invalid IV provided, must be of length 16")
	}

	h, hErr := sha256Hash(iv, 2)
	if hErr != nil {
		return "", fmt.Errorf("failed to generate IV hash: %v", hErr)
	}

	return h[:16], nil
}

func fileNumber(i, minChars int) (string, error) {
	if i < 0 {
		return "", errors.New("invalid i provided")
	}

	iStr := strconv.Itoa(i)

	iLen := len(iStr)
	if minChars < iLen {
		minChars = iLen
	}

	var res string

	for j := 0; j < minChars-iLen; j++ {
		res += "0"
	}

	res += iStr

	return res, nil
}
