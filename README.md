# directory-encryptor

Encrypt your directories with AES256-CBC in a convenient way

### Usage

Encrypt directory (-b for 200Mb max single encrypted file size):  
`go run cmd/directory-encryptor.go -s source-dir -o encrypted-data-dir -b 209715200 -p 'my-password' -m encrypt`

Decrypt directory:  
`go run cmd/directory-encryptor.go -s encrypted-data-dir -o decrypted-files-and-directories -p 'my-password' -m decrypt`

Validate encrypted files against raw file directory (no file modifications):  
`go run cmd/directory-encryptor.go -i '.DS_Store' -s encrypted-data-dir -o decrypted-files-and-directories -p 'my-password' -m validate`

### TODOs

- The tool must be able to switch to validation mode straight after encryption process if the corresponding flag is provided
- Ignore specified files during encryption using existing `-i` flag
- Add concurrency (all CPUs by default)
- Add checksum to encrypted metadata for (way) faster encrypted data validation (keep older versions of encrypted data without checksums compatible with the tool, disable "rapid" validation for those)
