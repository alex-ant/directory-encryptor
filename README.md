# directory-encryptor

Encrypt your directories with AES256-CBC in a convenient way

### Usage

Encrypt directory (-b for 200Mb max single encrypted file size):  
`go run cmd/directory-encryptor.go -s source-dir -o encrypted-data-dir -b 209715200 -p 'my-password' -m encrypt`

Decrypt directory:  
`go run cmd/directory-encryptor.go -s encrypted-data-dir -o decrypted-files-and-directories -p 'my-password' -m decrypt`

Validate encrypted files against raw file directory (no file modifications):  
`go run cmd/directory-encryptor.go -i '.DS_Store' -s encrypted-data-dir -o decrypted-files-and-directories -p 'my-password' -m validate`
