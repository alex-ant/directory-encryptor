# directory-encryptor

Encrypt your directories with AES256-CBC in a convenient way

### Usage

Encrypt directory (-b for 200Mb max single encrypted file size):  
`go run cmd/directory-encryptor.go -s source-dir -o encrypted-data-dir -b 209715200 -p 'my-password' -m encrypt`

Decrypt directory:  
`go run cmd/directory-encryptor.go -s encrypted-data-dir -p 'my-password' -m decrypt -o decrypted-files-and-directories`
