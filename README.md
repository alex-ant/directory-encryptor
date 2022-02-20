# directory-encryptor

### Usage

Encrypt directory (-b for 200Mb max single encrypted file size):  
`go run cmd/directory-encryptor.go -v -s source-dir -o encrypted-data-dir -b 209715200 -k 5e40482321e6df91295cedbd46706039 -m encrypt`

Decrypt directory:  
`go run cmd/directory-encryptor.go -v -s encrypted-data-dir -k 5e40482321e6df91295cedbd46706039 -m decrypt -o decrypted-files-and-directories`
