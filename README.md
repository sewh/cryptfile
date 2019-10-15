cryptfile
=========

cryptfile is a small utility for encrypting and decrypting files. It was written to secure documents before they are transmitted to a semi-trusted third-party for archiving. It functions by taking a file and outputting an encrypted version of that file and a metadata file that contains the original file name and the encryption key. Decryption takes the encrypted file and the metadata file and decrypts it back into the plaintext version.

Data is encrypted with AES-256-CTR with a HMAC-SHA256 used for data integrity.

**Use at your own risk. This is my own pieced together utility so there's likely to be some issues with it.**

## Installation


```bash
go get github.com/sewh/cryptfile/cmd/cryptfile
go install github.com/sewh/cryptfile/cmd/cryptfile

# Ensure $(go env GOPATH) is in your path
```


## Usage


```
usage (encrypt): cryptfile encrypt /path/to/file
usage (decrypt): cryptfile decrypt /path/to/enc/file /path/to/meta/file
```
