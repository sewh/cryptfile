package file

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

type metadata struct {
	KeyHex   string `json:"key"`
	FileName string `json:"filename"`
}

// Encrypt takes a path to a file and outputs an encrypted version of that file in
// the same directory. It also outputs a metadata file that contains the original filename
// and the randomly generated AES-256 key used to encrypt the data. The filename of both of these files
// is the SHA-256 HMAC with either '.enc' or '.meta' depending on whether the file is the encrypted
// file or the metadata file respectively. Upon finishing, it returns the path to the encrypted file, the
// path to the metadata file, and any errors that have occured. If an error has occured, the encrypted file
// path and the metadata file path will be empty.
func Encrypt(path string) (string, string, error) {
	// Validate path
	_, err := os.Stat(path)
	if err != nil {
		return "", "", err
	}

	// Create a temporary file to write the encrypted data to. We'll rename this
	// to the HMAC hash once it has been written out.
	tempFile, err := ioutil.TempFile("", "")
	if err != nil {
		return "", "", err
	}
	defer tempFile.Close()

	// Open up the plaintext file for reading
	inputFile, err := os.Open(path)
	if err != nil {
		return "", "", err

	}
	defer inputFile.Close()

	plainBuffer := make([]byte, aes.BlockSize)
	cipherBuffer := make([]byte, aes.BlockSize)

	// Create a random encryption key. We store this in the private metadata
	// file later on.
	encKey := make([]byte, 32)
	bytesWritten, err := rand.Read(encKey)
	if err != nil {
		return "", "", err
	}
	if bytesWritten != 32 {
		return "", "", errors.New("Couldn't create AES-256 key")
	}

	// The filename is the SHA256 HMAC of the ciphertext and AES key. This
	// will be validated when decrypted.
	mac := hmac.New(sha256.New, encKey)

	// Create the AES encrypter
	aesCipher, err := aes.NewCipher(encKey)
	if err != nil {
		return "", "", err
	}

	// Make a random IV so we can create the CBC mode
	iv := make([]byte, aes.BlockSize)
	bytesWritten, err = rand.Read(iv)
	if err != nil {
		return "", "", err
	}
	if bytesWritten != aes.BlockSize {
		return "", "", errors.New("Could not create random AES IV")
	}

	stream := cipher.NewCTR(aesCipher, iv)

	// Write out the IV as the first block in the file
	tempFile.Write(iv)
	mac.Write(iv)

	// Begin the copy loop
	for {
		amountRead, err := inputFile.Read(plainBuffer)
		shouldFinish := false
		if err == io.EOF {
			shouldFinish = true
		} else if err != nil {
			return "", "", err
		}

		stream.XORKeyStream(cipherBuffer, plainBuffer)
		mac.Write(cipherBuffer[:amountRead])

		tempFile.Write(cipherBuffer[:amountRead])

		if shouldFinish {
			break
		}
	}

	// Rename temporary file into the encrypted file
	absDir, _ := filepath.Abs(path)
	outputDir := filepath.Dir(absDir)

	hexSum := hex.EncodeToString(mac.Sum(nil))
	fileName := hexSum + ".enc"
	filePath := filepath.Join(outputDir, fileName)
	tempFile.Close()
	err = os.Rename(tempFile.Name(), filePath)
	if err != nil {
		return "", "", err
	}

	metaName := hexSum + ".meta"
	metaPath := filepath.Join(outputDir, metaName)

	// Write out metadata JSON file
	meta := &metadata{
		KeyHex:   hex.EncodeToString(encKey),
		FileName: filepath.Base(path),
	}
	j, err := json.Marshal(meta)
	if err != nil {
		return "", "", err
	}
	err = ioutil.WriteFile(metaPath, j, 0600)
	if err != nil {
		return "", "", err
	}

	// Return filenames
	return filePath, metaPath, nil
}

// Decrypt takes a path to an encrypted file and it's associated metadata file that have been
// produced by `Encrypt` and decrypts it back into plaintext with its original filename. Upon
// finishing, `Decrypt` returns a path to the newly created plaintext file and an error. If an error
// occured, the returned path will be empty.
func Decrypt(encPath, metaPath string) (string, error) {
	if _, err := os.Stat(encPath); os.IsNotExist(err) {
		return "", err
	}
	if _, err := os.Stat(metaPath); os.IsNotExist(err) {
		return "", err
	}

	// Deserialize our metadata
	meta := &metadata{}
	jsonBytes, err := ioutil.ReadFile(metaPath)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal(jsonBytes, meta)
	if err != nil {
		return "", err
	}

	// Extract out our AES-256 key
	aesKey, err := hex.DecodeString(meta.KeyHex)
	if err != nil {
		return "", err
	}
	if len(aesKey) != 32 {
		return "", errors.New(fmt.Sprintf("Expected AES-256 key to be 32-bytes, got %d", len(aesKey)))
	}

	// Extract out HMAC hash
	hmacHex := strings.TrimSuffix(filepath.Base(encPath), ".enc")
	hmacBytes, err := hex.DecodeString(hmacHex)
	if err != nil {
		return "", err
	}
	if len(hmacBytes) != 32 {
		return "", errors.New(fmt.Sprintf("Expected HMAC-SHA256 sum to be 64 bytes, got %d", len(hmacBytes)))
	}

	// Firstly, validate HMAC before we attempt any decryption
	mac := hmac.New(sha256.New, aesKey)
	macBuff := make([]byte, aes.BlockSize)
	encFile, err := os.Open(encPath)
	if err != nil {
		return "", err
	}

	for {
		shouldBreak := false
		amountRead, err := encFile.Read(macBuff)
		if err == io.EOF {
			shouldBreak = true
		}

		mac.Write(macBuff[:amountRead])

		if shouldBreak {
			break
		}
	}

	thisHmac := mac.Sum(nil)
	if !hmac.Equal(hmacBytes, thisHmac) {
		fmt.Println(hex.EncodeToString(hmacBytes))
		fmt.Println(hex.EncodeToString(thisHmac))
		return "", errors.New("HMACs were not equal")
	}

	// Now attempt the decrypt
	outputFilename := meta.FileName
	absPath, _ := filepath.Abs(encPath)
	outputDir := filepath.Dir(absPath)
	outputPath := filepath.Join(outputDir, outputFilename)

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return "", err
	}
	defer outputFile.Close()

	_, err = encFile.Seek(0, 0)
	if err != nil {
		return "", err
	}

	cipherBuff := make([]byte, aes.BlockSize)
	iv := make([]byte, aes.BlockSize)
	plainBuff := make([]byte, aes.BlockSize)

	aesCipher, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}

	amountRead, err := encFile.Read(iv)
	if err != nil {
		return "", err
	}
	if amountRead != aes.BlockSize {
		return "", errors.New(fmt.Sprintf("Expected to read %d byte IV. Got %d", aes.BlockSize, amountRead))
	}

	stream := cipher.NewCTR(aesCipher, iv)

	for {
		shouldBreak := false
		bytesRead, err := encFile.Read(cipherBuff)
		if err == io.EOF {
			shouldBreak = true
		}
		if err != nil && err != io.EOF {
			return "", err
		}

		stream.XORKeyStream(plainBuff, cipherBuff[:bytesRead])

		outputFile.Write(plainBuff[:bytesRead])

		if shouldBreak {
			break
		}
	}

	return outputPath, nil
}
