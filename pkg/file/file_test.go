package file

import (
	"crypto/aes"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"testing"
)

var fileContentsHex string = "32bd49dae22a51ffc78374f0afaa716b7974c4689fd599e50cfa5d69e0c13641e2ae1c3eebe35ffdc134b16abb6cb801b154be10144e79a8c7aeab0c99b6dd63d0b7775e33ba331414ab74fc936c5013a58b0260620aad2f1ad1cdd3fcff06e2c1da24a712c34bee9ce11f1172f0653e652bf34f5d826272e6e7aca57b56f0dc41d8fccde84cb0d93a23a01901358dc08fc99a583e11ebf49746d15aec6b7f0a5c137e8c0f66d5dc35729b3b525b1759787c81636b74397d918591d76837fac62f03e29350278bd3e686d9e8809a33e7032bc0030e6bdbbbe3786395dae162c97ebf29136fabb992f2e4c9017c30fed40466cb56ce0da13a6674553d1abe715fffffff"

func fileContents() []byte {
	bytes, _ := hex.DecodeString(fileContentsHex)
	return bytes
}

func TestEncrypt(t *testing.T) {
	// Set up an example file
	tFile, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatal("Couldn't create temporary file")
	}
	defer func() {
		tFile.Close()
		os.Remove(tFile.Name())
	}()
	tFile.Write(fileContents())
	tFile.Close()

	// Attempt to encrypt a file that doesn't exist
	fileName, metaName, err := Encrypt("no-exist")
	if !os.IsNotExist(err) {
		t.Fatal("Encrypt should have returned io.IsNotExist for a made up file name")
	}

	// Encrypt works without error
	fileName, metaName, err = Encrypt(tFile.Name())
	defer func() {
		if _, err := os.Stat(fileName); !os.IsNotExist(err) {
			os.Remove(fileName)
		}
		if _, err := os.Stat(metaName); !os.IsNotExist(err) {
			os.Remove(metaName)
		}
	}()

	if err != nil {
		t.Fatal(err.Error())
	}
	if fileName == "" {
		t.Fatal("Encrypt didn't return a filename")
	}
	if metaName == "" {
		t.Fatal("Encrypt didn't return a encryption key file name")
	}

	// Encrypt returns content that's different from the plaintext
	plainBuff := make([]byte, aes.BlockSize)
	cipherBuff := make([]byte, aes.BlockSize)
	plainFile, _ := os.Open(tFile.Name())
	cipherFile, _ := os.Open(fileName)

	isDifferent := false

	for {
		shouldFinish := false
		_, err = plainFile.Read(plainBuff)
		if err == io.EOF {
			shouldFinish = true
		}
		_, err = cipherFile.Read(cipherBuff)
		if err == io.EOF {
			shouldFinish = true
		}

		for i := 0; i < aes.BlockSize; i++ {
			if plainBuff[i] != cipherBuff[i] {
				isDifferent = true
			}
		}

		if shouldFinish {
			break
		}
	}

	if !isDifferent {
		t.Fatal("Plaintext and ciphertext files should be different")
	}

	// Ensure that the file is AES IV + len(plaintext) long
	fileStat, err := os.Stat(fileName)
	if err != nil {
		t.Fatal(err.Error())
	}
	expectedSize := int64(aes.BlockSize + len(fileContents()))
	if fileStat.Size() != expectedSize {
		t.Fatalf("Expected ciphertext file to be %d bytes, it's actually %d", expectedSize, fileStat.Size())
	}

}

func TestDecrypt(t *testing.T) {
	// Encrypt a file so we have something to play with
	tempPlain, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err.Error())
	}
	tempPlain.Write(fileContents())
	tempPlain.Close()

	encPath, metaPath, err := Encrypt(tempPlain.Name())
	if err != nil {
		t.Fatal(err.Error())
	}
	defer os.Remove(encPath)
	defer os.Remove(metaPath)

	// Remove the plaintext file so we can reconstitute it
	os.Remove(tempPlain.Name())

	// Load meta file for later use
	metaBytes, err := ioutil.ReadFile(metaPath)
	if err != nil {
		t.Fatal(err.Error())
	}
	meta := &metadata{}
	err = json.Unmarshal(metaBytes, meta)
	if err != nil {
		t.Fatal(err.Error())
	}

	// Decrypt the files
	plainFile, err := Decrypt(encPath, metaPath)
	if err != nil {
		t.Fatal(err.Error())
	}
	defer os.Remove(plainFile)

	// Make sure that the output file exists
	if _, err := os.Stat(plainFile); os.IsNotExist(err) {
		t.Fatal(err.Error())
	}

	// Make sure the new file matches the plaintext we inputted
	fromFile, err := ioutil.ReadFile(plainFile)
	if err != nil {
		t.Fatal(err.Error())
	}

	origContents := fileContents()
	for i := 1; i < len(origContents); i++ {
		if origContents[i] != fromFile[i] {
			t.Fatal("Decrypted file is different from our original one")
		}
	}

}
