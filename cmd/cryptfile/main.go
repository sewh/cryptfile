package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/sewh/cryptfile/pkg/file"
)

var args []string

func usage() {
	fmt.Println("usage (encrypt): cryptfile encrypt /path/to/file")
	fmt.Println("usage (decrypt): cryptfile decrypt /path/to/enc/file /path/to/meta/file")
	os.Exit(0)
}

func main() {
	flag.Parse()
	args = flag.Args()

	if len(args) < 2 {
		usage()
	}
	if args[0] != "encrypt" && args[0] != "decrypt" {
		usage()
	}
	if args[0] == "decrypt" && len(args) < 3 {
		usage()
	}

	if args[0] == "encrypt" {
		encFile, metaFile, err := file.Encrypt(args[1])
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		fmt.Printf("Wrote encrypted file to: %s\n", encFile)
		fmt.Printf("Wrote metadata file to:  %s\n", metaFile)
	} else if args[0] == "decrypt" {
		plainFile, err := file.Decrypt(args[1], args[2])
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		fmt.Printf("Wrote decrypted file to: %s\n", plainFile)
	}
}
