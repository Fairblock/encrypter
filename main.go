package main

import (
	enc "DistributedIBE/encryption"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"

	bls "github.com/drand/kyber-bls12381"
)

const EXPECTING_ARG_NUM = 4

func main() {
	if len(os.Args) < EXPECTING_ARG_NUM {
		panic(fmt.Sprintf("\nExpecting %d arguments, got %d arguments. Usage: ./encrypter <ID> <publickey> <plaintext> <optional: privatekey>\n", EXPECTING_ARG_NUM, len(os.Args)))
	}

	suite := bls.NewBLS12381Suite()
	publicKeyByte, err := hex.DecodeString(os.Args[2])
	if err != nil {
		panic(fmt.Sprintf("\nError decoding public key: %s\n", err.Error()))
	}

	publicKeyPoint := suite.G1().Point()
	err = publicKeyPoint.UnmarshalBinary(publicKeyByte)
	if err != nil {
		panic(fmt.Sprintf("\nError unmarshalling public key: %s\n", err.Error()))
	}

	var destCipherData bytes.Buffer
	var plainTextBuffer bytes.Buffer
	_, err = plainTextBuffer.WriteString(os.Args[3])
	if err != nil {
		panic(fmt.Sprintf("\nError writing plaintext string to buffer: %s\n", err.Error()))
	}

	err = enc.Encrypt(publicKeyPoint, []byte(os.Args[1]), &destCipherData, &plainTextBuffer)
	if err != nil {
		panic(fmt.Sprintf("\nError encrypting: %s\n", err.Error()))
	}

	hexCipher := hex.EncodeToString(destCipherData.Bytes())

	fmt.Println(hexCipher)

	if len(os.Args) == EXPECTING_ARG_NUM+1 {
		privateKeyByte, err := hex.DecodeString(os.Args[4])
		if err != nil {
			panic(fmt.Sprintf("\nError decoding private key: %s\n", err.Error()))
		}

		privateKeyPoint := suite.G2().Point()
		err = privateKeyPoint.UnmarshalBinary(privateKeyByte)
		if err != nil {
			panic(fmt.Sprintf("\nError unmarshalling private key: %s\n", err.Error()))
		}

		cipherBytes, err := hex.DecodeString(hexCipher)
		if err != nil {
			panic(fmt.Sprintf("\nError decoding cipher from hex to bytes: %s\n", err.Error()))
		}

		var destPlainText bytes.Buffer
		var cipherBuffer bytes.Buffer
		_, err = cipherBuffer.Write(cipherBytes)
		if err != nil {
			panic(fmt.Sprintf("\nError writing plaintext string to buffer: %s\n", err.Error()))
		}

		err = enc.Decrypt(publicKeyPoint, privateKeyPoint, &destPlainText, &cipherBuffer)
		if err != nil {
			panic(fmt.Sprintf("\nError decrypting: %s\n", err.Error()))
		}

		fmt.Printf("\nDecrypt Cipher Successfully:\n%s\n", destPlainText.String())
	}
}
